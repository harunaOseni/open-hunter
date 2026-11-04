"""Learn per-domain mailbox patterns from delivery outcomes.

A send that was delivered is the strongest evidence a mailbox format is real; a
public commit email is weaker, and a bounce only says that one rendered address
does not exist. Companies mix formats (anthropic.com uses flast@, firstlast@ and
first@), so the result is a weighted list of patterns rather than one winner.

Weights per pattern:

    delivered * 1.0 + seed * 1.0 + public_votes * 0.5 - bounced * 0.25

A bounce penalizes the pattern lightly at the domain level, because qventus.com
delivered mudit.garg@ while first.last bounced for other people. For the person
who bounced, the exact address and its pattern are excluded outright.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from openhunter.errors import InputError
from openhunter.names import mailbox_forms, split_name
from openhunter.patterns import PATTERN_ORDER, PATTERN_PRIOR, PatternVote, _render

DELIVERED = "delivered"
BOUNCED = "bounced"
STATUSES = (DELIVERED, BOUNCED)

DELIVERED_WEIGHT = 1.0
SEED_WEIGHT = 1.0
PUBLIC_WEIGHT = 0.5
BOUNCE_PENALTY = 0.25

# Observed on 2026-11-04 from Gmail delivery results and public addresses.
# "handle" means people choose their own local part (laolu@, roasbeef@, stark@),
# which cannot be rendered from a name, so it is reported but never generated.
SEED_PATTERNS: dict[str, tuple[str, ...]] = {
    "buildwithfern.com": ("first",),
    "midjourney.com": ("first",),
    "withmoment.com": ("first",),
    "qventus.com": ("first.last", "first"),
    "anthropic.com": ("flast", "firstlast", "first"),
    "lightning.engineering": ("first", "handle"),
}


@dataclass(frozen=True)
class Outcome:
    email: str
    status: str
    first_name: str | None = None
    last_name: str | None = None

    @property
    def domain(self) -> str:
        return self.email.rsplit("@", 1)[1]

    @property
    def local(self) -> str:
        return self.email.rsplit("@", 1)[0].split("+", 1)[0]


@dataclass(frozen=True)
class WeightedPattern:
    pattern: str
    weight: float
    delivered: int
    bounced: int
    seeded: bool
    public_votes: int


@dataclass
class PersonExclusions:
    emails: set[str] = field(default_factory=set)
    patterns: set[str] = field(default_factory=set)


def normalize_status(value: str) -> str:
    cleaned = (value or "").strip().lower()
    if cleaned in {"delivered", "sent", "replied", "ok"}:
        return DELIVERED
    if cleaned in {"bounced", "bounce", "failed", "undeliverable"}:
        return BOUNCED
    raise InputError(f"Unknown delivery status {value!r}; use delivered or bounced.")


def make_outcome(email: str, status: str, name: str | None = None,
                 first_name: str | None = None, last_name: str | None = None) -> Outcome:
    address = (email or "").strip().lower()
    if address.count("@") != 1 or not address.split("@")[0] or "." not in address.split("@")[1]:
        raise InputError(f"{email!r} is not an email address.")
    if name and not (first_name and last_name):
        split_first, split_last = split_name(name)
        first_name = first_name or split_first
        last_name = last_name or split_last
    return Outcome(address, normalize_status(status), first_name, last_name)


def matching_patterns(local: str, first: str | None, last: str | None) -> set[str]:
    if not first or not last:
        return set()
    hits: set[str] = set()
    for first_form in mailbox_forms(first):
        for last_form in mailbox_forms(last):
            for pattern_id, template, _prior in PATTERN_ORDER:
                if _render(template, first_form, last_form) == local:
                    hits.add(pattern_id)
    return hits


def weigh_patterns(
    domain: str,
    outcomes: Iterable[Outcome],
    public_votes: Sequence[PatternVote] = (),
    seeds: dict[str, tuple[str, ...]] | None = None,
) -> list[WeightedPattern]:
    seed_map = SEED_PATTERNS if seeds is None else seeds
    delivered: dict[str, int] = defaultdict(int)
    bounced: dict[str, int] = defaultdict(int)
    for outcome in outcomes:
        if outcome.domain != domain:
            continue
        for pattern_id in matching_patterns(outcome.local, outcome.first_name, outcome.last_name):
            (delivered if outcome.status == DELIVERED else bounced)[pattern_id] += 1
    votes = {vote.pattern: vote.matched_count for vote in public_votes}
    seeded = set(seed_map.get(domain, ()))
    ids = set(delivered) | set(bounced) | set(votes) | seeded
    rows: list[WeightedPattern] = []
    for pattern_id in ids:
        weight = (
            delivered[pattern_id] * DELIVERED_WEIGHT
            + (SEED_WEIGHT if pattern_id in seeded else 0.0)
            + votes.get(pattern_id, 0) * PUBLIC_WEIGHT
            - bounced[pattern_id] * BOUNCE_PENALTY
        )
        rows.append(WeightedPattern(pattern_id, round(weight, 3), delivered[pattern_id],
                                    bounced[pattern_id], pattern_id in seeded, votes.get(pattern_id, 0)))
    rows.sort(key=lambda row: (-row.weight, -row.delivered, -PATTERN_PRIOR.get(row.pattern, 0.0), row.pattern))
    return rows


def exclusions_for(first: str, last: str, domain: str, outcomes: Iterable[Outcome]) -> PersonExclusions:
    """Bounced addresses for this person, and the patterns those addresses used."""
    result = PersonExclusions()
    firsts, lasts = set(mailbox_forms(first)), set(mailbox_forms(last))
    for outcome in outcomes:
        if outcome.domain != domain or outcome.status != BOUNCED:
            continue
        same_person = (
            outcome.first_name is not None and outcome.last_name is not None
            and set(mailbox_forms(outcome.first_name)) & firsts
            and set(mailbox_forms(outcome.last_name)) & lasts
        )
        hits = matching_patterns(outcome.local, first, last)
        if same_person or hits:
            result.emails.add(outcome.email)
            result.patterns.update(hits)
    return result


def read_outreach_sheet(path: Path, sheet: str = "Outreach") -> list[Outcome]:
    """Read column B (name), C (address) and F (status) from a tracker workbook.

    'Bounced' is a bounce. 'Sent' is treated as delivered only when the same
    address never appears as Bounced anywhere in the sheet.
    """
    try:
        import openpyxl
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise InputError("Importing a workbook needs openpyxl: pip install 'openhunter[xlsx]'.") from exc
    workbook = openpyxl.load_workbook(Path(path), read_only=True, data_only=True)
    if sheet not in workbook.sheetnames:
        raise InputError(f"The workbook has no sheet named {sheet!r}.")
    rows: list[tuple[str, str, str | None]] = []
    bounced: set[str] = set()
    for row in workbook[sheet].iter_rows(values_only=True):
        if len(row) < 6:
            continue
        name, email, status = row[1], row[2], row[5]
        if not isinstance(email, str) or "@" not in email or not isinstance(status, str):
            continue
        address, label = email.strip().lower(), status.strip().lower()
        if label == "bounced":
            bounced.add(address)
        if label in {"bounced", "sent"}:
            rows.append((address, label, name if isinstance(name, str) else None))
    workbook.close()
    outcomes: dict[str, Outcome] = {}
    for address, label, name in rows:
        status = BOUNCED if address in bounced else DELIVERED
        try:
            outcomes[address] = make_outcome(address, status, name=name)
        except InputError:
            continue
    return list(outcomes.values())


def rerank(candidates, weighted, excluded_emails: set[str], excluded_patterns: set[str]):
    """Drop excluded candidates and boost the rest by observed pattern weight.

    A pattern with positive weight lifts its candidate to 0.5 + 0.1 * weight
    (capped at 0.97) when that beats the prior score. Ranks are renumbered.
    """
    from openhunter.patterns import Candidate

    weights = {}
    for row in weighted:
        pattern_id = row["pattern"] if isinstance(row, dict) else row.pattern
        weight = row["weight"] if isinstance(row, dict) else row.weight
        weights[pattern_id] = float(weight)
    kept = []
    for candidate in candidates:
        if candidate.email in excluded_emails or candidate.pattern in excluded_patterns:
            continue
        score, reason = candidate.score, candidate.reason
        weight = weights.get(candidate.pattern, 0.0)
        if weight > 0:
            boosted = round(min(0.97, 0.5 + 0.1 * weight), 2)
            if boosted > score:
                score, reason = boosted, f"observed pattern {candidate.pattern} (weight {weight:g})"
        elif weight < 0:
            score = round(score * 0.5, 2)
            reason = f"{reason}; pattern bounced at this domain"
        kept.append((candidate, score, reason))
    kept.sort(key=lambda item: (-item[1], -weights.get(item[0].pattern, 0.0), -PATTERN_PRIOR.get(item[0].pattern, 0.0), item[0].email))
    return [Candidate(c.email, c.pattern, index, score, reason) for index, (c, score, reason) in enumerate(kept, start=1)]
