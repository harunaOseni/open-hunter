"""Infer a company mailbox pattern and rank candidates for one person.

Named evidence is the number of on-domain, non-role addresses whose local part
equals a pattern rendered from that person's name. Confidence is

    ratio * (1 - 0.55 ** n)

capped at 0.97. A single agreeing address is 0.45. Three agreeing addresses
are 0.83. Companies mix formats, so even a clean sample is not treated as certain.

When every discovered address lacks a name, a structural guess is allowed only
if at least three addresses exist and at least 75% share one shape. That guess
is capped at 0.34 so it cannot outrank one named match.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from openhunter.errors import InputError
from openhunter.names import mailbox_forms, split_name
from openhunter.net import normalize_domain
from openhunter.roles import is_role_address

STRUCTURAL_CONFIDENCE = 0.34
_LOCAL_RE = re.compile(r"[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?")

# (id, template, prior). Priors are base rates for technical companies, used to
# break ties and to rank candidates when a domain has no evidence yet.
PATTERN_ORDER: tuple[tuple[str, str, float], ...] = (
    ("first.last", "{first}.{last}", 0.50),
    ("flast", "{f}{last}", 0.18),
    ("first", "{first}", 0.10),
    ("firstlast", "{first}{last}", 0.08),
    ("f.last", "{f}.{last}", 0.05),
    ("first_last", "{first}_{last}", 0.03),
    ("firstl", "{first}{l}", 0.02),
    ("last.first", "{last}.{first}", 0.015),
    ("first-last", "{first}-{last}", 0.01),
    ("last", "{last}", 0.008),
    ("first.l", "{first}.{l}", 0.006),
    ("lastfirst", "{last}{first}", 0.005),
    ("f_last", "{f}_{last}", 0.004),
    ("last.f", "{last}.{f}", 0.003),
    ("lastf", "{last}{f}", 0.002),
    ("fl", "{f}{l}", 0.001),
)
PATTERN_PRIOR = {pattern_id: prior for pattern_id, _template, prior in PATTERN_ORDER}


@dataclass(frozen=True)
class KnownEmail:
    email: str
    first_name: str | None = None
    last_name: str | None = None
    full_name: str | None = None


@dataclass(frozen=True)
class PatternVote:
    pattern: str
    matched_count: int


@dataclass(frozen=True)
class PatternInference:
    domain: str
    pattern: str | None
    confidence: float
    sample_count: int
    matched_count: int
    alternates: tuple[PatternVote, ...]
    method: str
    notes: tuple[str, ...]


@dataclass(frozen=True)
class Candidate:
    email: str
    pattern: str
    rank: int
    score: float
    reason: str


def sample_confidence(matched: int, total: int) -> float:
    if matched <= 0 or total <= 0:
        return 0.0
    ratio = matched / total
    sample = 1 - (0.55**total)
    return round(min(0.97, ratio * sample), 2)


def infer_pattern(domain: str, known: Sequence[KnownEmail]) -> PatternInference:
    normalized_domain = normalize_domain(domain)
    named: list[set[str]] = []
    structural: list[str] = []
    seen: set[str] = set()
    for item in known:
        email = item.email.strip().lower()
        if email in seen or not _on_domain(email, normalized_domain):
            continue
        if _is_noreply(email) or is_role_address(email):
            continue
        seen.add(email)
        local = email.split("@", 1)[0].split("+", 1)[0]
        first, last = _resolve_names(item)
        if first and last:
            named.append(_matching_patterns(local, first, last))
        else:
            structural.append(local)
    if named:
        return _from_named(normalized_domain, named)
    return _from_structure(normalized_domain, structural)


def generate_candidates(
    first_name: str,
    last_name: str,
    domain: str,
    inference: PatternInference | None = None,
    limit: int = 8,
) -> list[Candidate]:
    if not first_name or not first_name.strip() or not last_name or not last_name.strip():
        raise InputError("Both a first name and a last name are required.")
    normalized_domain = normalize_domain(domain)
    first_forms = mailbox_forms(first_name)
    last_forms = mailbox_forms(last_name)
    if not first_forms or not last_forms:
        raise InputError("The name needs letters that can appear in a mailbox.")
    primary_first = first_forms[0]
    primary_last = last_forms[0]
    best: dict[str, tuple[str, float, str]] = {}

    def consider(email: str, pattern_id: str, score: float, reason: str) -> None:
        current = best.get(email)
        if current is None or score > current[1]:
            best[email] = (pattern_id, round(score, 2), reason)

    inferred_id = inference.pattern if inference and inference.confidence > 0 else None
    inferred_score = 0.0
    if inference and inferred_id:
        inferred_score = round(0.40 + 0.57 * inference.confidence, 2)
    for pattern_id, template, prior in PATTERN_ORDER:
        _consider_form(
            consider,
            template,
            pattern_id,
            primary_first,
            primary_last,
            normalized_domain,
            prior,
            "common corporate pattern",
            inferred_id,
            inferred_score,
            variant=False,
        )
        for first_form in first_forms:
            for last_form in last_forms:
                if first_form == primary_first and last_form == primary_last:
                    continue
                _consider_form(
                    consider,
                    template,
                    pattern_id,
                    first_form,
                    last_form,
                    normalized_domain,
                    prior * 0.85,
                    "name spelling variant",
                    inferred_id,
                    inferred_score * 0.85,
                    variant=True,
                )
    ranked = sorted(
        best.items(),
        key=lambda item: (-item[1][1], -PATTERN_PRIOR[item[1][0]], item[0]),
    )
    candidates: list[Candidate] = []
    for index, (email, (pattern_id, score, reason)) in enumerate(ranked[: max(1, limit)], start=1):
        candidates.append(Candidate(email, pattern_id, index, score, reason))
    return candidates


def _consider_form(
    consider,
    template: str,
    pattern_id: str,
    first: str,
    last: str,
    domain: str,
    score: float,
    reason: str,
    inferred_id: str | None,
    inferred_score: float,
    *,
    variant: bool,
) -> None:
    rendered = _render(template, first, last)
    if rendered is None:
        return
    if inferred_id == pattern_id and inferred_score > 0:
        score = max(score, inferred_score)
        if variant:
            reason = f"inferred pattern {pattern_id}, alternate spelling"
        else:
            reason = f"matches inferred pattern {pattern_id}"
    consider(f"{rendered}@{domain}", pattern_id, score, reason)


def _from_named(domain: str, named: list[set[str]]) -> PatternInference:
    votes: Counter[str] = Counter()
    for hits in named:
        votes.update(hits)
    total = len(named)
    if not votes:
        return _empty(
            domain,
            total,
            ("Named addresses did not match a common mailbox pattern.",),
        )
    pattern_id = max(PATTERN_ORDER, key=lambda item: (votes[item[0]], item[2]))[0]
    alternates = tuple(
        PatternVote(candidate, votes[candidate])
        for candidate, _template, _prior in sorted(
            PATTERN_ORDER, key=lambda item: (votes[item[0]], item[2]), reverse=True
        )
        if votes[candidate] > 0
    )
    return PatternInference(
        domain=domain,
        pattern=pattern_id,
        confidence=sample_confidence(votes[pattern_id], total),
        sample_count=total,
        matched_count=votes[pattern_id],
        alternates=alternates,
        method="named",
        notes=(),
    )


def _from_structure(domain: str, locals_: list[str]) -> PatternInference:
    if len(locals_) < 3:
        return _empty(domain, 0, ())
    dotted = sum(1 for local in locals_ if re.fullmatch(r"[a-z]{2,}\.[a-z]{2,}", local))
    initial_dot = sum(1 for local in locals_ if re.fullmatch(r"[a-z]\.[a-z]{2,}", local))
    if dotted / len(locals_) >= 0.75:
        return PatternInference(
            domain=domain,
            pattern="first.last",
            confidence=STRUCTURAL_CONFIDENCE,
            sample_count=len(locals_),
            matched_count=dotted,
            alternates=(PatternVote("first.last", dotted),),
            method="structural",
            notes=("Structural guess only: local parts look like first.last and no names were available to confirm it.",),
        )
    if initial_dot / len(locals_) >= 0.75:
        return PatternInference(
            domain=domain,
            pattern="f.last",
            confidence=STRUCTURAL_CONFIDENCE,
            sample_count=len(locals_),
            matched_count=initial_dot,
            alternates=(PatternVote("f.last", initial_dot),),
            method="structural",
            notes=("Structural guess only: local parts look like f.last and no names were available to confirm it.",),
        )
    return _empty(
        domain,
        0,
        ("Addresses do not share a structure often enough to infer a pattern without names.",),
    )


def _empty(domain: str, sample_count: int, notes: tuple[str, ...]) -> PatternInference:
    return PatternInference(
        domain=domain,
        pattern=None,
        confidence=0.0,
        sample_count=sample_count,
        matched_count=0,
        alternates=(),
        method="none",
        notes=notes,
    )


def _resolve_names(item: KnownEmail) -> tuple[str | None, str | None]:
    first = item.first_name.strip() if item.first_name else None
    last = item.last_name.strip() if item.last_name else None
    if first and last:
        return first, last
    if item.full_name:
        split_first, split_last = split_name(item.full_name)
        return first or split_first, last or split_last
    return first, last


def _matching_patterns(local: str, first: str, last: str) -> set[str]:
    hits: set[str] = set()
    for first_form in mailbox_forms(first):
        for last_form in mailbox_forms(last):
            for pattern_id, template, _prior in PATTERN_ORDER:
                if _render(template, first_form, last_form) == local:
                    hits.add(pattern_id)
    return hits


def _render(template: str, first: str, last: str) -> str | None:
    if ("{first}" in template or "{f}" in template) and not first:
        return None
    if ("{last}" in template or "{l}" in template) and not last:
        return None
    local = template.format(
        first=first,
        last=last,
        f=first[:1],
        l=last[:1] if last else "",
    )
    if not _LOCAL_RE.fullmatch(local) or ".." in local:
        return None
    return local


def _on_domain(email: str, domain: str) -> bool:
    if "@" not in email:
        return False
    host = email.rsplit("@", 1)[1].rstrip(".")
    return host == domain


def _is_noreply(email: str) -> bool:
    host = email.rsplit("@", 1)[-1]
    return host in {"users.noreply.github.com", "noreply.github.com"}
