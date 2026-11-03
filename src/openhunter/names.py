"""Human-name splitting used by pattern inference and lead entry.

Middle names are dropped on purpose: mailbox patterns almost always use the
first given name and the final surname. Name particles (van, de, di, ...) stay
on the surname so "Vincent van Gogh" can match vincent.vangogh.
"""

from __future__ import annotations

import re
import unicodedata

HONORIFICS = frozenset(
    {"dr", "mr", "mrs", "ms", "miss", "mx", "prof", "professor", "sir", "dame"}
)
SUFFIXES = frozenset({"jr", "sr", "ii", "iii", "iv", "phd", "md", "mba", "cpa", "esq"})
PARTICLES = frozenset(
    {"van", "von", "de", "da", "di", "del", "der", "den", "la", "le", "st", "san", "bin", "al"}
)


def strip_accents(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value)
    return "".join(character for character in decomposed if not unicodedata.combining(character))


def split_name(full: str | None) -> tuple[str | None, str | None]:
    if full is None or not full.strip():
        return None, None
    cleaned = full.replace(",", " ")
    parts = [part.strip(".") for part in cleaned.split() if part.strip(".")]
    while parts and parts[0].lower().rstrip(".") in HONORIFICS:
        parts.pop(0)
    while parts and parts[-1].lower().rstrip(".") in SUFFIXES:
        parts.pop()
    if not parts:
        return None, None
    if len(parts) == 1:
        return parts[0], None
    if len(parts) >= 3 and parts[-2].lower() in PARTICLES:
        return parts[0], f"{parts[-2]} {parts[-1]}"
    return parts[0], parts[-1]


def mailbox_forms(value: str) -> list[str]:
    """Lowercase mailbox tokens for a name part, compact form first.

    "Anne-Marie" yields ``annemarie`` and ``anne-marie``. "van Gogh" yields
    ``vangogh``, ``van-gogh``, and ``gogh``.
    """
    parts = [part for part in re.split(r"\s+", strip_accents(value).strip()) if part]
    if not parts:
        return []
    forms: list[str] = []

    def add(token: str) -> None:
        cleaned = token.strip("-")
        if cleaned and cleaned not in forms:
            forms.append(cleaned)

    compact_parts = [_letters(part, keep_hyphen=False) for part in parts]
    compact_parts = [part for part in compact_parts if part]
    if compact_parts:
        add("".join(compact_parts))
        if len(compact_parts) > 1 or any("-" in part for part in parts):
            add("-".join(compact_parts))
    if len(parts) == 1 and "-" in parts[0]:
        add(_letters(parts[0], keep_hyphen=True))
    if len(parts) >= 2 and _letters(parts[-2], keep_hyphen=False) in PARTICLES:
        add(_letters(parts[-1], keep_hyphen=False))
    return forms


def _letters(token: str, *, keep_hyphen: bool) -> str:
    raw = strip_accents(token).lower().replace("'", "").replace("’", "").replace("`", "")
    raw = re.sub(r"[^a-z0-9-]", "", raw)
    if not keep_hyphen:
        raw = raw.replace("-", "")
    return raw.strip("-")
