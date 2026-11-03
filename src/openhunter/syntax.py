"""Practical mailbox syntax for outreach verification.

The checker is intentionally stricter than RFC 5322. Quoted local parts,
domain literals, and control characters are rejected. Control characters are
rejected before an address can reach an SMTP socket, so a value cannot inject
a second SMTP command.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_LOCAL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?|[A-Za-z0-9]")
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_TLD = re.compile(r"[A-Za-z]{2,24}")


@dataclass(frozen=True)
class SyntaxResult:
    ok: bool
    normalized: str | None
    reason: str | None


def check_syntax(email: object) -> SyntaxResult:
    if not isinstance(email, str):
        return SyntaxResult(False, None, "address must be text")
    if _CONTROL.search(email):
        return SyntaxResult(False, None, "invalid characters")
    stripped = email.strip()
    if any(character.isspace() for character in stripped):
        return SyntaxResult(False, None, "invalid characters")
    if not stripped:
        return SyntaxResult(False, None, "address is empty")
    if len(stripped) > 254:
        return SyntaxResult(False, None, "address is too long")
    if stripped.count("@") != 1:
        return SyntaxResult(False, None, "address needs one @")
    local, domain = stripped.split("@")
    if not _LOCAL.fullmatch(local) or ".." in local:
        return SyntaxResult(False, None, "invalid local part")
    if len(local) > 64:
        return SyntaxResult(False, None, "local part is too long")
    try:
        domain_ascii = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return SyntaxResult(False, None, "invalid domain")
    if domain_ascii.endswith(".") or ".." in domain_ascii:
        return SyntaxResult(False, None, "invalid domain")
    labels = domain_ascii.split(".")
    if len(labels) < 2:
        return SyntaxResult(False, None, "domain needs a dot")
    if any(not _LABEL.fullmatch(label) for label in labels[:-1]):
        return SyntaxResult(False, None, "invalid domain")
    if not _TLD.fullmatch(labels[-1]):
        return SyntaxResult(False, None, "invalid domain")
    normalized = f"{local.lower()}@{domain_ascii.lower()}"
    return SyntaxResult(True, normalized, None)
