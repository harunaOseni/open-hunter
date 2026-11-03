"""Role-address detection.

A role address is a shared inbox (info@, security@, noreply@), not a person.
Patterns inferred from those addresses describe the inbox, not the company format.
"""

from __future__ import annotations

import re

ROLE_LOCALS = frozenset(
    {
        "info",
        "hello",
        "hi",
        "contact",
        "support",
        "help",
        "admin",
        "administrator",
        "sales",
        "marketing",
        "press",
        "media",
        "jobs",
        "careers",
        "hr",
        "recruiting",
        "talent",
        "team",
        "office",
        "enquiries",
        "inquiries",
        "abuse",
        "postmaster",
        "hostmaster",
        "webmaster",
        "noreply",
        "no-reply",
        "donotreply",
        "notifications",
        "notification",
        "newsletter",
        "news",
        "billing",
        "accounts",
        "finance",
        "legal",
        "privacy",
        "security",
        "feedback",
        "partners",
        "partner",
        "root",
        "it",
        "ops",
        "operations",
        "success",
        "service",
        "mail",
        "email",
        "general",
        "customerservice",
        "customercare",
        "founders",
    }
)


def is_role_address(email: str) -> bool:
    if "@" not in email:
        return False
    raw = email.split("@", 1)[0].split("+", 1)[0].lower()
    compact = re.sub(r"[._-]", "", raw)
    if raw in ROLE_LOCALS or compact in ROLE_LOCALS:
        return True
    if compact.startswith(("noreply", "donotreply", "mailerdaemon", "bounce")):
        return True
    tokens = [token for token in re.split(r"[._-]+", raw) if token]
    if tokens and all(token in ROLE_LOCALS for token in tokens):
        return True
    if len(tokens) == 2 and tokens[0] in ROLE_LOCALS and len(tokens[1]) <= 3:
        return True
    return False


def role_label(email: str) -> str | None:
    if not is_role_address(email):
        return None
    local = email.split("@", 1)[0].split("+", 1)[0]
    token = re.split(r"[._-]+", local)[0]
    return token.lower() or None
