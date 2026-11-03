"""A starter set of disposable mailbox domains.

This is not exhaustive. Pass extra domains via OPENHUNTER_DISPOSABLE_FILE
(one domain per line) when you have a list you trust. Subdomains match:
``a.mailinator.com`` is disposable because ``mailinator.com`` is.
"""

from __future__ import annotations

from collections.abc import Iterable

DISPOSABLE_DOMAINS = frozenset(
    {
        "mailinator.com",
        "mailinator.net",
        "mailinator.org",
        "guerrillamail.com",
        "guerrillamail.info",
        "guerrillamail.net",
        "guerrillamail.org",
        "guerrillamail.biz",
        "guerrillamail.de",
        "guerrillamailblock.com",
        "sharklasers.com",
        "grr.la",
        "tempmail.com",
        "temp-mail.org",
        "temp-mail.io",
        "10minutemail.com",
        "10minutemail.net",
        "yopmail.com",
        "yopmail.fr",
        "trashmail.com",
        "trashmail.de",
        "trashmail.net",
        "trashmail.org",
        "dispostable.com",
        "getnada.com",
        "maildrop.cc",
        "fakeinbox.com",
        "throwawaymail.com",
        "mohmal.com",
        "emailondeck.com",
        "mailnesia.com",
        "mintemail.com",
        "mytemp.email",
        "tempinbox.com",
        "spamgourmet.com",
        "spamgourmet.net",
        "mailcatch.com",
        "trash-mail.com",
        "discard.email",
        "mailnull.com",
        "tempr.email",
        "inboxkitten.com",
        "spam4.me",
        "mailsac.com",
        "tempmailo.com",
        "moakt.com",
        "tmpmail.org",
        "tmpmail.net",
        "tmail.ws",
        "discardmail.com",
        "getairmail.com",
        "safetymail.info",
        "wegwerfmail.de",
        "wegwerfmail.net",
        "mailexpire.com",
        "mailforspam.com",
        "filzmail.com",
        "anonbox.net",
        "deadaddress.com",
        "jetable.org",
        "trashymail.com",
        "burnermail.io",
    }
)


def is_disposable_domain(domain: str, extra: Iterable[str] = ()) -> bool:
    labels = domain.lower().strip(".").split(".")
    if len(labels) < 2:
        return False
    extras = {item.strip().lower().strip(".") for item in extra if item.strip()}
    for index in range(len(labels) - 1):
        candidate = ".".join(labels[index:])
        if candidate in DISPOSABLE_DOMAINS or candidate in extras:
            return True
    return False
