"""Classify an address as valid, invalid, accept-all, or unknown.

SMTP is a RCPT probe only. The probe never sends DATA, so no mail is delivered.
``valid`` requires the real mailbox to be accepted and a different, nonexistent
mailbox to be rejected. A TCP connect or an SMTP greeting is not acceptance.
A domain that accepts a deliberately nonexistent mailbox is accept-all: the
probe cannot tell whether the real mailbox exists. When the server accepts TCP
and never sends a greeting, the result is ``unknown`` with reason
``smtp_unreachable`` and ``mx_valid`` true. Port 25 is often blocked from
residential networks and cloud hosts; the port and timeout are configurable.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from openhunter.disposable import is_disposable_domain
from openhunter.roles import is_role_address
from openhunter.syntax import check_syntax

VerifyStatus = Literal["valid", "invalid", "accept_all", "unknown"]
RcptClass = Literal["accept", "reject", "temporary", "unreachable"]


@dataclass(frozen=True)
class MxLookup:
    hosts: tuple[str, ...] = ()
    null_mx: bool = False
    implicit_a: bool = False
    error: str | None = None


@dataclass(frozen=True)
class SmtpReply:
    code: int | None
    message: str = ""
    error: str | None = None


@dataclass(frozen=True)
class Verification:
    email: str
    status: VerifyStatus
    score: int
    syntax_ok: bool
    is_disposable: bool
    is_role: bool
    mx_hosts: tuple[str, ...]
    smtp_code: int | None
    smtp_error: str | None
    catch_all: bool | None
    notes: tuple[str, ...]
    reason: str | None = None
    mx_valid: bool = False


class MxResolver(Protocol):
    def lookup(self, domain: str) -> MxLookup:
        """Resolve MX hosts. ``error`` is set when DNS itself fails."""


class SmtpProber(Protocol):
    def probe_mailbox(
        self,
        mx_hosts: Sequence[str],
        recipient: str,
        *,
        timeout: float,
        port: int = 25,
    ) -> SmtpReply:
        """Issue MAIL FROM and RCPT TO. Do not send DATA."""


def verify_email(
    email: str,
    *,
    resolver: MxResolver,
    prober: SmtpProber,
    host_checker: Callable[[str], bool] | None = None,
    disposable_domains: Iterable[str] = (),
    smtp_enabled: bool = True,
    timeout: float = 5.0,
    smtp_port: int = 25,
) -> Verification:
    checker = host_checker or (lambda host: True)
    syntax = check_syntax(email)
    if not syntax.ok or syntax.normalized is None:
        return Verification(
            email=email.strip() if isinstance(email, str) else "",
            status="invalid",
            score=0,
            syntax_ok=False,
            is_disposable=False,
            is_role=False,
            mx_hosts=(),
            smtp_code=None,
            smtp_error=None,
            catch_all=None,
            notes=(f"syntax: {syntax.reason}",),
            reason="invalid_syntax",
            mx_valid=False,
        )
    normalized = syntax.normalized
    domain = normalized.split("@", 1)[1]
    disposable = is_disposable_domain(domain, disposable_domains)
    role = is_role_address(normalized)
    notes = _flags(disposable, role)
    looked = resolver.lookup(domain)
    if looked.error:
        if looked.error == "untrusted-dns":
            notes.append("Address records were private or fake-IP and were not used as a mail host.")
        else:
            notes.append(f"DNS lookup {looked.error}")
        return _result(
            normalized,
            "unknown",
            15,
            disposable,
            role,
            (),
            None,
            looked.error,
            None,
            notes,
            reason=_dns_reason(looked.error),
            mx_valid=False,
        )
    if looked.null_mx:
        notes.append("Domain publishes a null MX and does not accept mail.")
        return _result(
            normalized, "invalid", 5, disposable, role, (), None, None, False, notes, reason="null_mx"
        )
    if not looked.hosts:
        notes.append("No MX records.")
        return _result(
            normalized, "invalid", 5, disposable, role, (), None, None, False, notes, reason="no_mx"
        )
    if looked.implicit_a:
        notes.append("No MX record; the address record would be used.")
    safe = tuple(host for host in looked.hosts if checker(host))
    if not safe:
        notes.append("MX hosts are not public; skipped SMTP.")
        return _result(
            normalized,
            "unknown",
            20,
            disposable,
            role,
            looked.hosts,
            None,
            "private-mx",
            None,
            notes,
            reason="private_mx",
        )
    if not smtp_enabled:
        notes.append("SMTP probing is disabled.")
        return _result(
            normalized,
            "unknown",
            35,
            disposable,
            role,
            looked.hosts,
            None,
            None,
            None,
            notes,
            reason="smtp_disabled",
            mx_valid=True,
        )
    real = prober.probe_mailbox(safe, normalized, timeout=timeout, port=smtp_port)
    status, score, catch_all, smtp_code, smtp_error, probe_notes, reason = _interpret(
        real, prober, safe, domain, timeout, smtp_port
    )
    notes.extend(probe_notes)
    if status == "valid" and role:
        score = 80
    if disposable:
        score = min(score, 30)
    return _result(
        normalized,
        status,
        score,
        disposable,
        role,
        looked.hosts,
        smtp_code,
        smtp_error,
        catch_all,
        notes,
        reason=reason,
        mx_valid=True,
    )


def _interpret(
    real: SmtpReply,
    prober: SmtpProber,
    hosts: Sequence[str],
    domain: str,
    timeout: float,
    port: int,
) -> tuple[VerifyStatus, int, bool | None, int | None, str | None, list[str], str | None]:
    kind = _classify(real)
    if kind == "reject":
        return "invalid", 10, False, real.code, real.error, [], "recipient_rejected"
    if kind == "temporary":
        return (
            "unknown",
            45,
            None,
            real.code,
            real.error,
            ["The mail server asked us to try again later."],
            "smtp_temporary",
        )
    if kind == "unreachable":
        return (
            "unknown",
            40,
            None,
            real.code,
            real.error,
            [_unreachable_note(real, port)],
            real.error or "smtp_unreachable",
        )
    if kind == "accept":
        token = secrets.token_hex(8)
        random_address = f"zz-no-such-mailbox-{token}@{domain}"
        probe = prober.probe_mailbox(hosts, random_address, timeout=timeout, port=port)
        probe_kind = _classify(probe)
        if probe_kind == "accept":
            return (
                "accept_all",
                55,
                True,
                real.code,
                None,
                ["Domain accepts mail for a nonexistent mailbox (catch-all)."],
                "accept_all",
            )
        if probe_kind == "reject":
            # Both results are RCPT replies. A greeting or a bare connect is
            # classified above as unreachable and cannot reach this return.
            if not _rcpt_code(real) or not _rcpt_code(probe):
                return (
                    "unknown",
                    58,
                    None,
                    real.code,
                    probe.error,
                    ["The address was not confirmed by RCPT."],
                    "rcpt_incomplete",
                )
            return "valid", 96, False, real.code, None, [], None
        if probe_kind == "temporary" or probe_kind == "unreachable":
            return (
                "unknown",
                58,
                None,
                real.code,
                probe.error,
                ["The address was accepted, but a catch-all check did not finish."],
                "catch_all_incomplete",
            )
        _never(probe_kind)
    _never(kind)


def _classify(reply: SmtpReply) -> RcptClass:
    # An error means this reply is not an RCPT decision, even when a banner
    # code such as 220 or 250 was captured on the way down.
    if reply.error is not None or reply.code is None:
        return "unreachable"
    if 200 <= reply.code < 300:
        return "accept"
    if 500 <= reply.code < 600:
        return "reject"
    if 400 <= reply.code < 500:
        return "temporary"
    return "unreachable"


def _rcpt_code(reply: SmtpReply) -> bool:
    return reply.error is None and reply.code is not None


def _unreachable_note(reply: SmtpReply, port: int) -> str:
    if reply.error == "smtp_unreachable":
        return (
            f"The mail server accepted TCP on port {port} but sent no SMTP greeting "
            "before the timeout. The mailbox was not verified."
        )
    if reply.error in {"timeout", "refused", "blocked", "unreachable", "disconnected"}:
        return f"Outbound port {port} was unreachable or timed out; the mailbox was not verified."
    if reply.error == "mail-from-rejected":
        return "The server rejected MAIL FROM before RCPT could be checked."
    if reply.error:
        return f"SMTP probe failed ({reply.error})."
    return "SMTP probe did not return an RCPT result."


def _dns_reason(error: str) -> str:
    if error == "untrusted-dns":
        return "untrusted-dns"
    if error == "dns":
        return "dns_error"
    return f"dns_{error}"


def _flags(disposable: bool, role: bool) -> list[str]:
    notes: list[str] = []
    if disposable:
        notes.append("Disposable mailbox provider.")
    if role:
        notes.append("Role address.")
    return notes


def _result(
    email: str,
    status: VerifyStatus,
    score: int,
    disposable: bool,
    role: bool,
    mx_hosts: tuple[str, ...],
    smtp_code: int | None,
    smtp_error: str | None,
    catch_all: bool | None,
    notes: list[str],
    *,
    reason: str | None = None,
    mx_valid: bool = False,
) -> Verification:
    _check_status(status)
    bounded = max(0, min(100, score))
    return Verification(
        email=email,
        status=status,
        score=bounded,
        syntax_ok=True,
        is_disposable=disposable,
        is_role=role,
        mx_hosts=mx_hosts,
        smtp_code=smtp_code,
        smtp_error=smtp_error,
        catch_all=catch_all,
        notes=tuple(notes),
        reason=reason,
        mx_valid=mx_valid,
    )


def _check_status(status: VerifyStatus) -> None:
    if status == "valid" or status == "invalid" or status == "accept_all" or status == "unknown":
        return
    _never(status)


def _never(value: object) -> None:
    raise RuntimeError(f"unhandled verification state: {value!r}")
