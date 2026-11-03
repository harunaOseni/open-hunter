"""RCPT probe. The conversation ends before DATA, so nothing is delivered."""

from __future__ import annotations

import smtplib
import socket
from collections.abc import Callable, Sequence

from openhunter.net import host_is_public
from openhunter.verifier import SmtpReply

HostChecker = Callable[[str], bool]


class LiveSmtpProber:
    def __init__(
        self,
        timeout: float = 5.0,
        mail_from: str = "",
        host_checker: HostChecker = host_is_public,
        helo: str | None = None,
    ) -> None:
        self.timeout = timeout
        self.mail_from = mail_from
        self.host_checker = host_checker
        self.helo = helo or _helo_name()

    def probe_mailbox(
        self,
        mx_hosts: Sequence[str],
        recipient: str,
        *,
        timeout: float,
        port: int = 25,
    ) -> SmtpReply:
        last = SmtpReply(None, "", "unreachable")
        for host in list(mx_hosts)[:2]:
            if not self.host_checker(host):
                last = SmtpReply(None, "", "private-mx")
                continue
            reply = _probe_one(host, port, recipient, timeout, self.mail_from, self.helo)
            if reply.code is not None or reply.error == "mail-from-rejected":
                return reply
            last = reply
        return last


def _probe_one(
    host: str,
    port: int,
    recipient: str,
    timeout: float,
    mail_from: str,
    helo: str,
) -> SmtpReply:
    try:
        with smtplib.SMTP(host, port, timeout=timeout) as smtp:
            smtp.ehlo(helo)
            code, message = smtp.mail(mail_from)
            if code >= 400:
                return SmtpReply(None, _text(message), "mail-from-rejected")
            code, message = smtp.rcpt(recipient)
            try:
                smtp.quit()
            except smtplib.SMTPException:
                pass
            return SmtpReply(code, _text(message), None)
    except socket.timeout:
        return SmtpReply(None, "", "timeout")
    except ConnectionRefusedError:
        return SmtpReply(None, "", "refused")
    except smtplib.SMTPConnectError as exc:
        return SmtpReply(None, _text(getattr(exc, "smtp_error", b"")), "refused")
    except smtplib.SMTPServerDisconnected:
        return SmtpReply(None, "", "disconnected")
    except smtplib.SMTPSenderRefused as exc:
        return SmtpReply(None, _text(exc.smtp_error), "mail-from-rejected")
    except smtplib.SMTPResponseException as exc:
        return SmtpReply(exc.smtp_code, _text(exc.smtp_error), None)
    except smtplib.SMTPException:
        return SmtpReply(None, "", "protocol")
    except OSError as exc:
        if exc.errno in {110, 101, 113}:
            return SmtpReply(None, "", "blocked")
        if exc.errno == 111:
            return SmtpReply(None, "", "refused")
        return SmtpReply(None, "", "unreachable")


def _text(message: object) -> str:
    if isinstance(message, bytes):
        return message.decode("utf-8", errors="replace")
    return str(message or "")


def _helo_name() -> str:
    name = socket.getfqdn()
    if "." in name and name.lower() != "localhost":
        return name
    return "openhunter.local"
