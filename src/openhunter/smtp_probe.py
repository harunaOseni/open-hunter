"""RCPT probe. The conversation ends before DATA, so nothing is delivered.

The TCP connection and the SMTP greeting are timed separately. A peer that
accepts the socket and never sends a banner is ``smtp_unreachable``: that is
not an RCPT result, and it must not be reported as a valid mailbox.
``OPENHUNTER_SMTP_PORT`` selects the port (default 25). The per-attempt
timeout is the ``timeout`` argument, normally ``OPENHUNTER_SMTP_TIMEOUT``.
"""

from __future__ import annotations

import os
import smtplib
import socket
from collections.abc import Callable, Sequence
from typing import BinaryIO

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
            # A code is an RCPT result only when error is unset. A banner that
            # is not 220 still carries a code, and that must not end the probe
            # or be treated as acceptance of the mailbox.
            if reply.error is None or reply.error == "mail-from-rejected":
                return reply
            last = reply
        return last


def configured_smtp_port(default: int = 25) -> int:
    """Return ``OPENHUNTER_SMTP_PORT`` when it is a TCP port, else ``default``."""
    raw = os.environ.get("OPENHUNTER_SMTP_PORT", "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError:
        return default
    if 1 <= port <= 65535:
        return port
    return default


def _probe_one(
    host: str,
    port: int,
    recipient: str,
    timeout: float,
    mail_from: str,
    helo: str,
) -> SmtpReply:
    try:
        sock = socket.create_connection((host, port), timeout)
    except TimeoutError:
        return SmtpReply(None, "", "timeout")
    except ConnectionRefusedError:
        return SmtpReply(None, "", "refused")
    except OSError as exc:
        return _from_os_error(exc)

    try:
        smtp = smtplib.SMTP(timeout=timeout)
    except OSError:
        sock.close()
        return SmtpReply(None, "", "unreachable")
    smtp.sock = sock
    try:
        sock.settimeout(timeout)
        reader = sock.makefile("rb")
        smtp.file = reader
        try:
            code, message = _read_smtp_reply(reader)
        except TimeoutError:
            # The handshake completed and then the banner never arrived.
            # This is not an RCPT code; callers must not treat it as valid.
            return SmtpReply(None, "", "smtp_unreachable")
        except (ConnectionError, OSError):
            return SmtpReply(None, "", "disconnected")
        if code != 220:
            return SmtpReply(code if code >= 100 else None, _text(message), "protocol")
        return _rcpt(smtp, recipient, mail_from, helo)
    except TimeoutError:
        return SmtpReply(None, "", "timeout")
    except smtplib.SMTPConnectError as exc:
        return SmtpReply(None, _text(getattr(exc, "smtp_error", b"")), "refused")
    except smtplib.SMTPServerDisconnected as exc:
        if _mentions_timeout(exc):
            return SmtpReply(None, "", "timeout")
        return SmtpReply(None, "", "disconnected")
    except smtplib.SMTPSenderRefused as exc:
        return SmtpReply(None, _text(exc.smtp_error), "mail-from-rejected")
    except smtplib.SMTPResponseException as exc:
        # This is not the RCPT reply. Keep the code for debugging, but set an
        # error so a 2xx banner or EHLO failure cannot be reported as valid.
        return SmtpReply(exc.smtp_code, _text(exc.smtp_error), "protocol")
    except smtplib.SMTPException:
        return SmtpReply(None, "", "protocol")
    except OSError as exc:
        return _from_os_error(exc)
    finally:
        try:
            smtp.close()
        except (smtplib.SMTPException, OSError):
            pass


def _rcpt(smtp: smtplib.SMTP, recipient: str, mail_from: str, helo: str) -> SmtpReply:
    """MAIL FROM / RCPT TO only. DATA is never sent, so nothing is delivered."""
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


def _read_smtp_reply(source: BinaryIO) -> tuple[int, bytes]:
    """Read one SMTP reply, including a multiline banner.

    ``TimeoutError`` propagates so a missing greeting stays distinct from a
    later command that times out after a real banner.
    """
    resp: list[bytes] = []
    while True:
        line = source.readline(8192)
        if not line:
            raise ConnectionError("SMTP connection closed before a reply")
        stripped = line.rstrip(b"\r\n")
        if len(stripped) < 3 or not stripped[:3].isdigit():
            raise ConnectionError("SMTP reply has no code")
        text = stripped[4:] if len(stripped) > 3 else b""
        resp.append(text.strip(b" \t"))
        if stripped[3:4] != b"-":
            return int(stripped[:3]), b"\n".join(resp)


def _mentions_timeout(exc: BaseException) -> bool:
    text = str(exc).lower()
    return "timed out" in text or "timeout" in text


def _from_os_error(exc: OSError) -> SmtpReply:
    if isinstance(exc, TimeoutError):
        return SmtpReply(None, "", "timeout")
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
