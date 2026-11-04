"""Verification decisions with fake DNS and SMTP, plus one live local dialogue.

The live dialogue binds 127.0.0.1 only to prove the probe speaks SMTP and
stops before DATA. It does not contact a third-party mail server.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable

import pytest

from openhunter.smtp_probe import LiveSmtpProber, configured_smtp_port
from openhunter.verifier import MxLookup, SmtpReply, verify_email


class FixedMx:
    def __init__(self, result: MxLookup) -> None:
        self.result = result
        self.calls: list[str] = []

    def lookup(self, domain: str) -> MxLookup:
        self.calls.append(domain)
        return self.result


class ScriptedSmtp:
    def __init__(self, handler) -> None:
        self.handler = handler
        self.calls: list[str] = []

    def probe_mailbox(
        self,
        mx_hosts: list[str],
        recipient: str,
        *,
        timeout: float,
        port: int = 25,
    ) -> SmtpReply:
        del mx_hosts, timeout, port
        self.calls.append(recipient)
        return self.handler(recipient)


def _verify(email: str, resolver: FixedMx, prober: ScriptedSmtp, **kwargs):
    return verify_email(
        email,
        resolver=resolver,
        prober=prober,
        host_checker=lambda host: True,
        **kwargs,
    )


def test_invalid_syntax_does_not_touch_the_network() -> None:
    resolver = FixedMx(MxLookup(hosts=("mx.example.com",)))
    prober = ScriptedSmtp(lambda recipient: (_ for _ in ()).throw(AssertionError(recipient)))
    result = _verify("ada@example.com\r\nRCPT TO:<other@example.com>", resolver, prober)
    assert result.syntax_ok is False
    assert result.status == "invalid"
    assert result.score == 0
    assert resolver.calls == []
    assert prober.calls == []
    assert "syntax" in " ".join(result.notes).lower()


@pytest.mark.parametrize(
    "email",
    [
        "not-an-email",
        "a@b",
        "ada@",
        "@example.com",
        "ada..lovelace@example.com",
        ".ada@example.com",
        "ada@example.com.",
        "ada@-example.com",
        "ada example@example.com",
        "",
        "ada@localhost",
    ],
)
def test_rejects_malformed_addresses(email: str) -> None:
    resolver = FixedMx(MxLookup())
    prober = ScriptedSmtp(lambda recipient: SmtpReply(250, "ok", None))
    result = _verify(email, resolver, prober)
    assert result.status == "invalid"
    assert result.score == 0
    assert prober.calls == []


def test_accepts_a_normal_address_and_probes_the_normalized_form() -> None:
    resolver = FixedMx(MxLookup(hosts=("mx.example.com",)))

    def handler(recipient: str) -> SmtpReply:
        if recipient.startswith("zz-no-such-mailbox-"):
            return SmtpReply(550, "no such user", None)
        return SmtpReply(250, "ok", None)

    prober = ScriptedSmtp(handler)
    result = _verify("Ada.Lovelace+job@Example.COM", resolver, prober)
    assert result.syntax_ok is True
    assert result.email == "ada.lovelace+job@example.com"
    assert prober.calls[0] == "ada.lovelace+job@example.com"
    assert result.status == "valid"
    assert result.score == 96
    assert result.catch_all is False
    assert result.smtp_code == 250
    assert result.mx_valid is True
    assert result.reason is None
    assert resolver.calls == ["example.com"]


def test_role_and_disposable_flags() -> None:
    assert _flag("info@example.com").is_role is True
    assert _flag("support.team@example.com").is_role is True
    assert _flag("sales.us@example.com").is_role is True
    assert _flag("noreply+alerts@example.com").is_role is True
    assert _flag("jane.doe@example.com").is_role is False
    assert _flag("ada@mailinator.com").is_disposable is True
    assert _flag("ada@a.mailinator.com").is_disposable is True
    assert _flag("ada@example.com").is_disposable is False


def _flag(email: str):
    resolver = FixedMx(MxLookup(hosts=("mx.example.com",)))
    prober = ScriptedSmtp(
        lambda recipient: SmtpReply(550, "nope", None)
        if recipient.startswith("zz-no-such-mailbox-")
        else SmtpReply(250, "ok", None)
    )
    return _verify(email, resolver, prober)


def test_valid_role_address_scores_lower_than_a_person_mailbox() -> None:
    result = _flag("info@example.com")
    assert result.status == "valid"
    assert result.is_role is True
    assert result.score == 80


def test_valid_disposable_address_is_capped() -> None:
    result = _flag("ada@mailinator.com")
    assert result.status == "valid"
    assert result.is_disposable is True
    assert result.score == 30


def test_no_mx_is_invalid_and_skips_smtp() -> None:
    resolver = FixedMx(MxLookup(hosts=()))
    prober = ScriptedSmtp(lambda recipient: SmtpReply(250, "ok", None))
    result = _verify("ada@example.com", resolver, prober)
    assert result.status == "invalid"
    assert result.score == 5
    assert prober.calls == []
    assert any("mx" in note.lower() for note in result.notes)


def test_null_mx_is_invalid() -> None:
    resolver = FixedMx(MxLookup(hosts=(), null_mx=True))
    prober = ScriptedSmtp(lambda recipient: SmtpReply(250, "ok", None))
    result = _verify("ada@example.com", resolver, prober)
    assert result.status == "invalid"
    assert result.score == 5
    assert any("null mx" in note.lower() for note in result.notes)
    assert prober.calls == []


def test_dns_timeout_is_unknown() -> None:
    resolver = FixedMx(MxLookup(error="timeout"))
    prober = ScriptedSmtp(lambda recipient: SmtpReply(250, "ok", None))
    result = _verify("ada@example.com", resolver, prober)
    assert result.status == "unknown"
    assert result.score == 15
    assert prober.calls == []


def test_private_mx_is_not_probed() -> None:
    resolver = FixedMx(MxLookup(hosts=("mail.internal.example",)))
    prober = ScriptedSmtp(lambda recipient: (_ for _ in ()).throw(AssertionError("probed")))
    result = verify_email(
        "ada@example.com",
        resolver=resolver,
        prober=prober,
        host_checker=lambda host: False,
    )
    assert result.status == "unknown"
    assert result.score == 20
    assert any("public" in note.lower() or "private" in note.lower() for note in result.notes)


def test_recipient_rejected_does_not_need_a_catch_all_probe() -> None:
    resolver = FixedMx(MxLookup(hosts=("mx.example.com",)))
    prober = ScriptedSmtp(lambda recipient: SmtpReply(550, "no such user", None))
    result = _verify("ada@example.com", resolver, prober)
    assert result.status == "invalid"
    assert result.score == 10
    assert result.catch_all is False
    assert prober.calls == ["ada@example.com"]


def test_accepted_recipient_on_a_catch_all_domain() -> None:
    resolver = FixedMx(MxLookup(hosts=("mx.example.com",)))
    prober = ScriptedSmtp(lambda recipient: SmtpReply(250, "ok", None))
    result = _verify("ada@example.com", resolver, prober)
    assert result.status == "accept_all"
    assert result.score == 55
    assert result.catch_all is True
    assert len(prober.calls) == 2
    assert prober.calls[1].startswith("zz-no-such-mailbox-")
    assert prober.calls[1].endswith("@example.com")


def test_catch_all_probe_failure_stays_unknown() -> None:
    resolver = FixedMx(MxLookup(hosts=("mx.example.com",)))

    def handler(recipient: str) -> SmtpReply:
        if recipient.startswith("zz-no-such-mailbox-"):
            return SmtpReply(None, "", "timeout")
        return SmtpReply(250, "ok", None)

    prober = ScriptedSmtp(handler)
    result = _verify("ada@example.com", resolver, prober)
    assert result.status == "unknown"
    assert result.score == 58
    assert result.catch_all is None
    assert any("catch-all" in note.lower() or "catch all" in note.lower() for note in result.notes)


def test_temporary_smtp_failure_is_unknown() -> None:
    resolver = FixedMx(MxLookup(hosts=("mx.example.com",)))
    prober = ScriptedSmtp(lambda recipient: SmtpReply(450, "try again", None))
    result = _verify("ada@example.com", resolver, prober)
    assert result.status == "unknown"
    assert result.score == 45
    assert prober.calls == ["ada@example.com"]


def test_port_25_unreachable_is_unknown_with_an_honest_note() -> None:
    resolver = FixedMx(MxLookup(hosts=("mx.example.com", "mx2.example.com")))
    prober = ScriptedSmtp(lambda recipient: SmtpReply(None, "", "timeout"))
    result = _verify("ada@example.com", resolver, prober)
    assert result.status == "unknown"
    assert result.score == 40
    assert result.mx_valid is True
    assert result.reason == "timeout"
    assert result.mx_hosts == ("mx.example.com", "mx2.example.com")
    note = " ".join(result.notes).lower()
    assert "port 25" in note


def test_smtp_can_be_disabled() -> None:
    resolver = FixedMx(MxLookup(hosts=("mx.example.com",)))
    prober = ScriptedSmtp(lambda recipient: (_ for _ in ()).throw(AssertionError("probed")))
    result = _verify("ada@example.com", resolver, prober, smtp_enabled=False)
    assert result.status == "unknown"
    assert result.score == 35
    assert any("disabled" in note.lower() for note in result.notes)


def test_scores_stay_in_range() -> None:
    samples = [
        _flag("ada@example.com"),
        _flag("info@mailinator.com"),
    ]
    assert all(0 <= item.score <= 100 for item in samples)
    disposable_role = _flag("info@mailinator.com")
    assert disposable_role.score <= 30


def test_live_probe_stops_before_data_and_reports_rcpt_codes() -> None:
    seen: list[str] = []
    ready = threading.Event()
    port: dict[str, int] = {}

    def serve() -> None:
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port["value"] = server.getsockname()[1]
        ready.set()
        for _connection in range(2):
            conn, _addr = server.accept()
            try:
                reader = conn.makefile("r", encoding="utf-8", newline="\n")
                writer = conn.makefile("w", encoding="utf-8", newline="\n")

                def send(line: str) -> None:
                    writer.write(line + "\r\n")
                    writer.flush()

                send("220 test.example ESMTP")
                while True:
                    line = reader.readline()
                    if not line:
                        break
                    seen.append(line.strip())
                    command = line.strip().upper()
                    if command.startswith("EHLO") or command.startswith("HELO"):
                        send("250-test.example")
                        send("250 OK")
                    elif command.startswith("MAIL"):
                        send("250 OK")
                    elif command.startswith("RCPT"):
                        if "reject-me" in line.lower():
                            send("550 5.1.1 no such user")
                        else:
                            send("250 2.1.5 OK")
                    elif command.startswith("DATA"):
                        send("550 DATA is not allowed")
                    elif command.startswith("QUIT"):
                        send("221 bye")
                        break
                    else:
                        send("502 unknown")
            finally:
                conn.close()
        server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert ready.wait(2)
    prober = LiveSmtpProber(timeout=2, host_checker=lambda host: True)
    accepted = prober.probe_mailbox(["127.0.0.1"], "ada@example.com", timeout=2, port=port["value"])
    rejected = prober.probe_mailbox(
        ["127.0.0.1"], "reject-me@example.com", timeout=2, port=port["value"]
    )
    thread.join(2)
    assert accepted.code == 250
    assert rejected.code == 550
    assert not any(line.upper().startswith("DATA") for line in seen)


def test_live_probe_reports_connection_refused() -> None:
    prober = LiveSmtpProber(timeout=1, host_checker=lambda host: True)
    # Bind a port and close it so the connect fails immediately instead of
    # guessing a closed port that a firewall might blackhole.
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    closed = sock.getsockname()[1]
    sock.close()
    reply = prober.probe_mailbox(["127.0.0.1"], "ada@example.com", timeout=1, port=closed)
    assert reply.code is None
    assert reply.error in {"refused", "blocked", "unreachable", "timeout"}


def test_smtp_port_and_timeout_are_forwarded_to_the_probe() -> None:
    seen: dict[str, object] = {}

    class Capture:
        def probe_mailbox(self, mx_hosts: list[str], recipient: str, *, timeout: float, port: int = 25) -> SmtpReply:
            seen["hosts"] = tuple(mx_hosts)
            seen["recipient"] = recipient
            seen["timeout"] = timeout
            seen["port"] = port
            return SmtpReply(550, "no such user", None)

    result = verify_email(
        "ada@example.com",
        resolver=FixedMx(MxLookup(hosts=("aspmx.l.google.com",))),
        prober=Capture(),
        host_checker=lambda host: True,
        timeout=2.5,
        smtp_port=587,
    )
    assert result.status == "invalid"
    assert seen == {
        "hosts": ("aspmx.l.google.com",),
        "recipient": "ada@example.com",
        "timeout": 2.5,
        "port": 587,
    }


def test_unreachable_note_names_the_configured_port() -> None:
    resolver = FixedMx(MxLookup(hosts=("aspmx.l.google.com",)))
    prober = ScriptedSmtp(lambda recipient: SmtpReply(None, "", "timeout"))
    result = verify_email(
        "ada@example.com",
        resolver=resolver,
        prober=prober,
        host_checker=lambda host: True,
        smtp_port=587,
    )
    assert result.status == "unknown"
    assert result.mx_valid is True
    assert "587" in " ".join(result.notes)
    assert result.status != "valid"


def test_banner_code_without_an_rcpt_result_is_not_valid() -> None:
    resolver = FixedMx(MxLookup(hosts=("aspmx.l.google.com",)))
    prober = ScriptedSmtp(lambda recipient: SmtpReply(250, "not an rcpt", "protocol"))
    result = _verify("ada@example.com", resolver, prober)
    assert result.status == "unknown"
    assert result.status != "valid"
    assert result.mx_valid is True
    assert prober.calls == ["ada@example.com"]


def test_smtp_unreachable_is_unknown_with_mx_still_valid() -> None:
    resolver = FixedMx(MxLookup(hosts=("aspmx.l.google.com", "alt1.aspmx.l.google.com")))
    prober = ScriptedSmtp(lambda recipient: SmtpReply(None, "", "smtp_unreachable"))
    result = _verify("ada@anthropic.com", resolver, prober)
    assert result.status == "unknown"
    assert result.reason == "smtp_unreachable"
    assert result.mx_valid is True
    assert result.smtp_code is None
    assert result.mx_hosts[0] == "aspmx.l.google.com"
    assert result.catch_all is None
    assert prober.calls == ["ada@anthropic.com"]
    note = " ".join(result.notes).lower()
    assert "greeting" in note
    assert "not verified" in note


def test_missing_greeting_tries_the_next_mail_host(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake(host: str, port: int, recipient: str, timeout: float, mail_from: str, helo: str) -> SmtpReply:
        del port, recipient, timeout, mail_from, helo
        calls.append(host)
        if host == "mx1.example":
            return SmtpReply(250, "not a greeting", "protocol")
        return SmtpReply(250, "2.1.5 OK", None)

    monkeypatch.setattr("openhunter.smtp_probe._probe_one", fake)
    prober = LiveSmtpProber(host_checker=lambda host: True)
    reply = prober.probe_mailbox(
        ["mx1.example", "mx2.example"], "ada@example.com", timeout=1, port=2525
    )
    assert calls == ["mx1.example", "mx2.example"]
    assert reply.code == 250
    assert reply.error is None


def test_configured_smtp_port_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENHUNTER_SMTP_PORT", raising=False)
    assert configured_smtp_port() == 25
    monkeypatch.setenv("OPENHUNTER_SMTP_PORT", "587")
    assert configured_smtp_port() == 587
    monkeypatch.setenv("OPENHUNTER_SMTP_PORT", "0")
    assert configured_smtp_port() == 25
    monkeypatch.setenv("OPENHUNTER_SMTP_PORT", "nope")
    assert configured_smtp_port() == 25


class _LocalSmtp:
    """Accepts on 127.0.0.1 and runs ``talk`` for each connection."""

    def __init__(self, talk: Callable[[socket.socket, threading.Event], None]) -> None:
        self._talk = talk
        self.release = threading.Event()
        self.ready = threading.Event()
        self.port = 0
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self) -> _LocalSmtp:
        self._thread.start()
        assert self.ready.wait(2)
        return self

    def __exit__(self, *args: object) -> None:
        self.release.set()
        self._thread.join(2)

    def _run(self) -> None:
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(4)
        server.settimeout(0.2)
        self.port = server.getsockname()[1]
        self.ready.set()
        try:
            while not self.release.is_set():
                try:
                    conn, _addr = server.accept()
                except socket.timeout:
                    continue
                try:
                    self._talk(conn, self.release)
                finally:
                    conn.close()
        finally:
            server.close()


def _hold(conn: socket.socket, release: threading.Event) -> None:
    del conn
    release.wait(3)


def _banner_then_hold(conn: socket.socket, release: threading.Event) -> None:
    conn.sendall(b"220 test.example ESMTP\r\n")
    release.wait(3)


def _false_banner(conn: socket.socket, release: threading.Event) -> None:
    conn.sendall(b"250 not a greeting\r\n")
    release.wait(3)


def test_live_greeting_timeout_is_smtp_unreachable_and_not_valid() -> None:
    with _LocalSmtp(_hold) as server:
        started = time.monotonic()
        result = verify_email(
            "ada@anthropic.com",
            resolver=FixedMx(MxLookup(hosts=("127.0.0.1",))),
            prober=LiveSmtpProber(timeout=0.3, host_checker=lambda host: True),
            host_checker=lambda host: True,
            timeout=0.3,
            smtp_port=server.port,
        )
        elapsed = time.monotonic() - started
    assert elapsed < 1.2
    assert result.status == "unknown"
    assert result.reason == "smtp_unreachable"
    assert result.mx_valid is True
    assert result.smtp_code is None
    assert result.status != "valid"
    assert "greeting" in " ".join(result.notes).lower()


def test_live_timeout_after_a_greeting_is_not_the_greeting_failure() -> None:
    with _LocalSmtp(_banner_then_hold) as server:
        prober = LiveSmtpProber(timeout=0.3, host_checker=lambda host: True)
        started = time.monotonic()
        reply = prober.probe_mailbox(["127.0.0.1"], "ada@example.com", timeout=0.3, port=server.port)
        elapsed = time.monotonic() - started
    assert elapsed < 1.2
    assert reply.code is None
    assert reply.error == "timeout"


def test_live_non_greeting_banner_is_not_an_rcpt_success() -> None:
    with _LocalSmtp(_false_banner) as server:
        prober = LiveSmtpProber(timeout=0.4, host_checker=lambda host: True)
        reply = prober.probe_mailbox(["127.0.0.1"], "ada@example.com", timeout=0.4, port=server.port)
    assert reply.error == "protocol"
    assert reply.code == 250
    result = verify_email(
        "ada@example.com",
        resolver=FixedMx(MxLookup(hosts=("127.0.0.1",))),
        prober=_StaticProber(reply),
        host_checker=lambda host: True,
    )
    assert result.status == "unknown"
    assert result.status != "valid"


class _StaticProber:
    def __init__(self, reply: SmtpReply) -> None:
        self.reply = reply

    def probe_mailbox(
        self,
        mx_hosts: list[str],
        recipient: str,
        *,
        timeout: float,
        port: int = 25,
    ) -> SmtpReply:
        del mx_hosts, recipient, timeout, port
        return self.reply
