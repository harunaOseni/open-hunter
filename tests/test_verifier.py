"""Verification decisions with fake DNS and SMTP, plus one live local dialogue.

The live dialogue binds 127.0.0.1 only to prove the probe speaks SMTP and
stops before DATA. It does not contact a third-party mail server.
"""

from __future__ import annotations

import socket
import threading

import pytest

from openhunter.smtp_probe import LiveSmtpProber
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

    def probe_mailbox(self, mx_hosts: list[str], recipient: str, *, timeout: float) -> SmtpReply:
        del mx_hosts, timeout
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
