"""CLI leads commands and help. Discovery commands are covered without the CLI."""

from __future__ import annotations

import pytest

from openhunter.cli import main


def test_help_exits_cleanly() -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--help"])
    assert caught.value.code == 0


def test_leads_round_trip(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("OPENHUNTER_DB", str(tmp_path / "cli.db"))
    destination = tmp_path / "leads.csv"
    assert (
        main(
            [
                "leads",
                "save",
                "--email",
                "ada@example.com",
                "--name",
                "Ada Lovelace",
                "--domain",
                "example.com",
                "--role",
                "Engineer",
                "--source",
                "https://example.com/team",
            ]
        )
        == 0
    )
    assert main(["leads", "list"]) == 0
    listed = capsys.readouterr().out
    assert "ada@example.com" in listed
    assert main(["leads", "export", str(destination)]) == 0
    assert "ada@example.com" in destination.read_text(encoding="utf-8")


def test_save_requires_a_name_or_email(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENHUNTER_DB", str(tmp_path / "cli.db"))
    with pytest.raises(SystemExit) as caught:
        main(["leads", "save", "--domain", "example.com"])
    assert caught.value.code == 2
