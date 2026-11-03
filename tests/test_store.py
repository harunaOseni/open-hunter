"""SQLite cache expiry and the saved lead list."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from openhunter.store import Store


def test_cache_expires_and_does_not_return_other_keys(tmp_path) -> None:
    store = Store(tmp_path / "nested" / "openhunter.db")
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store.put_cache("verify", "ada@example.com", {"status": "valid"}, 10, now=start)
    assert store.get_cache("verify", "ada@example.com", now=start)["status"] == "valid"
    assert store.get_cache("verify", "ada@example.com", now=start + timedelta(seconds=11)) is None
    assert store.get_cache("pattern", "ada@example.com", now=start) is None


def test_address_index_keeps_the_first_seen_time(tmp_path) -> None:
    store = Store(tmp_path / "openhunter.db")
    first = datetime(2026, 1, 1, tzinfo=timezone.utc)
    later = datetime(2026, 2, 1, tzinfo=timezone.utc)
    store.upsert_addresses(
        [
            {
                "email": "Ada@Runpod.io",
                "source": "website_text",
                "source_url": "https://news.example/story",
                "name": None,
                "confidence": 0.6,
            }
        ],
        now=first,
    )
    store.upsert_addresses(
        [
            {
                "email": "ada@runpod.io",
                "source": "website_text",
                "source_url": "https://news.example/story",
                "name": "Ada Lovelace",
                "first_name": "Ada",
                "last_name": "Lovelace",
                "confidence": 0.4,
            }
        ],
        now=later,
    )
    rows = store.addresses_for_domain("runpod.io")
    assert len(rows) == 1
    assert rows[0]["first_seen"] == first.isoformat()
    assert rows[0]["last_seen"] == later.isoformat()
    assert rows[0]["name"] == "Ada Lovelace"
    assert rows[0]["confidence"] == 0.6
    assert store.addresses_for_domain("other.example") == []


def test_lead_upsert_list_filter_and_csv(tmp_path) -> None:
    store = Store(tmp_path / "openhunter.db")
    hostile = "Ada'; DROP TABLE leads;--"
    saved = store.save_lead(
        email="Ada@Example.com",
        full_name=hostile,
        first_name="Ada",
        last_name="Lovelace",
        role=None,
        company="Example",
        domain="example.com",
        source_url="https://example.com/team",
        confidence=0.8,
        notes="first",
    )
    updated = store.save_lead(
        email="ada@example.com",
        full_name=hostile,
        first_name="Ada",
        last_name="Lovelace",
        role="Engineer",
        company="Example",
        domain="example.com",
        source_url="https://example.com/team",
        confidence=0.9,
        notes="updated",
    )
    assert updated["id"] == saved["id"]
    assert updated["role"] == "Engineer"
    assert updated["email"] == "ada@example.com"
    store.save_lead(
        email="grace@other.com",
        full_name="Grace Hopper",
        first_name="Grace",
        last_name="Hopper",
        role="Admiral",
        company="Other",
        domain="other.com",
        source_url="https://other.com",
        confidence=0.5,
        notes="",
    )
    listed = store.list_leads(domain="example.com")
    assert [row["email"] for row in listed] == ["ada@example.com"]
    assert listed[0]["full_name"] == hostile
    destination = tmp_path / "out" / "leads.csv"
    count = store.export_csv(destination, domain="example.com")
    assert count == 1
    text = destination.read_text(encoding="utf-8")
    assert "ada@example.com" in text
    assert "Engineer" in text
    assert hostile in text
    empty = tmp_path / "empty.csv"
    assert store.export_csv(empty, domain="missing.example") == 0
    assert empty.read_text(encoding="utf-8").splitlines()[0].startswith("email,")
