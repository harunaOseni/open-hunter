"""SQLite cache and the saved lead list.

The cache is a freshness hint, not a source of truth: domain searches live for
seven days and SMTP results for one day because mailboxes and MX records change.
Lead identity is the email plus domain when an email exists, so saving the same
person twice updates the row instead of duplicating it.
"""

from __future__ import annotations

import csv
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from openhunter.errors import InputError

LEAD_COLUMNS = (
    "email",
    "full_name",
    "first_name",
    "last_name",
    "role",
    "company",
    "domain",
    "source_url",
    "confidence",
    "notes",
    "created_at",
)


class Store:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS cache_entries (
                    kind TEXT NOT NULL,
                    cache_key TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    ttl_seconds INTEGER NOT NULL,
                    PRIMARY KEY (kind, cache_key)
                );
                CREATE TABLE IF NOT EXISTS leads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dedupe_key TEXT NOT NULL UNIQUE,
                    email TEXT,
                    full_name TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    role TEXT,
                    company TEXT,
                    domain TEXT,
                    source_url TEXT,
                    confidence REAL,
                    notes TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            connection.commit()

    def get_cache(self, kind: str, key: str, *, now: datetime | None = None) -> dict[str, object] | None:
        moment = now or _now()
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT payload, created_at, ttl_seconds FROM cache_entries WHERE kind = ? AND cache_key = ?",
                (kind, key),
            ).fetchone()
        if row is None:
            return None
        created = datetime.fromisoformat(str(row["created_at"]))
        if moment - created > timedelta(seconds=int(row["ttl_seconds"])):
            return None
        payload = json.loads(str(row["payload"]))
        if isinstance(payload, dict):
            return payload
        return None

    def put_cache(
        self,
        kind: str,
        key: str,
        payload: dict[str, object],
        ttl_seconds: int,
        *,
        now: datetime | None = None,
    ) -> None:
        moment = now or _now()
        encoded = json.dumps(payload, ensure_ascii=False)
        with closing(self._connect()) as connection:
            connection.execute(
                """
                INSERT INTO cache_entries (kind, cache_key, payload, created_at, ttl_seconds)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(kind, cache_key) DO UPDATE SET
                    payload = excluded.payload,
                    created_at = excluded.created_at,
                    ttl_seconds = excluded.ttl_seconds
                """,
                (kind, key, encoded, moment.isoformat(), ttl_seconds),
            )
            connection.commit()

    def save_lead(
        self,
        *,
        email: str | None,
        full_name: str | None,
        first_name: str | None,
        last_name: str | None,
        role: str | None,
        company: str | None,
        domain: str | None,
        source_url: str | None,
        confidence: float | None,
        notes: str | None,
    ) -> dict[str, object]:
        normalized_email = email.strip().lower() if email and email.strip() else None
        normalized_domain = domain.strip().lower() if domain and domain.strip() else None
        name = full_name.strip() if full_name and full_name.strip() else None
        if normalized_email is None and name is None:
            raise InputError("A lead needs an email or a name.")
        dedupe_key = (
            f"email:{normalized_email}|{normalized_domain or ''}"
            if normalized_email
            else f"person:{(name or '').lower()}|{normalized_domain or ''}|{(source_url or '').strip()}"
        )
        moment = _now().isoformat()
        with closing(self._connect()) as connection:
            existing = connection.execute(
                "SELECT id, created_at FROM leads WHERE dedupe_key = ?",
                (dedupe_key,),
            ).fetchone()
            values = (
                normalized_email,
                name,
                first_name,
                last_name,
                role,
                company,
                normalized_domain,
                source_url,
                confidence,
                notes or "",
            )
            if existing is None:
                cursor = connection.execute(
                    """
                    INSERT INTO leads (
                        dedupe_key, email, full_name, first_name, last_name, role, company,
                        domain, source_url, confidence, notes, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (dedupe_key, *values, moment, moment),
                )
                lead_id = int(cursor.lastrowid)
            else:
                lead_id = int(existing["id"])
                connection.execute(
                    """
                    UPDATE leads SET
                        email = ?, full_name = ?, first_name = ?, last_name = ?, role = ?,
                        company = ?, domain = ?, source_url = ?, confidence = ?, notes = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (*values, moment, lead_id),
                )
            connection.commit()
            row = connection.execute("SELECT * FROM leads WHERE id = ?", (lead_id,)).fetchone()
        if row is None:
            raise InputError("The lead could not be saved.")
        return _lead_dict(row)

    def list_leads(self, *, domain: str | None = None, limit: int = 100) -> list[dict[str, object]]:
        bounded = max(1, min(int(limit), 500))
        with closing(self._connect()) as connection:
            if domain:
                rows = connection.execute(
                    """
                    SELECT * FROM leads WHERE domain = ?
                    ORDER BY updated_at DESC, id DESC LIMIT ?
                    """,
                    (domain.strip().lower(), bounded),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM leads ORDER BY updated_at DESC, id DESC LIMIT ?",
                    (bounded,),
                ).fetchall()
        return [_lead_dict(row) for row in rows]

    def export_csv(self, path: Path, *, domain: str | None = None) -> int:
        rows = self.list_leads(domain=domain, limit=500)
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=LEAD_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow({column: row.get(column, "") for column in LEAD_COLUMNS})
        return len(rows)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        return connection


def _lead_dict(row: sqlite3.Row) -> dict[str, object]:
    return {key: row[key] for key in row.keys() if key != "dedupe_key"}


def _now() -> datetime:
    return datetime.now(timezone.utc)
