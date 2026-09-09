"""SQLite-backed scan state for resumable runs.

The state file stores scope, settings, endpoint progress, candidates, findings
and aggregate statistics.  It deliberately does **not** store cookies or
``Authorization`` headers: :meth:`ScanConfig.to_dict` strips them before they
reach the database, and there is no flag to change that.  Resuming an
authenticated scan therefore requires re-supplying ``--cookie`` / ``--header``.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from paramscout.config import ScanConfig
from paramscout.models import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS endpoints (
    endpoint   TEXT PRIMARY KEY,
    url        TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'pending',
    candidates INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS candidates (
    endpoint TEXT NOT NULL,
    name     TEXT NOT NULL,
    sources  TEXT NOT NULL DEFAULT '[]',
    evidence TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (endpoint, name)
);
CREATE TABLE IF NOT EXISTS findings (
    endpoint  TEXT NOT NULL,
    parameter TEXT NOT NULL,
    payload   TEXT NOT NULL,
    PRIMARY KEY (endpoint, parameter)
);
CREATE TABLE IF NOT EXISTS stats (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class StateStore:
    """A thin, dependency-free wrapper around one SQLite file."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        directory = Path(self.path).parent
        if str(directory) and not directory.exists():
            directory.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    # -- meta -------------------------------------------------------------

    def set_meta(self, key: str, value: Any) -> None:
        self.connection.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value)),
        )
        self.connection.commit()

    def get_meta(self, key: str, default: Any = None) -> Any:
        row = self.connection.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except json.JSONDecodeError:
            return default

    def save_config(self, config: ScanConfig) -> None:
        """Persist settings with all credentials removed."""

        self.set_meta("config", config.to_dict(include_secrets=False))
        self.set_meta("saved_at", _now())

    def load_config(self) -> dict[str, Any]:
        return self.get_meta("config", {}) or {}

    # -- endpoints ----------------------------------------------------------

    def upsert_endpoint(self, endpoint: str, url: str, *, status: str = "pending", candidates: int = 0) -> None:
        self.connection.execute(
            "INSERT INTO endpoints(endpoint, url, status, candidates, updated_at) VALUES(?, ?, ?, ?, ?) "
            "ON CONFLICT(endpoint) DO UPDATE SET url = excluded.url, "
            "candidates = excluded.candidates, updated_at = excluded.updated_at",
            (endpoint, url, status, candidates, _now()),
        )
        self.connection.commit()

    def mark_endpoint(self, endpoint: str, status: str) -> None:
        self.connection.execute(
            "UPDATE endpoints SET status = ?, updated_at = ? WHERE endpoint = ?",
            (status, _now(), endpoint),
        )
        self.connection.commit()

    def endpoints_by_status(self, status: str | None = None) -> list[dict[str, Any]]:
        if status is None:
            rows = self.connection.execute("SELECT * FROM endpoints ORDER BY rowid").fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM endpoints WHERE status = ? ORDER BY rowid", (status,)
            ).fetchall()
        return [dict(row) for row in rows]

    def pending_endpoints(self) -> list[dict[str, Any]]:
        """Endpoints that still need work: never started, or started and cut short."""

        rows = self.connection.execute(
            "SELECT * FROM endpoints WHERE status IN ('pending', 'prepared') ORDER BY rowid"
        ).fetchall()
        return [dict(row) for row in rows]

    # -- candidates ---------------------------------------------------------

    def save_candidates(self, endpoint: str, candidates: list[Any]) -> None:
        for candidate in candidates:
            self.connection.execute(
                "INSERT INTO candidates(endpoint, name, sources, evidence) VALUES(?, ?, ?, ?) "
                "ON CONFLICT(endpoint, name) DO UPDATE SET sources = excluded.sources, "
                "evidence = excluded.evidence",
                (
                    endpoint,
                    candidate.name,
                    json.dumps([kind.value for kind in candidate.sources]),
                    json.dumps([item.to_dict() for item in candidate.evidence]),
                ),
            )
        self.connection.commit()

    def load_candidates(self) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT * FROM candidates ORDER BY rowid").fetchall()
        return [dict(row) for row in rows]

    # -- findings ------------------------------------------------------------

    def save_finding(self, finding: Finding) -> None:
        self.connection.execute(
            "INSERT INTO findings(endpoint, parameter, payload) VALUES(?, ?, ?) "
            "ON CONFLICT(endpoint, parameter) DO UPDATE SET payload = excluded.payload",
            (finding.endpoint, finding.parameter, json.dumps(finding.to_dict())),
        )
        self.connection.commit()

    def load_findings(self) -> list[dict[str, Any]]:
        rows = self.connection.execute("SELECT payload FROM findings ORDER BY rowid").fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            try:
                out.append(json.loads(row["payload"]))
            except json.JSONDecodeError:
                continue
        return out

    def delete_findings(self) -> None:
        self.connection.execute("DELETE FROM findings")
        self.connection.commit()

    # -- stats -----------------------------------------------------------------

    def save_stats(self, stats: dict[str, Any]) -> None:
        self.set_meta("stats", stats)

    def load_stats(self) -> dict[str, Any]:
        return self.get_meta("stats", {}) or {}

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for table in ("endpoints", "candidates", "findings"):
            row = self.connection.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
            out[table] = int(row["n"])
        return out

    def close(self) -> None:
        self.connection.commit()
        self.connection.close()

    def __enter__(self) -> StateStore:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
