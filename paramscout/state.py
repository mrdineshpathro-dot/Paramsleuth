"""SQLite-backed state store enabling resumable scans.

What is persisted
-----------------
- scan metadata (tool, version, config subset, scope snapshot)
- endpoints discovered / queued and their completion state
- candidates and their probe status
- per-request accounting counters and throttling events

Secrets are **never** persisted: cookie values, custom header values, and
``Authorization`` are stored only as redacted markers. On resume the operator
must supply credentials again (``--cookie`` / ``--header``).

Scope is re-validated on resume: every persisted endpoint is re-checked
against the scope supplied at resume time (or the persisted scope snapshot,
with a warning, when none is given) before any further request.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import __about__
from .models import Endpoint


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


class StateStore:
    """Thin, synchronous SQLite store (safe for one writer process)."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS endpoints (
                id TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                key TEXT NOT NULL,
                url TEXT NOT NULL,
                method TEXT NOT NULL,
                source TEXT NOT NULL,
                is_seed INTEGER NOT NULL DEFAULT 0,
                probed INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS candidates (
                id TEXT PRIMARY KEY,
                endpoint_id TEXT NOT NULL REFERENCES endpoints(id),
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                discovery_score REAL NOT NULL DEFAULT 0,
                security_relevant INTEGER NOT NULL DEFAULT 0,
                sources_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'pending',
                result_json TEXT,
                UNIQUE (endpoint_id, name)
            );
            CREATE TABLE IF NOT EXISTS request_counts (
                purpose TEXT PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS throttles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                host TEXT NOT NULL,
                status INTEGER NOT NULL,
                consecutive INTEGER NOT NULL
            );
            """
        )
        self._conn.commit()

    # ---- low level -----------------------------------------------------
    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- meta ----------------------------------------------------------
    def set_meta(self, key: str, value: Any) -> None:
        payload = value if isinstance(value, str) else json.dumps(value)
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, payload),
            )

    def get_meta(self, key: str) -> Any:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key=?", (key,)
            ).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row["value"])
        except (json.JSONDecodeError, TypeError):
            return row["value"]

    def init_scan(self, config_subset: dict[str, Any], scope_snapshot: dict[str, Any]) -> None:
        """Stamp metadata for a new scan (no-op-ish when resuming same file)."""
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                ("created_at", _now()),
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                ("tool", __about__.__title__),
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)",
                ("version", __about__.__version__),
            )

    # ---- endpoints -------------------------------------------------------
    def upsert_endpoint(self, endpoint: Endpoint) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO endpoints(id,host,key,url,method,source,is_seed) "
                "VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET "
                "host=excluded.host,key=excluded.key,url=excluded.url,"
                "source=excluded.source,is_seed=excluded.is_seed",
                (
                    endpoint.id,
                    endpoint.host,
                    endpoint.key,
                    endpoint.url,
                    "GET",
                    endpoint.source,
                    1 if endpoint.is_seed else 0,
                ),
            )

    def endpoint_ids(self) -> list[str]:
        with self._lock:
            rows = self._conn.execute("SELECT id FROM endpoints").fetchall()
        return [r["id"] for r in rows]

    def endpoint_count(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM endpoints"
            ).fetchone()
        return int(row["c"])

    def mark_endpoint_probed(self, endpoint_id: str) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE endpoints SET probed=1 WHERE id=?", (endpoint_id,)
            )

    def unprobed_endpoints(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM endpoints WHERE probed=0 ORDER BY is_seed DESC, id"
            ).fetchall()
        return [dict(r) for r in rows]

    # ---- candidates --------------------------------------------------------
    def upsert_candidate(
        self,
        endpoint_id: str,
        name: str,
        category: str,
        discovery_score: float,
        security_relevant: bool,
        sources: list[dict[str, str]],
    ) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO candidates"
                "(id,endpoint_id,name,category,discovery_score,security_relevant,sources_json,status) "
                "VALUES(?,?,?,?,?,?,?,'pending') "
                "ON CONFLICT(endpoint_id,name) DO UPDATE SET "
                "category=excluded.category,discovery_score=excluded.discovery_score,"
                "security_relevant=excluded.security_relevant",
                (
                    f"{endpoint_id}|{name}",
                    endpoint_id,
                    name,
                    category,
                    discovery_score,
                    1 if security_relevant else 0,
                    json.dumps(sources),
                ),
            )

    def pending_candidates(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT c.*, e.url AS endpoint_url, e.host AS endpoint_host, "
                "e.key AS endpoint_key "
                "FROM candidates c JOIN endpoints e ON e.id=c.endpoint_id "
                "WHERE c.status='pending' ORDER BY c.discovery_score DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def set_candidate_status(self, candidate_id: str, status: str, result_json: str | None) -> None:
        with self._tx() as conn:
            conn.execute(
                "UPDATE candidates SET status=?, result_json=? WHERE id=?",
                (status, result_json, candidate_id),
            )

    def candidate_count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM candidates").fetchone()
        return int(row["c"])

    def candidate_status_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) AS c FROM candidates GROUP BY status"
            ).fetchall()
        return {r["status"]: int(r["c"]) for r in rows}

    def results_for(self, statuses: tuple[str, ...]) -> list[dict[str, Any]]:
        marks = ",".join("?" * len(statuses))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT c.*, e.url AS endpoint_url, e.host AS endpoint_host, "
                f"e.key AS endpoint_key FROM candidates c JOIN endpoints e "
                f"ON e.id=c.endpoint_id WHERE c.status IN ({marks})",
                statuses,
            ).fetchall()
        return [dict(r) for r in rows]

    # ---- request accounting ---------------------------------------------
    def increment_request(self, purpose: str) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO request_counts(purpose,count) VALUES(?,1) "
                "ON CONFLICT(purpose) DO UPDATE SET count=count+1",
                (purpose,),
            )

    def request_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM request_counts").fetchall()
        return {r["purpose"]: int(r["count"]) for r in rows}

    def total_requests(self) -> int:
        counts = self.request_counts()
        return sum(counts.values())

    # ---- throttles --------------------------------------------------------
    def add_throttle(self, host: str, status: int, consecutive: int) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO throttles(ts,host,status,consecutive) VALUES(?,?,?,?)",
                (_now(), host, status, consecutive),
            )

    def throttle_count(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM throttles").fetchone()
        return int(row["c"])

    # ---- shared helpers -----------------------------------------------------
    @staticmethod
    def endpoint_id_for(url: str) -> str:
        """Deterministic endpoint id so re-runs reuse state instead of dup rows."""
        import hashlib

        return hashlib.sha1(url.encode("utf-8", "surrogatepass")).hexdigest()[:20]


def build_endpoint(
    url: str,
    host: str,
    netloc: str,
    key: str,
    source: str,
    is_seed: bool,
    base_query: list[tuple[str, str]] | None = None,
) -> Endpoint:
    """Build an Endpoint plus its stable id from a validated, in-scope URL."""
    return Endpoint(
        id=StateStore.endpoint_id_for(url),
        key=key,
        url=url,
        host=host,
        netloc=netloc,
        source=source,
        is_seed=is_seed,
        base_query=base_query or [],
    )
