from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Any, Iterator

from .config import DB_PATH

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None


def _connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA foreign_keys=ON")
        _conn.execute("PRAGMA busy_timeout=5000")
    return _conn


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    with _lock:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
              id TEXT PRIMARY KEY,
              source TEXT NOT NULL,
              type TEXT NOT NULL,
              ts REAL NOT NULL,
              severity_hint TEXT,
              fields TEXT NOT NULL,
              created_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);

            CREATE TABLE IF NOT EXISTS alerts (
              id TEXT PRIMARY KEY,
              event_id TEXT,
              rule_id TEXT,
              title TEXT NOT NULL,
              category TEXT,
              severity TEXT NOT NULL,
              status TEXT NOT NULL,
              recommended_action TEXT,
              rationale TEXT,
              payload TEXT,
              created_at REAL NOT NULL,
              updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

            CREATE TABLE IF NOT EXISTS drafts (
              id TEXT PRIMARY KEY,
              alert_id TEXT,
              name TEXT NOT NULL,
              yaml_text TEXT NOT NULL,
              status TEXT NOT NULL,
              origin TEXT NOT NULL,
              created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS surface (
              id TEXT PRIMARY KEY,
              kind TEXT NOT NULL,
              key TEXT NOT NULL UNIQUE,
              title TEXT NOT NULL,
              detail TEXT,
              risk TEXT NOT NULL,
              status TEXT NOT NULL,
              first_seen REAL NOT NULL,
              last_seen REAL NOT NULL,
              extra TEXT
            );

            CREATE TABLE IF NOT EXISTS audit (
              id TEXT PRIMARY KEY,
              ts REAL NOT NULL,
              kind TEXT NOT NULL,
              summary TEXT NOT NULL,
              detail TEXT
            );

            CREATE TABLE IF NOT EXISTS blocks (
              id TEXT PRIMARY KEY,
              kind TEXT NOT NULL,
              value TEXT NOT NULL,
              reason TEXT,
              expires_at REAL,
              created_at REAL NOT NULL,
              active INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pending_actions (
              id TEXT PRIMARY KEY,
              kind TEXT NOT NULL,
              alert_id TEXT,
              payload TEXT NOT NULL,
              status TEXT NOT NULL,
              created_at REAL NOT NULL
            );
            """
        )


def new_id() -> str:
    return uuid.uuid4().hex[:16]


def now() -> float:
    return time.time()


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {k: row[k] for k in row.keys()}


def add_audit(kind: str, summary: str, detail: dict[str, Any] | None = None) -> str:
    aid = new_id()
    with db() as conn:
        conn.execute(
            "INSERT INTO audit(id, ts, kind, summary, detail) VALUES (?,?,?,?,?)",
            (aid, now(), kind, summary, json.dumps(detail or {}, ensure_ascii=False)),
        )
    return aid
