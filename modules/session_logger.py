"""
session_logger.py - Persistent event logging across sessions.

Writes three parallel outputs every time an event is recorded:

  logs/YYYY-MM-DD.log       Rolling human-readable text log (all events,
                             appended continuously — survives crashes)

  logs/YYYY-MM-DD_conn.log  Connections-only log for network history review.
                             One line per CONN_NEW event with full detail.

  data/events.db            SQLite database of every event from every session.
                             Never truncated — queryable with --history mode.

All writes are thread-safe.
"""

import csv
import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .events import EventType, SecurityEvent, Severity

logger = logging.getLogger(__name__)

# Human-readable severity prefix for text logs
_SEV_PREFIX = {
    Severity.CRITICAL: "[CRITICAL]",
    Severity.HIGH:     "[HIGH    ]",
    Severity.MEDIUM:   "[MEDIUM  ]",
    Severity.LOW:      "[LOW     ]",
    Severity.INFO:     "[INFO    ]",
}

_CONN_TYPES = {EventType.CONN_NEW, EventType.CONN_LISTEN}

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT    NOT NULL,
    timestamp   TEXT    NOT NULL,
    event_type  TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    source      TEXT    NOT NULL,
    description TEXT    NOT NULL,
    remediated  INTEGER NOT NULL DEFAULT 0,
    details     TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_severity   ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_session    ON events(session_id);
"""


class SessionLogger:
    def __init__(self, logs_dir: Path, data_dir: Path, session_id: str):
        """
        logs_dir   : directory for text / CSV logs  (logs/)
        data_dir   : directory for SQLite DB         (data/)
        session_id : unique string identifying this run (ISO timestamp)
        """
        self._logs_dir  = logs_dir
        self._data_dir  = data_dir
        self._session   = session_id
        self._lock      = threading.Lock()
        self._date_str  = datetime.now().strftime("%Y-%m-%d")

        logs_dir.mkdir(parents=True, exist_ok=True)
        data_dir.mkdir(parents=True, exist_ok=True)

        self._log_path  = logs_dir / f"{self._date_str}.log"
        self._conn_path = logs_dir / f"{self._date_str}_connections.log"
        self._db_path   = data_dir / "events.db"

        self._db: Optional[sqlite3.Connection] = None
        self._open_db()
        self._write_session_header()

    # ------------------------------------------------------------------
    # Public API

    def record(self, event: SecurityEvent):
        """Thread-safe. Write event to all outputs."""
        with self._lock:
            self._write_text(event)
            if event.event_type in _CONN_TYPES:
                self._write_conn(event)
            self._write_db(event)

    def write_csv_export(self, events: List[SecurityEvent]) -> Path:
        """
        Write a CSV of all events from this session.
        Returns the path written.
        """
        path = self._logs_dir / f"session_{self._session}.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "severity", "event_type", "source",
                "description", "remediated",
                "remote_ip", "remote_port", "process", "hostname",
            ])
            for ev in events:
                d = ev.details
                writer.writerow([
                    ev.timestamp.isoformat(),
                    ev.severity.value,
                    ev.event_type.value,
                    ev.source,
                    ev.description,
                    "yes" if ev.remediated else "",
                    d.get("remote_ip", ""),
                    d.get("remote_port", ""),
                    d.get("process", ""),
                    d.get("hostname", ""),
                ])
        logger.info("CSV export written: %s", path)
        return path

    def close(self):
        with self._lock:
            self._write_session_footer()
            if self._db:
                self._db.close()
                self._db = None

    # ------------------------------------------------------------------
    # History query (used by --history mode)

    def query_recent(self, limit: int = 500,
                     severity: Optional[str] = None,
                     event_type: Optional[str] = None) -> List[dict]:
        """Return recent events from the DB as dicts, newest first."""
        if not self._db:
            return []
        clauses = []
        params: list = []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        try:
            cur = self._db.execute(sql, params)
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]
        except Exception as exc:
            logger.warning("DB query failed: %s", exc)
            return []

    def query_connections(self, limit: int = 1000) -> List[dict]:
        """Return all connection events from the DB, newest first."""
        return self.query_recent(
            limit=limit,
            event_type=EventType.CONN_NEW.value,
        )

    # ------------------------------------------------------------------
    # Internal

    def _open_db(self):
        try:
            self._db = sqlite3.connect(str(self._db_path), check_same_thread=False)
            self._db.executescript(_CREATE_TABLE)
            self._db.commit()
        except Exception as exc:
            logger.error("Could not open event DB: %s", exc)
            self._db = None

    def _write_session_header(self):
        sep = "=" * 72
        line = (
            f"\n{sep}\n"
            f"  SESSION START  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  "
            f"(id: {self._session})\n"
            f"{sep}\n"
        )
        self._append(self._log_path, line)
        self._append(self._conn_path,
                     f"\n{sep}\n  SESSION START  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{sep}\n"
                     "TIMESTAMP            SEVERITY  PROCESS              REMOTE IP        HOST                          PORT  PROTO\n"
                     + "-" * 100 + "\n")

    def _write_session_footer(self):
        line = f"  SESSION END    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        self._append(self._log_path, line)
        self._append(self._conn_path, line)

    def _write_text(self, event: SecurityEvent):
        prefix = _SEV_PREFIX.get(event.severity, "[      ]")
        fixed  = " [REMEDIATED]" if event.remediated else ""
        line   = (
            f"{event.timestamp.strftime('%H:%M:%S')}  "
            f"{prefix}  "
            f"{event.event_type.value:<16}  "
            f"{event.source:<20}  "
            f"{event.description}{fixed}\n"
        )
        self._append(self._log_path, line)

    def _write_conn(self, event: SecurityEvent):
        d = event.details
        prefix = _SEV_PREFIX.get(event.severity, "[      ]")
        line = (
            f"{event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}  "
            f"{prefix}  "
            f"{d.get('process', event.source):<20}  "
            f"{d.get('remote_ip', ''):<16}  "
            f"{d.get('hostname', ''):<28}  "
            f"{str(d.get('remote_port', '')):<6}  "
            f"{d.get('proto', '')}\n"
        )
        self._append(self._conn_path, line)

    def _write_db(self, event: SecurityEvent):
        if not self._db:
            return
        import json
        try:
            self._db.execute(
                "INSERT INTO events "
                "(session_id, timestamp, event_type, severity, source, "
                " description, remediated, details) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    self._session,
                    event.timestamp.isoformat(),
                    event.event_type.value,
                    event.severity.value,
                    event.source,
                    event.description,
                    1 if event.remediated else 0,
                    json.dumps(event.details),
                ),
            )
            self._db.commit()
        except Exception as exc:
            logger.warning("DB write failed: %s", exc)

    @staticmethod
    def _append(path: Path, text: str):
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(text)
        except Exception as exc:
            logger.warning("Log write failed (%s): %s", path, exc)
