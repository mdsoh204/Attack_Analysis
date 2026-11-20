"""Opt-in SQLite persistence for live packet captures.

SQLite is part of Python, so the dashboard can persist captures locally without
requiring a database server, credentials, or a network connection.  It is
intended for one local dashboard process.  Set ``PACKET_DATABASE_PATH`` to
place the database file somewhere else.
"""

import json
import os
import sqlite3
import threading


class PacketStore:
    """Store validated packet records only while persistence is enabled."""

    def __init__(self, database_path: str | None = None):
        default_path = os.path.join(os.path.dirname(__file__), "data", "packet_monitor.sqlite3")
        self.path = os.path.abspath(database_path or os.getenv("PACKET_DATABASE_PATH", default_path))
        self._enabled = False
        self._ready = False
        self._error = ""
        self._lock = threading.RLock()

    def _open(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def connect(self) -> bool:
        """Create and verify the local database and its packet table."""
        with self._lock:
            try:
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                with self._open() as database:
                    database.execute("PRAGMA journal_mode = WAL")
                    database.execute("PRAGMA foreign_keys = ON")
                    database.execute(
                        """
                        CREATE TABLE IF NOT EXISTS captured_packets (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            session_id TEXT NOT NULL,
                            packet_id INTEGER NOT NULL,
                            captured_at REAL NOT NULL,
                            src_ip TEXT,
                            src_port INTEGER,
                            dst_ip TEXT,
                            dst_port INTEGER,
                            protocol TEXT,
                            packet_size INTEGER,
                            is_real INTEGER NOT NULL CHECK (is_real IN (0, 1)),
                            details_json TEXT NOT NULL,
                            UNIQUE(session_id, packet_id)
                        )
                        """
                    )
                    database.execute(
                        "CREATE INDEX IF NOT EXISTS ix_captured_packets_session_time "
                        "ON captured_packets(session_id, captured_at)"
                    )
                    database.execute(
                        "CREATE INDEX IF NOT EXISTS ix_captured_packets_protocol "
                        "ON captured_packets(protocol)"
                    )
                self._ready = True
                self._error = ""
                return True
            except (OSError, sqlite3.Error) as exc:
                self._ready = False
                self._error = str(exc)
                return False

    @property
    def enabled(self) -> bool:
        return self._enabled

    def status(self) -> dict:
        return {
            "engine": "SQLite",
            "enabled": self._enabled,
            "connected": self._ready,
            "path": self.path,
            "error": self._error,
        }

    def set_enabled(self, enabled: bool) -> dict:
        """Turn database writes on or off without affecting live capture or CSV."""
        if enabled and not self.connect():
            self._enabled = False
            return self.status()
        with self._lock:
            self._enabled = enabled
        return self.status()

    def save(self, packet: dict) -> bool:
        """Save one record.  A disabled database deliberately performs no write."""
        if not self._enabled:
            return False
        if not self._ready and not self.connect():
            return False

        try:
            details = json.dumps(packet, ensure_ascii=False, default=str, separators=(",", ":"))
            with self._lock, self._open() as database:
                database.execute(
                    """
                    INSERT INTO captured_packets
                        (session_id, packet_id, captured_at, src_ip, src_port, dst_ip,
                         dst_port, protocol, packet_size, is_real, details_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(session_id, packet_id) DO UPDATE SET
                        captured_at=excluded.captured_at,
                        src_ip=excluded.src_ip,
                        src_port=excluded.src_port,
                        dst_ip=excluded.dst_ip,
                        dst_port=excluded.dst_port,
                        protocol=excluded.protocol,
                        packet_size=excluded.packet_size,
                        is_real=excluded.is_real,
                        details_json=excluded.details_json
                    """,
                    (
                        packet["session_id"], packet["id"], packet["timestamp"],
                        packet.get("src_ip"), packet.get("src_port"), packet.get("dst_ip"),
                        packet.get("dst_port"), packet.get("proto"), packet.get("size"),
                        1 if packet.get("is_real") else 0, details,
                    ),
                )
            self._error = ""
            return True
        except (KeyError, TypeError, ValueError, sqlite3.Error) as exc:
            self._error = str(exc)
            return False

store = PacketStore()
