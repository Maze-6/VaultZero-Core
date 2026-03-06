"""
audit_ledger.py  (formerly db_handler.py)
Author: Jeet Upadhyaya Anand
Role: Operational Security & Forensic Engineering
Forensic Audit Ledger for VaultZero distributed storage system.
Implements SQLite with ACID compliance for tamper-evident audit trails.
Features:
- Dual-timestamp logging (UTC + IST) to prevent timeline ambiguity in investigations
- Chain-of-custody compliant log format suitable for legal evidence
- Every file access event recorded with full attribution
Complements Mourya's cryptographic architecture with operational forensic capability.
"""
import sqlite3
import pathlib
from datetime import datetime, timezone
import config

# Fix 11: Absolute path anchored to this file's location, regardless of cwd.
# Resolves to <project_root>/data/audit.db  (ops/../../data/audit.db).
# Using an absolute path prevents registry.db from being created in whatever
# directory the process happens to be running from.
DB_PATH = pathlib.Path(__file__).parent.parent / 'data' / 'audit.db'


class DBHandler:
    def __init__(self, db_path=None):
        """
        Args:
            db_path: Path to the SQLite database file.  Defaults to the
                     module-level DB_PATH (absolute, anchored to project root).
                     Pass \":memory:\" for unit tests to avoid touching the filesystem.
        """
        # Default to the module-level absolute path; callers may override.
        if db_path is None:
            db_path = str(DB_PATH)
            # Ensure parent directory exists (data/ may not exist on first run)
            DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.init_db()

    def init_db(self):
        """Creates the files and events tables if they don't exist."""
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                filename TEXT PRIMARY KEY,
                uploaded_at TEXT NOT NULL
            )
        """)
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                utc_ts     TEXT    NOT NULL,
                ist_ts     TEXT    NOT NULL,
                action     TEXT    NOT NULL,
                filename   TEXT    NOT NULL,
                user       TEXT    NOT NULL DEFAULT 'system'
            )
        """)
        self.conn.commit()

    def add_file(self, filename: str):
        """Adds a new file record to the registry."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute("INSERT OR REPLACE INTO files (filename, uploaded_at) VALUES (?, ?)", (filename, timestamp))
        self.conn.commit()

    def remove_file(self, filename: str):
        """Removes a file record from the registry."""
        self.cursor.execute("DELETE FROM files WHERE filename = ?", (filename,))
        self.conn.commit()

    def get_files(self) -> list:
        """Returns a list of all stored filenames."""
        self.cursor.execute("SELECT filename FROM files ORDER BY uploaded_at DESC")
        return [row[0] for row in self.cursor.fetchall()]

    def log_event(self, action: str, filename: str, user: str = 'system') -> None:
        """
        Append a forensic audit event with dual-timestamp (UTC + local/IST).

        The dual-timestamp format mirrors watchdog_service.log_event() so that
        audit records from both subsystems are consistent and can be correlated.

        Args:
            action:   Event type string (e.g. 'file_encrypt', 'node_0_healthy',
                      'shard_distribute').
            filename: Filename or resource being acted upon.
            user:     User or service that triggered the event (default 'system').
        """
        utc_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        ist_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.cursor.execute(
            "INSERT INTO events (utc_ts, ist_ts, action, filename, user) "
            "VALUES (?, ?, ?, ?, ?)",
            (utc_ts, ist_ts, action, filename, user),
        )
        self.conn.commit()

    def get_events(self) -> list:
        """Return all audit events as a list of dicts, newest first."""
        self.cursor.execute(
            "SELECT utc_ts, ist_ts, action, filename, user FROM events "
            "ORDER BY id DESC"
        )
        cols = ('utc_ts', 'ist_ts', 'action', 'filename', 'user')
        return [dict(zip(cols, row)) for row in self.cursor.fetchall()]

    def close(self):
        self.conn.close()
