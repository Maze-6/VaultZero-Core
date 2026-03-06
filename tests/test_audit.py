"""
test_audit.py
Author: Mourya Reddy Udumula
Unit tests for ops/audit_ledger.py — VaultZero forensic audit ledger.

Covers:
  1. DBHandler can be instantiated with an in-memory SQLite database.
  2. log_event() inserts a row with correct fields into the events table.
  3. get_events() returns events newest-first.
  4. DB_PATH is an absolute path anchored to the project root (not relative).
  5. add_file / get_files round-trip.
"""

import sys
import os

import pytest

ROOT    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPS_DIR = os.path.join(ROOT, 'ops')
sys.path.insert(0, ROOT)
sys.path.insert(0, OPS_DIR)

from audit_ledger import DBHandler, DB_PATH


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def db():
    """In-memory DBHandler for fast, isolated tests."""
    handler = DBHandler(db_path=":memory:")
    yield handler
    handler.close()


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

class TestDBHandlerInit:
    def test_instantiates_with_in_memory_db(self):
        """DBHandler(db_path=':memory:') succeeds without touching the filesystem."""
        handler = DBHandler(db_path=":memory:")
        assert handler.conn is not None
        handler.close()

    def test_db_path_is_absolute(self):
        """DB_PATH is an absolute path (not a bare filename like 'registry.db')."""
        import pathlib
        assert DB_PATH.is_absolute(), (
            f"DB_PATH should be absolute, got: {DB_PATH}"
        )

    def test_db_path_anchored_to_project_root(self):
        """DB_PATH resolves to <project_root>/data/audit.db."""
        import pathlib
        project_root = pathlib.Path(ROOT)
        expected     = project_root / 'data' / 'audit.db'
        assert DB_PATH == expected, (
            f"Expected DB_PATH={expected}, got {DB_PATH}"
        )


class TestLogEvent:
    def test_log_event_inserts_row(self, db):
        """log_event() inserts exactly one row into the events table."""
        db.log_event(action='test_action', filename='test_file.txt', user='pytest')
        events = db.get_events()
        assert len(events) == 1

    def test_log_event_fields_match(self, db):
        """log_event() stores correct action, filename, and user."""
        db.log_event(action='file_encrypt', filename='vault.enc', user='alice')
        events = db.get_events()
        assert events[0]['action']   == 'file_encrypt'
        assert events[0]['filename'] == 'vault.enc'
        assert events[0]['user']     == 'alice'

    def test_log_event_has_dual_timestamp(self, db):
        """log_event() stores non-empty utc_ts and ist_ts."""
        db.log_event(action='node_check', filename='shard_0')
        events = db.get_events()
        assert events[0]['utc_ts'], "utc_ts should not be empty"
        assert events[0]['ist_ts'], "ist_ts should not be empty"

    def test_log_event_default_user_is_system(self, db):
        """log_event() defaults user to 'system' when not specified."""
        db.log_event(action='auto_check', filename='shard_1')
        events = db.get_events()
        assert events[0]['user'] == 'system'

    def test_get_events_newest_first(self, db):
        """get_events() returns rows newest-first (by AUTOINCREMENT id DESC)."""
        db.log_event(action='first',  filename='a.txt')
        db.log_event(action='second', filename='b.txt')
        db.log_event(action='third',  filename='c.txt')
        events = db.get_events()
        assert [e['action'] for e in events] == ['third', 'second', 'first']


class TestFileRegistry:
    def test_add_and_get_files(self, db):
        """add_file() stores a record; get_files() retrieves it."""
        db.add_file("document.pdf")
        files = db.get_files()
        assert "document.pdf" in files

    def test_remove_file(self, db):
        """remove_file() deletes a previously added record."""
        db.add_file("to_delete.txt")
        db.remove_file("to_delete.txt")
        assert "to_delete.txt" not in db.get_files()

    def test_multiple_files(self, db):
        """Multiple files can be added and retrieved."""
        for name in ["alpha.key", "beta.key", "gamma.key"]:
            db.add_file(name)
        files = db.get_files()
        assert len(files) == 3
