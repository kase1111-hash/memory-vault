"""
Tests for deadman.py - Dead-man switch functionality.

Tests initialization, heir management, and trigger detection
using a temporary database.
"""
import os
import sys
import sqlite3
import json
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import deadman


@pytest.fixture
def dms_db(tmp_path, monkeypatch):
    """Create a temporary database for dead-man switch tests."""
    db_path = str(tmp_path / "test_vault.db")
    monkeypatch.setattr(deadman, "DB_PATH", db_path)

    # Initialize the tables
    deadman.init_deadman_switch()
    return db_path


class TestInitDeadmanSwitch:
    """Test DMS table initialization."""

    def test_creates_tables(self, dms_db):
        conn = sqlite3.connect(dms_db)
        c = conn.cursor()

        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in c.fetchall()}

        assert "deadman_switch" in tables
        assert "dms_heirs" in tables
        conn.close()

    def test_initializes_switch_row(self, dms_db):
        conn = sqlite3.connect(dms_db)
        c = conn.cursor()
        c.execute("SELECT id, armed FROM deadman_switch WHERE id = 1")
        row = c.fetchone()
        assert row is not None
        assert row[0] == 1
        assert row[1] == 0  # Not armed
        conn.close()

    def test_idempotent(self, dms_db):
        # Call again - should not raise
        deadman.init_deadman_switch()
        conn = sqlite3.connect(dms_db)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM deadman_switch")
        assert c.fetchone()[0] == 1  # Still just one row
        conn.close()


class TestListHeirs:
    """Test heir listing."""

    def test_empty_heirs(self, dms_db):
        heirs = deadman.list_heirs()
        assert heirs == []

    def test_with_heirs(self, dms_db):
        conn = sqlite3.connect(dms_db)
        c = conn.cursor()
        c.execute(
            "INSERT INTO dms_heirs (name, public_key_b64) VALUES (?, ?)",
            ("Alice", "AAAA"),
        )
        c.execute(
            "INSERT INTO dms_heirs (name, public_key_b64) VALUES (?, ?)",
            ("Bob", "BBBB"),
        )
        conn.commit()
        conn.close()

        heirs = deadman.list_heirs()
        assert len(heirs) == 2
        names = {h["name"] for h in heirs}
        assert names == {"Alice", "Bob"}


class TestIsDeadmanTriggered:
    """Test trigger detection."""

    def test_not_armed(self, dms_db):
        assert deadman.is_deadman_triggered() is False

    def test_armed_not_expired(self, dms_db):
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat() + "Z"
        conn = sqlite3.connect(dms_db)
        c = conn.cursor()
        c.execute(
            "UPDATE deadman_switch SET armed = 1, deadline = ? WHERE id = 1",
            (future,),
        )
        conn.commit()
        conn.close()

        assert deadman.is_deadman_triggered() is False

    def test_armed_and_expired(self, dms_db):
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat() + "Z"
        conn = sqlite3.connect(dms_db)
        c = conn.cursor()
        c.execute(
            "UPDATE deadman_switch SET armed = 1, deadline = ? WHERE id = 1",
            (past,),
        )
        conn.commit()
        conn.close()

        assert deadman.is_deadman_triggered() is True

    def test_armed_no_deadline(self, dms_db):
        conn = sqlite3.connect(dms_db)
        c = conn.cursor()
        c.execute("UPDATE deadman_switch SET armed = 1 WHERE id = 1")
        conn.commit()
        conn.close()

        assert deadman.is_deadman_triggered() is False


class TestGetPayloadMemoryIds:
    """Test payload memory ID retrieval."""

    def test_no_payload(self, dms_db):
        ids = deadman.get_payload_memory_ids()
        assert ids == []

    def test_with_payload(self, dms_db):
        memory_ids = ["mem-001", "mem-002", "mem-003"]
        conn = sqlite3.connect(dms_db)
        c = conn.cursor()
        c.execute(
            "UPDATE deadman_switch SET payload_memory_ids = ? WHERE id = 1",
            (json.dumps(memory_ids),),
        )
        conn.commit()
        conn.close()

        result = deadman.get_payload_memory_ids()
        assert result == memory_ids


class TestGetHeirReleasePackages:
    """Test release package retrieval."""

    def test_no_packages(self, dms_db):
        packages = deadman.get_heir_release_packages()
        assert packages == []

    def test_with_packages(self, dms_db):
        conn = sqlite3.connect(dms_db)
        c = conn.cursor()
        c.execute(
            """INSERT INTO dms_heirs (name, public_key_b64, encrypted_payload, memory_ids)
               VALUES (?, ?, ?, ?)""",
            ("Alice", "AAAA", b"encrypted_blob", json.dumps(["mem-001"])),
        )
        conn.commit()
        conn.close()

        packages = deadman.get_heir_release_packages()
        assert len(packages) == 1
        assert packages[0]["heir"] == "Alice"
        assert packages[0]["memory_ids"] == ["mem-001"]
        assert "encrypted_payload_b64" in packages[0]

    def test_skips_heirs_without_payload(self, dms_db):
        conn = sqlite3.connect(dms_db)
        c = conn.cursor()
        c.execute(
            "INSERT INTO dms_heirs (name, public_key_b64) VALUES (?, ?)",
            ("NoPayload", "CCCC"),
        )
        c.execute(
            """INSERT INTO dms_heirs (name, public_key_b64, encrypted_payload, memory_ids)
               VALUES (?, ?, ?, ?)""",
            ("HasPayload", "DDDD", b"data", json.dumps(["m1"])),
        )
        conn.commit()
        conn.close()

        packages = deadman.get_heir_release_packages()
        assert len(packages) == 1
        assert packages[0]["heir"] == "HasPayload"
