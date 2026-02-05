"""
Tests for intentlog.py - Intent linking between memories and intents.

Uses a temporary database with the memories table schema.
"""
import os
import sys
import sqlite3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import intentlog


@pytest.fixture
def intent_db(tmp_path, monkeypatch):
    """Create a temporary database with memories table for intent tests."""
    db_path = str(tmp_path / "test_vault.db")
    monkeypatch.setattr(intentlog, "DB_PATH", db_path)

    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE memories (
            memory_id TEXT PRIMARY KEY,
            classification INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT '2025-01-01T00:00:00Z',
            value_metadata TEXT,
            intent_ref TEXT,
            tombstoned INTEGER DEFAULT 0
        )
    """)
    # Insert test memories
    c.execute("""
        INSERT INTO memories (memory_id, classification, created_at)
        VALUES ('mem-001', 1, '2025-01-15T10:00:00Z')
    """)
    c.execute("""
        INSERT INTO memories (memory_id, classification, created_at)
        VALUES ('mem-002', 2, '2025-01-16T10:00:00Z')
    """)
    conn.commit()
    conn.close()
    return db_path


class TestLinkIntent:
    """Test linking intents to memories."""

    def test_link_new_intent(self, intent_db):
        result = intentlog.link_intent("mem-001", "intent-abc")
        assert result is True

        # Verify it was stored
        refs = intentlog.get_intents_for_memory("mem-001")
        assert "intent-abc" in refs

    def test_link_multiple_intents(self, intent_db):
        intentlog.link_intent("mem-001", "intent-1")
        intentlog.link_intent("mem-001", "intent-2")

        refs = intentlog.get_intents_for_memory("mem-001")
        assert "intent-1" in refs
        assert "intent-2" in refs

    def test_link_duplicate_ignored(self, intent_db):
        intentlog.link_intent("mem-001", "intent-1")
        intentlog.link_intent("mem-001", "intent-1")  # duplicate

        refs = intentlog.get_intents_for_memory("mem-001")
        assert refs.count("intent-1") == 1

    def test_link_nonexistent_memory_raises(self, intent_db):
        with pytest.raises(ValueError, match="not found"):
            intentlog.link_intent("nonexistent", "intent-1")


class TestUnlinkIntent:
    """Test unlinking intents from memories."""

    def test_unlink_existing(self, intent_db):
        intentlog.link_intent("mem-001", "intent-1")
        intentlog.link_intent("mem-001", "intent-2")

        result = intentlog.unlink_intent("mem-001", "intent-1")
        assert result is True

        refs = intentlog.get_intents_for_memory("mem-001")
        assert "intent-1" not in refs
        assert "intent-2" in refs

    def test_unlink_nonexistent_intent(self, intent_db):
        intentlog.link_intent("mem-001", "intent-1")
        result = intentlog.unlink_intent("mem-001", "intent-999")
        assert result is False

    def test_unlink_from_empty(self, intent_db):
        result = intentlog.unlink_intent("mem-001", "intent-1")
        assert result is False

    def test_unlink_nonexistent_memory_raises(self, intent_db):
        with pytest.raises(ValueError, match="not found"):
            intentlog.unlink_intent("nonexistent", "intent-1")

    def test_unlink_last_intent_clears_ref(self, intent_db):
        intentlog.link_intent("mem-001", "intent-only")
        intentlog.unlink_intent("mem-001", "intent-only")

        refs = intentlog.get_intents_for_memory("mem-001")
        assert refs == []


class TestGetIntentsForMemory:
    """Test retrieving intents for a memory."""

    def test_no_intents(self, intent_db):
        refs = intentlog.get_intents_for_memory("mem-001")
        assert refs == []

    def test_with_intents(self, intent_db):
        intentlog.link_intent("mem-001", "i1")
        intentlog.link_intent("mem-001", "i2")
        refs = intentlog.get_intents_for_memory("mem-001")
        assert set(refs) == {"i1", "i2"}

    def test_nonexistent_memory(self, intent_db):
        refs = intentlog.get_intents_for_memory("nonexistent")
        assert refs == []


class TestGetMemoriesForIntent:
    """Test retrieving memories for an intent."""

    def test_no_memories(self, intent_db):
        results = intentlog.get_memories_for_intent("intent-xyz")
        assert results == []

    def test_finds_linked_memory(self, intent_db):
        intentlog.link_intent("mem-001", "intent-shared")
        intentlog.link_intent("mem-002", "intent-shared")

        results = intentlog.get_memories_for_intent("intent-shared")
        mem_ids = [r["memory_id"] for r in results]
        assert "mem-001" in mem_ids
        assert "mem-002" in mem_ids

    def test_no_substring_false_positive(self, intent_db):
        """intent-1 should not match intent-10."""
        intentlog.link_intent("mem-001", "intent-10")
        results = intentlog.get_memories_for_intent("intent-1")
        # intent-1 is a substring of intent-10 in LIKE, but exact match check should filter it
        mem_ids = [r["memory_id"] for r in results]
        assert "mem-001" not in mem_ids


class TestSearchByIntent:
    """Test search_by_intent."""

    def test_search_finds_matches(self, intent_db):
        intentlog.link_intent("mem-001", "project-alpha-v1")
        results = intentlog.search_by_intent("alpha")
        assert len(results) >= 1
        assert results[0]["memory_id"] == "mem-001"

    def test_search_empty(self, intent_db):
        results = intentlog.search_by_intent("nonexistent-pattern")
        assert results == []

    def test_search_respects_limit(self, intent_db):
        intentlog.link_intent("mem-001", "batch-test")
        intentlog.link_intent("mem-002", "batch-test")
        results = intentlog.search_by_intent("batch", limit=1)
        assert len(results) <= 1
