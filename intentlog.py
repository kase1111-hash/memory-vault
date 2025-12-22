# memory_vault/intentlog.py
"""
IntentLog Adapter - Bidirectional linking between Memory Vault and IntentLog systems.

This module provides integration with external IntentLog systems for tracking
the relationship between memories and the intents that created/used them.
"""

import sqlite3
import json
from typing import List, Optional
from datetime import datetime

from .db import DB_PATH


def link_intent(memory_id: str, intent_id: str) -> bool:
    """
    Link a memory to an intent ID (bidirectional linking).

    Args:
        memory_id: The memory to link
        intent_id: The IntentLog intent ID

    Returns:
        bool: True if link was created successfully
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Check memory exists
    c.execute("SELECT intent_ref FROM memories WHERE memory_id = ?", (memory_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise ValueError(f"Memory '{memory_id}' not found")

    # Update intent_ref (can store multiple as JSON array)
    existing = row[0]
    if existing:
        try:
            intent_refs = json.loads(existing)
            if not isinstance(intent_refs, list):
                intent_refs = [intent_refs]
        except json.JSONDecodeError:
            intent_refs = [existing]
    else:
        intent_refs = []

    if intent_id not in intent_refs:
        intent_refs.append(intent_id)

    c.execute(
        "UPDATE memories SET intent_ref = ? WHERE memory_id = ?",
        (json.dumps(intent_refs), memory_id)
    )
    conn.commit()
    conn.close()

    print(f"Linked memory {memory_id[:8]}... to intent {intent_id}")
    return True


def unlink_intent(memory_id: str, intent_id: str) -> bool:
    """
    Remove a link between a memory and an intent.

    Args:
        memory_id: The memory to unlink
        intent_id: The IntentLog intent ID to remove

    Returns:
        bool: True if unlink was successful
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT intent_ref FROM memories WHERE memory_id = ?", (memory_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise ValueError(f"Memory '{memory_id}' not found")

    existing = row[0]
    if not existing:
        conn.close()
        return False

    try:
        intent_refs = json.loads(existing)
        if not isinstance(intent_refs, list):
            intent_refs = [intent_refs]
    except json.JSONDecodeError:
        intent_refs = [existing]

    if intent_id in intent_refs:
        intent_refs.remove(intent_id)
        new_ref = json.dumps(intent_refs) if intent_refs else None
        c.execute(
            "UPDATE memories SET intent_ref = ? WHERE memory_id = ?",
            (new_ref, memory_id)
        )
        conn.commit()
        conn.close()
        print(f"Unlinked intent {intent_id} from memory {memory_id[:8]}...")
        return True

    conn.close()
    return False


def get_memories_for_intent(intent_id: str) -> List[dict]:
    """
    Find all memories linked to a specific intent.

    Args:
        intent_id: The IntentLog intent ID

    Returns:
        List of memory records (id, classification, created_at, metadata)
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Search for intent_id in intent_ref JSON
    # SQLite JSON functions or LIKE pattern matching
    c.execute("""
        SELECT memory_id, classification, created_at, value_metadata, tombstoned
        FROM memories
        WHERE intent_ref LIKE ?
    """, (f'%{intent_id}%',))

    results = []
    for row in c.fetchall():
        memory_id, classification, created_at, metadata, tombstoned = row
        # Verify the intent_id is actually in the list (not just substring match)
        c.execute("SELECT intent_ref FROM memories WHERE memory_id = ?", (memory_id,))
        ref_row = c.fetchone()
        if ref_row and ref_row[0]:
            try:
                refs = json.loads(ref_row[0])
                if not isinstance(refs, list):
                    refs = [refs]
                if intent_id in refs:
                    results.append({
                        "memory_id": memory_id,
                        "classification": classification,
                        "created_at": created_at,
                        "metadata": json.loads(metadata) if metadata else {},
                        "tombstoned": bool(tombstoned)
                    })
            except json.JSONDecodeError:
                if ref_row[0] == intent_id:
                    results.append({
                        "memory_id": memory_id,
                        "classification": classification,
                        "created_at": created_at,
                        "metadata": json.loads(metadata) if metadata else {},
                        "tombstoned": bool(tombstoned)
                    })

    conn.close()
    return results


def get_intents_for_memory(memory_id: str) -> List[str]:
    """
    Get all intent IDs linked to a memory.

    Args:
        memory_id: The memory ID

    Returns:
        List of intent IDs
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT intent_ref FROM memories WHERE memory_id = ?", (memory_id,))
    row = c.fetchone()
    conn.close()

    if not row or not row[0]:
        return []

    try:
        refs = json.loads(row[0])
        if not isinstance(refs, list):
            refs = [refs]
        return refs
    except json.JSONDecodeError:
        return [row[0]] if row[0] else []


def search_by_intent(query: str, limit: int = 20) -> List[dict]:
    """
    Search memories by intent reference pattern.

    Args:
        query: Search pattern for intent IDs
        limit: Maximum results to return

    Returns:
        List of matching memory summaries
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        SELECT memory_id, classification, created_at, intent_ref, tombstoned
        FROM memories
        WHERE intent_ref LIKE ?
        ORDER BY created_at DESC
        LIMIT ?
    """, (f'%{query}%', limit))

    results = []
    for row in c.fetchall():
        memory_id, classification, created_at, intent_ref, tombstoned = row
        results.append({
            "memory_id": memory_id,
            "classification": classification,
            "created_at": created_at,
            "intent_refs": json.loads(intent_ref) if intent_ref else [],
            "tombstoned": bool(tombstoned)
        })

    conn.close()
    return results
