# memory_vault/db.py

import sqlite3
import os
import json

# Default database path
DB_PATH = os.path.expanduser("~/.memory_vault/vault.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def _index_exists(c: sqlite3.Cursor, index_name: str) -> bool:
    c.execute("SELECT name FROM sqlite_master WHERE type='index' AND name=?", (index_name,))
    return c.fetchone() is not None


def _table_exists(c: sqlite3.Cursor, table_name: str) -> bool:
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    return c.fetchone() is not None


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # --- Core Tables (unchanged) ---
    c.execute('''
        CREATE TABLE IF NOT EXISTS encryption_profiles (
            profile_id TEXT PRIMARY KEY,
            cipher TEXT NOT NULL DEFAULT 'AES-256-GCM',
            key_source TEXT NOT NULL,
            rotation_policy TEXT DEFAULT 'manual',
            exportable INTEGER NOT NULL DEFAULT 0
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS memories (
            memory_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            classification INTEGER NOT NULL,
            encryption_profile TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            salt BLOB,
            intent_ref TEXT,
            value_metadata TEXT,              -- JSON string, searchable
            access_policy TEXT,
            audit_proof TEXT,
            sealed_blob BLOB,
            FOREIGN KEY (encryption_profile) REFERENCES encryption_profiles (profile_id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS recall_log (
            request_id TEXT PRIMARY KEY,
            memory_id TEXT NOT NULL,
            requester TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            approved INTEGER NOT NULL,
            justification TEXT,               -- Searchable
            FOREIGN KEY (memory_id) REFERENCES memories (memory_id)
        )
    ''')

    # --- Column migrations ---
    c.execute("PRAGMA table_info(memories)")
    columns = [col[1] for col in c.fetchall()]
    if 'sealed_blob' not in columns:
        c.execute("ALTER TABLE memories ADD COLUMN sealed_blob BLOB")
        print("Added 'sealed_blob' column")

    # --- Performance Indexes ---
    if not _index_exists(c, "idx_memories_classification"):
        c.execute("CREATE INDEX idx_memories_classification ON memories (classification)")
    if not _index_exists(c, "idx_memories_encryption_profile"):
        c.execute("CREATE INDEX idx_memories_encryption_profile ON memories (encryption_profile)")
    if not _index_exists(c, "idx_recall_log_memory_approved_timestamp"):
        c.execute('''CREATE INDEX idx_recall_log_memory_approved_timestamp 
                     ON recall_log (memory_id, approved, timestamp DESC)''')
    if not _index_exists(c, "idx_recall_log_timestamp"):
        c.execute("CREATE INDEX idx_recall_log_timestamp ON recall_log (timestamp)")
    if not _index_exists(c, "idx_recall_log_approved"):
        c.execute("CREATE INDEX idx_recall_log_approved ON recall_log (approved)")
    if not _index_exists(c, "idx_recall_log_requester"):
        c.execute("CREATE INDEX idx_recall_log_requester ON recall_log (requester)")

    # --- Full-Text Search Setup ---

    # 1. FTS5 virtual table for value_metadata
    if not _table_exists(c, "memories_fts"):
        c.execute('''
            CREATE VIRTUAL TABLE memories_fts USING fts5(
                memory_id,
                value_metadata,
                content='memories',
                content_rowid='rowid'
            )
        ''')
        print("Created FTS table: memories_fts")

        # Triggers to keep FTS index in sync
        c.execute('''
            CREATE TRIGGER IF NOT EXISTS memories_insert_fts AFTER INSERT ON memories BEGIN
                INSERT INTO memories_fts(rowid, memory_id, value_metadata)
                VALUES (new.rowid, new.memory_id, new.value_metadata);
            END;
        ''')
        c.execute('''
            CREATE TRIGGER IF NOT EXISTS memories_update_fts AFTER UPDATE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, memory_id, value_metadata)
                VALUES ('delete', old.rowid, old.memory_id, old.value_metadata);
                INSERT INTO memories_fts(rowid, memory_id, value_metadata)
                VALUES (new.rowid, new.memory_id, new.value_metadata);
            END;
        ''')
        c.execute('''
            CREATE TRIGGER IF NOT EXISTS memories_delete_fts AFTER DELETE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, memory_id, value_metadata)
                VALUES ('delete', old.rowid, old.memory_id, old.value_metadata);
            END;
        ''')

        # Populate initial data
        c.execute('''
            INSERT INTO memories_fts(memories_fts, rowid, memory_id, value_metadata)
            SELECT 'delete', rowid, memory_id, value_metadata FROM memories
        ''')
        c.execute('''
            INSERT INTO memories_fts(rowid, memory_id, value_metadata)
            SELECT rowid, memory_id, value_metadata FROM memories WHERE value_metadata IS NOT NULL
        ''')
        print("Populated initial FTS data for value_metadata")

    # 2. FTS5 virtual table for justification in recall_log
    if not _table_exists(c, "recall_log_fts"):
        c.execute('''
            CREATE VIRTUAL TABLE recall_log_fts USING fts5(
                request_id,
                memory_id,
                justification,
                content='recall_log',
                content_rowid='rowid'
            )
        ''')
        print("Created FTS table: recall_log_fts")

        # Sync triggers
        c.execute('''
            CREATE TRIGGER IF NOT EXISTS recall_insert_fts AFTER INSERT ON recall_log BEGIN
                INSERT INTO recall_log_fts(rowid, request_id, memory_id, justification)
                VALUES (new.rowid, new.request_id, new.memory_id, new.justification);
            END;
        ''')
        c.execute('''
            CREATE TRIGGER IF NOT EXISTS recall_update_fts AFTER UPDATE ON recall_log BEGIN
                INSERT INTO recall_log_fts(recall_log_fts, rowid, request_id, memory_id, justification)
                VALUES ('delete', old.rowid, old.request_id, old.memory_id, old.justification);
                INSERT INTO recall_log_fts(rowid, request_id, memory_id, justification)
                VALUES (new.rowid, new.request_id, new.memory_id, new.justification);
            END;
        ''')

        # Populate initial data
        c.execute('''
            INSERT INTO recall_log_fts(rowid, request_id, memory_id, justification)
            SELECT rowid, request_id, memory_id, justification FROM recall_log WHERE justification IS NOT NULL
        ''')
        print("Populated initial FTS data for justification")

    # --- Default profiles ---
    default_profiles = [
        ("default-passphrase", "AES-256-GCM", "HumanPassphrase", "manual", 0),
        ("static-keyfile", "AES-256-GCM", "KeyFile", "never", 0),
    ]
    c.executemany('''
        INSERT OR IGNORE INTO encryption_profiles 
        (profile_id, cipher, key_source, rotation_policy, exportable)
        VALUES (?, ?, ?, ?, ?)
    ''', default_profiles)

    conn.commit()
    conn.close()
    print(f"Memory Vault database with full-text search ready at {DB_PATH}")


# Auto-initialize
if not os.path.exists(DB_PATH):
    init_db()
else:
    init_db()


# === Helper Functions for Full-Text Search ===

def search_memories_metadata(query: str, limit: int = 20) -> list[dict]:
    """
    Search value_metadata using full-text search.
    Returns list of matching memories with memory_id and snippet.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT m.memory_id, m.classification, snippet(memories_fts, 1) AS preview
        FROM memories_fts
        JOIN memories m ON m.memory_id = memories_fts.memory_id
        WHERE memories_fts.value_metadata MATCH ?
        ORDER BY rank
        LIMIT ?
    ''', (query, limit))
    results = [{"memory_id": r[0], "classification": r[1], "preview": r[2]} for r in c.fetchall()]
    conn.close()
    return results


def search_recall_justifications(query: str, limit: int = 20) -> list[dict]:
    """
    Search justification field in recall_log.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT rl.request_id, rl.memory_id, rl.timestamp, rl.approved, snippet(recall_log_fts, 2) AS preview
        FROM recall_log_fts rl_fts
        JOIN recall_log rl ON rl.request_id = rl_fts.request_id
        WHERE rl_fts.justification MATCH ?
        ORDER BY rl.timestamp DESC
        LIMIT ?
    ''', (query, limit))
    results = [
        {
            "request_id": r[0],
            "memory_id": r[1],
            "timestamp": r[2],
            "approved": bool(r[3]),
            "preview": r[4]
        } for r in c.fetchall()
    ]
    conn.close()
    return results
