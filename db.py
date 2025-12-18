# memory_vault/db.py

import sqlite3
import os
import json

# Default database path
DB_PATH = os.path.expanduser("~/.memory_vault/vault.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def _index_exists(c: sqlite3.Cursor, index_name: str) -> bool:
    c.execute("SELECT name FROM sqlite_master WHERE TYPE='index' AND name=?", (index_name,))
    return c.fetchone() is not None


def _table_exists(c: sqlite3.Cursor, table_name: str) -> bool:
    c.execute("SELECT name FROM sqlite_master WHERE TYPE='table' AND name=?", (table_name,))
    return c.fetchone() is not None


def init_db():
    """
    Initialize the SQLite database with all tables, indexes, FTS virtual tables,
    and backup tracking. All operations are idempotent.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # --- Core Tables ---

    # Encryption profiles
    c.execute('''
        CREATE TABLE IF NOT EXISTS encryption_profiles (
            profile_id TEXT PRIMARY KEY,
            cipher TEXT NOT NULL DEFAULT 'AES-256-GCM',
            key_source TEXT NOT NULL,
            rotation_policy TEXT DEFAULT 'manual',
            exportable INTEGER NOT NULL DEFAULT 0
        )
    ''')

    # Memories (cognitive artifacts)
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
            value_metadata TEXT,              -- JSON string, FTS indexed
            access_policy TEXT,               -- JSON string
            audit_proof TEXT,
            sealed_blob BLOB,                 -- TPM-sealed keys
            FOREIGN KEY (encryption_profile) REFERENCES encryption_profiles (profile_id)
        )
    ''')

    # Recall audit log
    c.execute('''
        CREATE TABLE IF NOT EXISTS recall_log (
            request_id TEXT PRIMARY KEY,
            memory_id TEXT NOT NULL,
            requester TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            approved INTEGER NOT NULL,
            justification TEXT,               -- FTS indexed
            FOREIGN KEY (memory_id) REFERENCES memories (memory_id)
        )
    ''')

    # Backup tracking for incremental backups
    c.execute('''
        CREATE TABLE IF NOT EXISTS backups (
            backup_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            type TEXT NOT NULL,               -- 'full' or 'incremental'
            parent_backup_id TEXT,            -- NULL for full backups
            memory_count INTEGER NOT NULL,
            description TEXT
        )
    ''')

    # --- Safe Column Migrations ---
    c.execute("PRAGMA table_info(memories)")
    columns = [col[1] for col in c.fetchall()]
    if 'sealed_blob' not in columns:
        c.execute("ALTER TABLE memories ADD COLUMN sealed_blob BLOB")
        print("Added 'sealed_blob' column to memories")

    # --- Performance Indexes ---
    indexes = [
        ("idx_memories_classification", "CREATE INDEX idx_memories_classification ON memories (classification)"),
        ("idx_memories_encryption_profile", "CREATE INDEX idx_memories_encryption_profile ON memories (encryption_profile)"),
        ("idx_recall_log_memory_approved_timestamp", 
         "CREATE INDEX idx_recall_log_memory_approved_timestamp ON recall_log (memory_id, approved, timestamp DESC)"),
        ("idx_recall_log_timestamp", "CREATE INDEX idx_recall_log_timestamp ON recall_log (timestamp)"),
        ("idx_recall_log_approved", "CREATE INDEX idx_recall_log_approved ON recall_log (approved)"),
        ("idx_recall_log_requester", "CREATE INDEX idx_recall_log_requester ON recall_log (requester)"),
    ]
    for name, sql in indexes:
        if not _index_exists(c, name):
            c.execute(sql)
            print(f"Created index: {name}")

    # --- Full-Text Search Virtual Tables ---

    # Metadata search
    if not _table_exists(c, "memories_fts"):
        c.execute('''
            CREATE VIRTUAL TABLE memories_fts USING fts5(
                memory_id, value_metadata, content='memories', content_rowid='rowid'
            )
        ''')
        # Triggers
        c.execute('''
            CREATE TRIGGER memories_insert_fts AFTER INSERT ON memories BEGIN
                INSERT INTO memories_fts(rowid, memory_id, value_metadata)
                VALUES (new.rowid, new.memory_id, new.value_metadata);
            END;
        ''')
        c.execute('''
            CREATE TRIGGER memories_update_fts AFTER UPDATE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, memory_id, value_metadata)
                VALUES ('delete', old.rowid, old.memory_id, old.value_metadata);
                INSERT INTO memories_fts(rowid, memory_id, value_metadata)
                VALUES (new.rowid, new.memory_id, new.value_metadata);
            END;
        ''')
        c.execute('''
            CREATE TRIGGER memories_delete_fts AFTER DELETE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, memory_id, value_metadata)
                VALUES ('delete', old.rowid, old.memory_id, old.value_metadata);
            END;
        ''')

        # Initial population
        c.execute('''
            INSERT INTO memories_fts(rowid, memory_id, value_metadata)
            SELECT rowid, memory_id, value_metadata FROM memories WHERE value_metadata IS NOT NULL
        ''')
        print("Initialized memories_fts full-text index")

    # Justification search
    if not _table_exists(c, "recall_log_fts"):
        c.execute('''
            CREATE VIRTUAL TABLE recall_log_fts USING fts5(
                request_id, memory_id, justification, content='recall_log', content_rowid='rowid'
            )
        ''')
        c.execute('''
            CREATE TRIGGER recall_insert_fts AFTER INSERT ON recall_log BEGIN
                INSERT INTO recall_log_fts(rowid, request_id, memory_id, justification)
                VALUES (new.rowid, new.request_id, new.memory_id, new.justification);
            END;
        ''')
        c.execute('''
            CREATE TRIGGER recall_update_fts AFTER UPDATE ON recall_log BEGIN
                INSERT INTO recall_log_fts(recall_log_fts, rowid, request_id, memory_id, justification)
                VALUES ('delete', old.rowid, old.request_id, old.memory_id, old.justification);
                INSERT INTO recall_log_fts(rowid, request_id, memory_id, justification)
                VALUES (new.rowid, new.request_id, new.memory_id, new.justification);
            END;
        ''')

        c.execute('''
            INSERT INTO recall_log_fts(rowid, request_id, memory_id, justification)
            SELECT rowid, request_id, memory_id, justification FROM recall_log WHERE justification IS NOT NULL
        ''')
        print("Initialized recall_log_fts full-text index")

    # --- Default Encryption Profiles ---
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
    print(f"Memory Vault database fully initialized at {DB_PATH}")


# Auto-initialize on import
if not os.path.exists(DB_PATH):
    init_db()
else:
    init_db()  # Ensures migrations and indexes are applied


# === Full-Text Search Helpers (unchanged) ===

def search_memories_metadata(query: str, limit: int = 20) -> list[dict]:
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
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT rl.request_id, rl.memory_id, rl.timestamp, rl.approved, snippet(recall_log_fts, 2) AS preview
        FROM recall_log_fts
        JOIN recall_log rl ON rl.request_id = recall_log_fts.request_id
        WHERE recall_log_fts.justification MATCH ?
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
