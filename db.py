# memory_vault/db.py

import sqlite3
import os

# Default database path
DB_PATH = os.path.expanduser("~/.memory_vault/vault.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def _index_exists(c: sqlite3.Cursor, index_name: str) -> bool:
    """Check if an index already exists."""
    c.execute("SELECT name FROM sqlite_master WHERE type='index' AND name=?", (index_name,))
    return c.fetchone() is not None


def init_db():
    """
    Initialize the SQLite database with tables and performance indexes.
    All operations are idempotent.
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Encryption profiles table
    c.execute('''
        CREATE TABLE IF NOT EXISTS encryption_profiles (
            profile_id TEXT PRIMARY KEY,
            cipher TEXT NOT NULL DEFAULT 'AES-256-GCM',
            key_source TEXT NOT NULL,
            rotation_policy TEXT DEFAULT 'manual',
            exportable INTEGER NOT NULL DEFAULT 0
        )
    ''')

    # Memories table
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
            value_metadata TEXT,
            access_policy TEXT,
            audit_proof TEXT,
            sealed_blob BLOB,
            FOREIGN KEY (encryption_profile) REFERENCES encryption_profiles (profile_id)
        )
    ''')

    # Recall log table
    c.execute('''
        CREATE TABLE IF NOT EXISTS recall_log (
            request_id TEXT PRIMARY KEY,
            memory_id TEXT NOT NULL,
            requester TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            approved INTEGER NOT NULL,
            justification TEXT,
            FOREIGN KEY (memory_id) REFERENCES memories (memory_id)
        )
    ''')

    # --- Safe column additions ---
    c.execute("PRAGMA table_info(memories)")
    columns = [col[1] for col in c.fetchall()]
    if 'sealed_blob' not in columns:
        c.execute("ALTER TABLE memories ADD COLUMN sealed_blob BLOB")
        print("Added 'sealed_blob' column to memories table")

    # --- Performance Indexes (idempotent) ---

    # 1. Fast lookup of memories by classification (used in potential future bulk boundary checks)
    if not _index_exists(c, "idx_memories_classification"):
        c.execute("CREATE INDEX idx_memories_classification ON memories (classification)")
        print("Created index: idx_memories_classification")

    # 2. Fast lookup of encryption profile for a memory
    if not _index_exists(c, "idx_memories_encryption_profile"):
        c.execute("CREATE INDEX idx_memories_encryption_profile ON memories (encryption_profile)")
        print("Created index: idx_memories_encryption_profile")

    # 3. Critical: Fast retrieval of latest approved recall for cooldown enforcement
    if not _index_exists(c, "idx_recall_log_memory_approved_timestamp"):
        c.execute('''
            CREATE INDEX idx_recall_log_memory_approved_timestamp 
            ON recall_log (memory_id, approved, timestamp DESC)
        ''')
        print("Created index: idx_recall_log_memory_approved_timestamp (for cooldown checks)")

    # 4. For auditing: Quick filtering by time range and approval status
    if not _index_exists(c, "idx_recall_log_timestamp"):
        c.execute("CREATE INDEX idx_recall_log_timestamp ON recall_log (timestamp)")
        print("Created index: idx_recall_log_timestamp")

    if not _index_exists(c, "idx_recall_log_approved"):
        c.execute("CREATE INDEX idx_recall_log_approved ON recall_log (approved)")
        print("Created index: idx_recall_log_approved")

    # 5. For forensic queries: Find all recalls by requester
    if not _index_exists(c, "idx_recall_log_requester"):
        c.execute("CREATE INDEX idx_recall_log_requester ON recall_log (requester)")
        print("Created index: idx_recall_log_requester")

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
    print(f"Memory Vault database ready and optimized at {DB_PATH}")


# Auto-initialize on import
if not os.path.exists(DB_PATH):
    init_db()
else:
    # Ensure schema and indexes are up-to-date
    init_db()
