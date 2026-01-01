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


def init_db(db_path: str = None):
    """
    Initialize the SQLite database with all required tables, indexes,
    full-text search virtual tables, and tamper-evidence structures.
    All operations are idempotent.

    Args:
        db_path: Optional path to the database file. If not provided, uses default DB_PATH.

    Returns:
        sqlite3.Connection: Connection to the initialized database.
    """
    path = db_path if db_path else DB_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    c = conn.cursor()

    # --- Core Tables ---

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
            value_metadata TEXT,
            access_policy TEXT,
            audit_proof TEXT,                 -- JSON list of Merkle sibling hashes
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
            justification TEXT,
            FOREIGN KEY (memory_id) REFERENCES memories (memory_id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS backups (
            backup_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            type TEXT NOT NULL,
            parent_backup_id TEXT,
            memory_count INTEGER NOT NULL,
            description TEXT
        )
    ''')

    # --- Merkle Tree for Tamper Evidence ---
    c.execute('''
        CREATE TABLE IF NOT EXISTS merkle_leaves (
            leaf_id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL UNIQUE,
            leaf_hash TEXT NOT NULL,
            FOREIGN KEY (request_id) REFERENCES recall_log (request_id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS merkle_roots (
            seq INTEGER PRIMARY KEY,
            root_hash TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            leaf_count INTEGER NOT NULL,
            signature TEXT NOT NULL   -- Base64 Ed25519 signature over seq|root|timestamp
        )
    ''')

    # --- Vault State Table (for Lockdown Mode) ---
    c.execute('''
        CREATE TABLE IF NOT EXISTS vault_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            lockdown INTEGER NOT NULL DEFAULT 0,
            lockdown_since TEXT,
            lockdown_reason TEXT
        )
    ''')
    c.execute("INSERT OR IGNORE INTO vault_state (id, lockdown) VALUES (1, 0)")

    # --- Safe Migrations ---
    c.execute("PRAGMA table_info(memories)")
    columns = [col[1] for col in c.fetchall()]
    if 'sealed_blob' not in columns:
        c.execute("ALTER TABLE memories ADD COLUMN sealed_blob BLOB")
        print("Added 'sealed_blob' column")
    if 'audit_proof' not in columns:
        c.execute("ALTER TABLE memories ADD COLUMN audit_proof TEXT")
        print("Added 'audit_proof' column")

    # --- Profile Key Rotation Columns ---
    c.execute("PRAGMA table_info(encryption_profiles)")
    profile_columns = [col[1] for col in c.fetchall()]
    if 'last_rotation' not in profile_columns:
        c.execute("ALTER TABLE encryption_profiles ADD COLUMN last_rotation TEXT")
        print("Added 'last_rotation' column to encryption_profiles")
    if 'rotation_count' not in profile_columns:
        c.execute("ALTER TABLE encryption_profiles ADD COLUMN rotation_count INTEGER DEFAULT 0")
        print("Added 'rotation_count' column to encryption_profiles")

    # --- Memory Tombstone Columns ---
    c.execute("PRAGMA table_info(memories)")
    memory_columns = [col[1] for col in c.fetchall()]
    if 'tombstoned' not in memory_columns:
        c.execute("ALTER TABLE memories ADD COLUMN tombstoned INTEGER DEFAULT 0")
        print("Added 'tombstoned' column to memories")
    if 'tombstoned_at' not in memory_columns:
        c.execute("ALTER TABLE memories ADD COLUMN tombstoned_at TEXT")
        print("Added 'tombstoned_at' column to memories")
    if 'tombstone_reason' not in memory_columns:
        c.execute("ALTER TABLE memories ADD COLUMN tombstone_reason TEXT")
        print("Added 'tombstone_reason' column to memories")
    if 'effort_receipt_id' not in memory_columns:
        c.execute("ALTER TABLE memories ADD COLUMN effort_receipt_id TEXT")
        print("Added 'effort_receipt_id' column to memories")
    if 'chain_anchor_id' not in memory_columns:
        c.execute("ALTER TABLE memories ADD COLUMN chain_anchor_id TEXT")
        print("Added 'chain_anchor_id' column to memories")

    # --- Escrow Shards Table ---
    c.execute('''
        CREATE TABLE IF NOT EXISTS escrow_shards (
            escrow_id TEXT NOT NULL,
            shard_index INTEGER NOT NULL,
            shard_data BLOB NOT NULL,
            recipient TEXT NOT NULL,
            created_at TEXT NOT NULL,
            threshold INTEGER NOT NULL,
            total_shards INTEGER NOT NULL,
            profile_id TEXT NOT NULL,
            PRIMARY KEY (escrow_id, shard_index)
        )
    ''')

    # --- Effort Tracking Tables (MP-02 Protocol) ---
    c.execute('''
        CREATE TABLE IF NOT EXISTS effort_signals (
            signal_id TEXT PRIMARY KEY,
            segment_id TEXT,
            signal_type TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            metadata TEXT
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS effort_segments (
            segment_id TEXT PRIMARY KEY,
            start_time TEXT NOT NULL,
            end_time TEXT,
            boundary_reason TEXT,
            signal_count INTEGER DEFAULT 0,
            metadata TEXT,
            validated INTEGER DEFAULT 0
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS effort_receipts (
            receipt_id TEXT PRIMARY KEY,
            segment_id TEXT NOT NULL,
            memory_id TEXT,
            time_bounds_start TEXT NOT NULL,
            time_bounds_end TEXT NOT NULL,
            signal_count INTEGER NOT NULL,
            signal_hashes TEXT NOT NULL,
            effort_summary TEXT,
            validation_result TEXT,
            created_at TEXT NOT NULL,
            signature TEXT NOT NULL,
            ledger_entry_id TEXT,
            ledger_proof TEXT
        )
    ''')

    # --- NatLangChain Anchor Records ---
    c.execute('''
        CREATE TABLE IF NOT EXISTS chain_anchors (
            anchor_id TEXT PRIMARY KEY,
            memory_id TEXT NOT NULL,
            entry_id TEXT NOT NULL,
            anchor_type TEXT NOT NULL,
            anchored_at TEXT NOT NULL,
            block_hash TEXT,
            block_height INTEGER,
            verified INTEGER DEFAULT 0,
            metadata TEXT
        )
    ''')

    # --- Performance Indexes ---
    indexes = [
        ("idx_memories_classification", "CREATE INDEX idx_memories_classification ON memories (classification)"),
        ("idx_memories_encryption_profile", "CREATE INDEX idx_memories_encryption_profile ON memories (encryption_profile)"),
        ("idx_recall_log_memory_approved_timestamp",
         "CREATE INDEX idx_recall_log_memory_approved_timestamp ON recall_log (memory_id, approved, timestamp DESC)"),
        ("idx_recall_log_timestamp", "CREATE INDEX idx_recall_log_timestamp ON recall_log (timestamp)"),
        ("idx_recall_log_approved", "CREATE INDEX idx_recall_log_approved ON recall_log (approved)"),
        ("idx_recall_log_requester", "CREATE INDEX idx_recall_log_requester ON recall_log (requester)"),
        ("idx_merkle_leaves_request_id", "CREATE UNIQUE INDEX idx_merkle_leaves_request_id ON merkle_leaves (request_id)"),
        # Effort tracking indexes
        ("idx_effort_signals_segment", "CREATE INDEX idx_effort_signals_segment ON effort_signals (segment_id)"),
        ("idx_effort_signals_timestamp", "CREATE INDEX idx_effort_signals_timestamp ON effort_signals (timestamp)"),
        ("idx_effort_segments_validated", "CREATE INDEX idx_effort_segments_validated ON effort_segments (validated)"),
        ("idx_effort_receipts_memory", "CREATE INDEX idx_effort_receipts_memory ON effort_receipts (memory_id)"),
        ("idx_effort_receipts_segment", "CREATE INDEX idx_effort_receipts_segment ON effort_receipts (segment_id)"),
        # NatLangChain anchor indexes
        ("idx_chain_anchors_memory", "CREATE INDEX idx_chain_anchors_memory ON chain_anchors (memory_id)"),
        ("idx_chain_anchors_entry", "CREATE INDEX idx_chain_anchors_entry ON chain_anchors (entry_id)"),
    ]
    for name, sql in indexes:
        if not _index_exists(c, name):
            c.execute(sql)
            print(f"Created index: {name}")

    # --- Full-Text Search (FTS5) ---

    if not _table_exists(c, "memories_fts"):
        c.execute('''
            CREATE VIRTUAL TABLE memories_fts USING fts5(
                memory_id, value_metadata, content='memories', content_rowid='rowid'
            )
        ''')
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

        c.execute('''
            INSERT INTO memories_fts(rowid, memory_id, value_metadata)
            SELECT rowid, memory_id, value_metadata FROM memories WHERE value_metadata IS NOT NULL
        ''')
        print("Initialized memories_fts")

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
        print("Initialized recall_log_fts")

    # --- Default Profiles ---
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
    print(f"Memory Vault database initialized at {path}")
    return conn


def get_connection(db_path: str = None):
    """
    Get a connection to the database.

    Args:
        db_path: Optional path to the database file. If not provided, uses default DB_PATH.

    Returns:
        sqlite3.Connection: Connection to the database.
    """
    path = db_path if db_path else DB_PATH
    return sqlite3.connect(path)


# Auto-initialize (close the connection after initialization)
_conn = init_db()
_conn.close()


# === Full-Text Search Helpers ===

def search_memories_metadata(conn_or_query, query_or_limit=None, limit: int = 20) -> list[dict]:
    """
    Search memories by metadata using FTS5.

    Can be called as:
        search_memories_metadata("search term")
        search_memories_metadata("search term", 10)
        search_memories_metadata(connection, "search term")
        search_memories_metadata(connection, "search term", 10)
    """
    # Handle both (query) and (conn, query) signatures
    if isinstance(conn_or_query, sqlite3.Connection):
        conn = conn_or_query
        query = query_or_limit
        should_close = False
    else:
        conn = sqlite3.connect(DB_PATH)
        query = conn_or_query
        if query_or_limit is not None:
            limit = query_or_limit
        should_close = True

    c = conn.cursor()
    c.execute('''
        SELECT m.memory_id, m.classification, snippet(memories_fts, 1, '[', ']', '...', 32) AS preview
        FROM memories_fts
        JOIN memories m ON m.memory_id = memories_fts.memory_id
        WHERE memories_fts.value_metadata MATCH ?
        ORDER BY rank
        LIMIT ?
    ''', (query, limit))
    results = [{"memory_id": r[0], "classification": r[1], "preview": r[2]} for r in c.fetchall()]
    if should_close:
        conn.close()
    return results


def search_recall_justifications(conn_or_query, query_or_limit=None, limit: int = 20) -> list[dict]:
    """
    Search recall justifications using FTS5.

    Can be called as:
        search_recall_justifications("search term")
        search_recall_justifications("search term", 10)
        search_recall_justifications(connection, "search term")
        search_recall_justifications(connection, "search term", 10)
    """
    # Handle both (query) and (conn, query) signatures
    if isinstance(conn_or_query, sqlite3.Connection):
        conn = conn_or_query
        query = query_or_limit
        should_close = False
    else:
        conn = sqlite3.connect(DB_PATH)
        query = conn_or_query
        if query_or_limit is not None:
            limit = query_or_limit
        should_close = True

    c = conn.cursor()
    c.execute('''
        SELECT rl.request_id, rl.memory_id, rl.timestamp, rl.approved, snippet(recall_log_fts, 2, '[', ']', '...', 32) AS preview
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
    if should_close:
        conn.close()
    return results
