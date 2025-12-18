# memory_vault/db.py

import sqlite3
import os

# Default database path (can be overridden if needed)
DB_PATH = os.path.expanduser("~/.memory_vault/vault.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


def init_db():
    """
    Initialize the SQLite database and create tables if they don't exist.
    Also performs safe migrations for new columns (e.g., sealed_blob).
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Encryption profiles table
    c.execute('''
        CREATE TABLE IF NOT EXISTS encryption_profiles (
            profile_id TEXT PRIMARY KEY,
            cipher TEXT NOT NULL DEFAULT 'AES-256-GCM',
            key_source TEXT NOT NULL,  -- HumanPassphrase, KeyFile, TPM
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
            classification INTEGER NOT NULL,  -- 0-5
            encryption_profile TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            ciphertext BLOB NOT NULL,
            nonce BLOB NOT NULL,
            salt BLOB,                        -- For passphrase-derived keys
            intent_ref TEXT,
            value_metadata TEXT,              -- JSON string
            access_policy TEXT,               -- JSON string
            audit_proof TEXT,                 -- Future use
            sealed_blob BLOB,                 -- For TPM-sealed keys
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
            approved INTEGER NOT NULL,        -- 1 = success, 0 = denied
            justification TEXT,
            FOREIGN KEY (memory_id) REFERENCES memories (memory_id)
        )
    ''')

    # --- Safe column additions (idempotent migrations) ---

    # Add sealed_blob if not exists (for TPM support)
    c.execute("PRAGMA table_info(memories)")
    columns = [col[1] for col in c.fetchall()]
    if 'sealed_blob' not in columns:
        c.execute("ALTER TABLE memories ADD COLUMN sealed_blob BLOB")
        print("Added 'sealed_blob' column to memories table (TPM support)")

    # Ensure default profiles exist
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
    print(f"Memory Vault database ready at {DB_PATH}")


# Optional: Call init_db() automatically on import
if not os.path.exists(DB_PATH):
    init_db()
else:
    # Ensure schema is up-to-date even if DB exists
    init_db()
