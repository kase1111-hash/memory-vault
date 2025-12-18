import sqlite3
import os
from datetime import datetime

DB_PATH = "vault.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS memories (
            memory_id TEXT PRIMARY KEY,
            created_at TEXT,
            created_by TEXT,
            classification INTEGER,
            encryption_profile TEXT,
            content_hash TEXT,
            ciphertext BLOB,
            nonce BLOB,
            salt BLOB,
            intent_ref TEXT,
            value_metadata TEXT,  -- JSON string
            access_policy TEXT,   -- JSON string
            audit_proof TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS encryption_profiles (
            profile_id TEXT PRIMARY KEY,
            cipher TEXT,
            key_source TEXT,
            rotation_policy TEXT,
            exportable INTEGER
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS recall_log (
            request_id TEXT,
            memory_id TEXT,
            requester TEXT,
            timestamp TEXT,
            approved INTEGER,
            justification TEXT
        )
    ''')
    # Default profile
    c.execute('INSERT OR IGNORE INTO encryption_profiles VALUES (?, ?, ?, ?, ?)',
              ("default-passphrase", "AES-256-GCM", "HumanPassphrase", "manual", 0))
    conn.commit()
    conn.close()
