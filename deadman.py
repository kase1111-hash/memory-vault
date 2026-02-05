# memory_vault/deadman.py

import sqlite3
import json
import os
from datetime import datetime, timedelta, timezone
from typing import List

from nacl.public import SealedBox
import base64

try:
    from memory_vault.physical_token import require_physical_token
    from memory_vault.db import DB_PATH
except ImportError:
    from physical_token import require_physical_token
    from db import DB_PATH
DMS_CONFIG_PATH = os.path.expanduser("~/.memory_vault/deadman_config.json")


def init_deadman_switch():
    """Initialize DMS tables"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Main DMS state
    c.execute('''
        CREATE TABLE IF NOT EXISTS deadman_switch (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            armed BOOLEAN NOT NULL DEFAULT 0,
            deadline TEXT,
            last_checkin TEXT,
            payload_memory_ids TEXT,          -- JSON list
            justification TEXT
        )
    ''')

    # Heirs and encrypted payloads
    c.execute('''
        CREATE TABLE IF NOT EXISTS dms_heirs (
            heir_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            public_key_b64 TEXT NOT NULL,     -- age/X25519 public key
            encrypted_payload BLOB,           -- SealedBox encrypted JSON payload
            memory_ids TEXT                   -- JSON list (reference only)
        )
    ''')

    # Ensure single-row constraint
    c.execute("INSERT OR IGNORE INTO deadman_switch (id, armed) VALUES (1, 0)")
    conn.commit()
    conn.close()


def add_heir(name: str, public_key_b64: str) -> None:
    """Add a trusted heir with their public key (age format)"""
    try:
        pubkey_bytes = base64.b64decode(public_key_b64)
        SealedBox(pubkey_bytes)  # Validate
    except Exception as e:
        print(f"Invalid public key: {e}")
        return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO dms_heirs (name, public_key_b64) VALUES (?, ?)",
                  (name, public_key_b64))
        conn.commit()
        print(f"Heir '{name}' added successfully")
    except sqlite3.IntegrityError:
        print(f"Heir '{name}' already exists")
    conn.close()


def list_heirs() -> List[dict]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT name, public_key_b64 FROM dms_heirs")
    heirs = [{"name": r[0], "public_key": r[1]} for r in c.fetchall()]
    conn.close()
    return heirs


def arm_deadman_switch(deadline_days: int, memory_ids: List[str], justification: str) -> None:
    print(f"\n[DEAD-MAN SWITCH] Arming for {deadline_days} days")
    print("Payload will be releasable to registered heirs if no check-in.")
    confirm = input("Type 'ARM DEADMAN SWITCH' to continue: ")
    if confirm != "ARM DEADMAN SWITCH":
        print("Aborted")
        return

    if not require_physical_token("Arm dead-man switch"):
        print("Physical token required")
        return

    deadline = (datetime.now(timezone.utc) + timedelta(days=deadline_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    checkin = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        UPDATE deadman_switch SET
            armed = 1,
            deadline = ?,
            last_checkin = ?,
            payload_memory_ids = ?,
            justification = ?
        WHERE id = 1
    ''', (deadline, checkin, json.dumps(memory_ids), justification))
    conn.commit()
    conn.close()

    print("Dead-man switch ARMED")
    print(f"Deadline: {deadline.split('T')[0]}")
    print(f"Payload: {len(memory_ids)} memories")
    print("Run 'dms-encrypt-payload' to encrypt for heirs")


def checkin_deadman_switch() -> bool:
    print("[DEAD-MAN CHECKIN]")
    if not require_physical_token("Dead-man checkin"):
        return False

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT armed FROM deadman_switch WHERE id = 1")
    row = c.fetchone()
    if not row or not row[0]:
        print("No active switch")
        conn.close()
        return False

    new_checkin = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    c.execute("UPDATE deadman_switch SET last_checkin = ? WHERE id = 1", (new_checkin,))
    conn.commit()
    conn.close()
    print(f"Check-in recorded: {new_checkin.split('T')[0]}")
    return True


def is_deadman_triggered() -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT armed, deadline FROM deadman_switch WHERE id = 1")
    row = c.fetchone()
    conn.close()
    if not row or not row[0]:
        return False
    if not row[1]:
        return False
    deadline = datetime.fromisoformat(row[1].rstrip("Z"))
    return datetime.now(timezone.utc) > deadline


def get_payload_memory_ids() -> List[str]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT payload_memory_ids FROM deadman_switch WHERE id = 1")
    row = c.fetchone()
    conn.close()
    return json.loads(row[0]) if row and row[0] else []


def encrypt_payload_for_heirs(vault) -> None:
    """Encrypt current DMS payload for all registered heirs"""
    memory_ids = get_payload_memory_ids()
    if not memory_ids:
        print("No active payload")
        return

    print(f"Encrypting payload ({len(memory_ids)} memories) for heirs...")
    if not require_physical_token("Encrypt DMS payload for heirs"):
        return

    # Recall and assemble plaintext payload
    plaintext_memories = {}
    for mid in memory_ids:
        try:
            plain = vault.recall_memory(mid, justification="DMS heir payload encryption")
            plaintext_memories[mid] = base64.b64encode(plain).decode()
        except Exception as e:
            print(f"Failed to recall {mid}: {e}")

    if not plaintext_memories:
        print("No memories accessible")
        return

    payload = {
        "release_trigger": "deadman_switch",
        "release_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "memories": plaintext_memories
    }
    payload_json = json.dumps(payload, indent=2).encode()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT heir_id, name, public_key_b64 FROM dms_heirs")
    heirs = c.fetchall()

    for heir_id, name, pub_b64 in heirs:
        pubkey = base64.b64decode(pub_b64)
        box = SealedBox(pubkey)
        encrypted = box.encrypt(payload_json)
        c.execute('''
            UPDATE dms_heirs
            SET encrypted_payload = ?, memory_ids = ?
            WHERE heir_id = ?
        ''', (encrypted, json.dumps(memory_ids), heir_id))
        print(f"Encrypted for {name}")

    conn.commit()
    conn.close()
    print("Payload encryption complete")


def get_heir_release_packages() -> List[dict]:
    """Export encrypted packages for delivery"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT name, public_key_b64, encrypted_payload, memory_ids
        FROM dms_heirs WHERE encrypted_payload IS NOT NULL
    ''')
    packages = []
    for name, pubkey, enc_blob, mids_json in c.fetchall():
        if enc_blob:
            packages.append({
                "heir": name,
                "public_key_b64": pubkey,
                "encrypted_payload_b64": base64.b64encode(enc_blob).decode(),
                "memory_ids": json.loads(mids_json) if mids_json else []
            })
    conn.close()
    return packages


def disarm_deadman_switch() -> None:
    print("[DEAD-MAN SWITCH] DISARM")
    if not require_physical_token("Disarm dead-man switch"):
        return
    confirm = input("Type 'DISARM DEADMAN SWITCH FOREVER' to confirm: ")
    if confirm != "DISARM DEADMAN SWITCH FOREVER":
        print("Aborted")
        return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE deadman_switch SET armed = 0, deadline = NULL, justification = 'disarmed' WHERE id = 1")
    conn.commit()
    conn.close()
    print("Dead-man switch DISARMED")
