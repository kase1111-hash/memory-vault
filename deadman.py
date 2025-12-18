# memory_vault/deadman.py

import sqlite3
import json
import os
import getpass
import time
from datetime import datetime, timedelta
from memory_vault.crypto import encrypt_memory, decrypt_memory, derive_key_from_passphrase

DB_PATH = os.path.expanduser("~/.memory_vault/vault.db")
DMS_CONFIG_PATH = os.path.expanduser("~/.memory_vault/deadman_config.json")

def init_deadman_switch():
    """Create DMS table if not exists"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS deadman_switch (
            id INTEGER PRIMARY KEY,
            armed BOOLEAN NOT NULL DEFAULT 0,
            deadline TEXT,                    -- ISO timestamp
            last_checkin TEXT,
            payload_memory_ids TEXT,          -- JSON list of vault memory_ids
            recipient_pubkeys TEXT,           -- JSON list of recipient public keys (for future encrypted release)
            justification TEXT
        )
    ''')
    conn.commit()
    conn.close()

def arm_deadman_switch(deadline_days: int, memory_ids: list[str], justification: str):
    """
    Arm the dead-man switch.
    Requires physical token + human confirmation.
    """
    from memory_vault.token import require_physical_token
    print(f"\n[DEAD-MAN SWITCH] Arming switch for {deadline_days} days from now.")
    print("This will release the specified memories if you do not check in.")
    confirm = input("Type 'ARM DEADMAN' to proceed: ")
    if confirm != "ARM DEADMAN":
        print("Aborted.")
        return

    if not require_physical_token(justification):
        print("Physical token required to arm dead-man switch.")
        return

    deadline = (datetime.utcnow() + timedelta(days=deadline_days)).isoformat() + "Z"
    payload = {
        "armed": True,
        "deadline": deadline,
        "last_checkin": datetime.utcnow().isoformat() + "Z",
        "payload_memory_ids": memory_ids,
        "recipient_pubkeys": [],  # Future: encrypted release
        "justification": justification
    }

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM deadman_switch")  # Only one active
    c.execute('''
        INSERT INTO deadman_switch (armed, deadline, last_checkin, payload_memory_ids, justification)
        VALUES (1, ?, ?, ?, ?)
    ''', (deadline, payload["last_checkin"], json.dumps(memory_ids), justification))
    conn.commit()
    conn.close()

    # Save encrypted config for external monitoring
    passphrase = getpass.getpass("Passphrase for DMS config backup: ")
    key, salt = derive_key_from_passphrase(passphrase)
    ciphertext, nonce = encrypt_memory(key, json.dumps(payload, indent=2).encode())
    backup = {
        "encrypted": True,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "hint": f"Armed on {datetime.utcnow().date()} for {deadline_days} days"
    }
    os.makedirs(os.path.dirname(DMS_CONFIG_PATH), exist_ok=True)
    with open(DMS_CONFIG_PATH, "w") as f:
        json.dump(backup, f, indent=2)

    print(f"Dead-man switch ARMED. Deadline: {deadline.split('T')[0]}")
    print(f"Encrypted config saved to {DMS_CONFIG_PATH}")

def checkin_deadman_switch():
    """Prove aliveness — resets the timer"""
    from memory_vault.token import require_physical_token
    print("[DEAD-MAN CHECKIN] Proving aliveness...")
    if not require_physical_token("Dead-man checkin"):
        print("Physical token required for checkin")
        return False

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT armed, deadline FROM deadman_switch")
    row = c.fetchone()
    if not row or not row[0]:
        print("No active dead-man switch")
        conn.close()
        return False

    new_checkin = datetime.utcnow().isoformat() + "Z"
    c.execute("UPDATE deadman_switch SET last_checkin = ?", (new_checkin,))
    conn.commit()
    conn.close()

    print(f"Check-in successful: {new_checkin.split('T')[0]}")
    return True

def is_deadman_triggered() -> bool:
    """Check if deadline has passed (for external monitor)"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT armed, deadline FROM deadman_switch")
    row = c.fetchone()
    conn.close()
    if not row or not row[0]:
        return False
    deadline = datetime.fromisoformat(row[1].rstrip("Z"))
    return datetime.utcnow() > deadline

def get_triggered_payload_memory_ids() -> list[str]:
    """Return memory IDs to release if triggered"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT payload_memory_ids FROM deadman_switch WHERE armed = 1")
    row = c.fetchone()
    conn.close()
    if row and row[0]:
        return json.loads(row[0])
    return []

def disarm_deadman_switch():
    """Permanently disarm"""
    from memory_vault.token import require_physical_token
    print("[DEAD-MAN SWITCH] Disarming...")
    if not require_physical_token("Disarm dead-man switch"):
        return
    confirm = input("Type 'DISARM DEADMAN FOREVER' to confirm: ")
    if confirm != "DISARM DEADMAN FOREVER":
        print("Aborted.")
        return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM deadman_switch")
    conn.commit()
    conn.close()
    if os.path.exists(DMS_CONFIG_PATH):
        os.rename(DMS_CONFIG_PATH, DMS_CONFIG_PATH + ".disarmed")
    print("Dead-man switch DISARMED")
