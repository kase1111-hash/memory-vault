# memory_vault/vault.py

import sqlite3
import json
import getpass
import os
import uuid
import hashlib
from datetime import datetime, timedelta

from nacl.utils import random as nacl_random

from .models import MemoryObject
from .crypto import (
    derive_key_from_passphrase,
    load_key_from_file,
    encrypt_memory,
    decrypt_memory,
    generate_keyfile
)
from .db import DB_PATH, init_db
from .boundary import check_recall


class MemoryVault:
    def __init__(self):
        init_db()
        self.profile_keys = {}  # Cache: profile_id -> key (bytes)

    # ==================== Profile Management ====================

    def create_profile(
        self,
        profile_id: str,
        cipher: str = "AES-256-GCM",
        key_source: str = "HumanPassphrase",
        rotation_policy: str = "manual",
        exportable: bool = False,
        generate_keyfile: bool = False
    ) -> None:
        if key_source not in ["HumanPassphrase", "KeyFile", "TPM"]:
            raise ValueError("Unsupported key_source")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT 1 FROM encryption_profiles WHERE profile_id = ?', (profile_id,))
        if c.fetchone():
            conn.close()
            raise ValueError(f"Profile '{profile_id}' already exists")

        if key_source == "KeyFile" and generate_keyfile:
            keyfile_path = generate_keyfile(profile_id)
            print(f"Generated keyfile: {keyfile_path}")

        c.execute('''
            INSERT INTO encryption_profiles 
            (profile_id, cipher, key_source, rotation_policy, exportable) 
            VALUES (?, ?, ?, ?, ?)
        ''', (profile_id, cipher, key_source, rotation_policy, 1 if exportable else 0))
        conn.commit()
        conn.close()
        print(f"Created encryption profile: {profile_id} ({key_source})")

    def list_profiles(self) -> list[dict]:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT profile_id, cipher, key_source, rotation_policy, exportable FROM encryption_profiles')
        rows = c.fetchall()
        conn.close()
        return [
            {
                "profile_id": r[0],
                "cipher": r[1],
                "key_source": r[2],
                "rotation_policy": r[3],
                "exportable": bool(r[4])
            } for r in rows
        ]

    # ==================== Key Handling ====================

    def _get_key_for_profile(self, profile_id: str, key_source: str, salt: bytes = None) -> bytes:
        # Return cached key if available
        if profile_id in self.profile_keys:
            return self.profile_keys[profile_id]

        key: bytes
        if key_source == "HumanPassphrase":
            passphrase = getpass.getpass(f"Enter passphrase for profile '{profile_id}': ")
            key, _ = derive_key_from_passphrase(passphrase, salt)
        elif key_source == "KeyFile":
            keyfile_path = os.path.expanduser(f"~/.memory_vault/keys/{profile_id}.key")
            key = load_key_from_file(keyfile_path)
        else:
            raise NotImplementedError(f"Key source '{key_source}' not supported")

        self.profile_keys[profile_id] = key
        return key

    # ==================== Memory Operations ====================

    def store_memory(self, obj: MemoryObject):
        if obj.classification < 0 or obj.classification > 5:
            raise ValueError("Invalid classification")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Validate profile exists
        c.execute('SELECT key_source FROM encryption_profiles WHERE profile_id = ?', (obj.encryption_profile,))
        profile_row = c.fetchone()
        if not profile_row:
            conn.close()
            raise ValueError(f"Encryption profile '{obj.encryption_profile}' not found")
        key_source = profile_row[0]

        # Generate per-memory salt for passphrase-derived keys
        salt = nacl_random(nacl.pwhash.SALTBYTES) if key_source == "HumanPassphrase" else None

        # Get encryption key (prompts if needed)
        key = self._get_key_for_profile(obj.encryption_profile, key_source, salt)

        # Encrypt
        ciphertext, nonce = encrypt_memory(key, obj.content_plaintext)
        obj.content_hash = hashlib.sha256(obj.content_plaintext).hexdigest()

        # Store
        c.execute('''
            INSERT INTO memories VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            obj.memory_id,
            obj.created_at.isoformat(),
            obj.created_by,
            obj.classification,
            obj.encryption_profile,
            obj.content_hash,
            ciphertext,
            nonce,
            salt,
            obj.intent_ref,
            json.dumps(obj.value_metadata),
            json.dumps(obj.access_policy),
            obj.audit_proof
        ))
        conn.commit()
        conn.close()
        print(f"Stored memory {obj.memory_id} | Level {obj.classification} | Profile: {obj.encryption_profile}")

    def recall_memory(self, memory_id: str, justification: str = "", requester: str = "agent") -> bytes:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT * FROM memories WHERE memory_id = ?', (memory_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            raise ValueError("Memory not found")

        (
            _, _, _, classification, encryption_profile, _,
            ciphertext, nonce, salt, _, value_metadata_json, access_policy_json, _
        ) = row

        access_policy = json.loads(access_policy_json or '{"cooldown_seconds": 0}')

        # 1. Boundary daemon check
        permitted, reason = check_recall(classification)
        if not permitted:
            self._log_recall(c, memory_id, requester, False, justification + f" | boundary: {reason}")
            conn.commit()
            conn.close()
            raise PermissionError(f"Boundary check failed: {reason}")

        # 2. Human approval for high classification
        if classification >= 3:
            print(f"[Classification Level {classification}] Human approval required.")
            approve = input("Approve recall? (yes/no): ").strip().lower()
            if approve != "yes":
                self._log_recall(c, memory_id, requester, False, justification + " | human denied")
                conn.commit()
                conn.close()
                raise PermissionError("Recall denied by human")

        # 3. Cooldown enforcement
        cooldown_seconds = access_policy.get("cooldown_seconds", 0)
        if cooldown_seconds > 0:
            last_time = self._get_last_successful_recall_time(c, memory_id)
            if last_time:
                elapsed = datetime.utcnow() - last_time
                if elapsed < timedelta(seconds=cooldown_seconds):
                    remaining = int(cooldown_seconds - elapsed.total_seconds())
                    self._log_recall(c, memory_id, requester, False, justification + f" | cooldown: {remaining}s remaining")
                    conn.commit()
                    conn.close()
                    raise PermissionError(f"Cooldown active — {remaining} seconds remaining")

        # 4. Retrieve key for decryption
        c.execute('SELECT key_source FROM encryption_profiles WHERE profile_id = ?', (encryption_profile,))
        key_source = c.fetchone()[0]
        key = self._get_key_for_profile(encryption_profile, key_source, salt)

        # 5. Decrypt
        plaintext = decrypt_memory(key, ciphertext, nonce)

        # 6. Log success
        self._log_recall(c, memory_id, requester, True, justification)
        conn.commit()
        conn.close()
        return plaintext

    # ==================== Internal Helpers ====================

    def _log_recall(self, cursor, memory_id: str, requester: str, approved: bool, justification: str):
        cursor.execute('''
            INSERT INTO recall_log 
            (request_id, memory_id, requester, timestamp, approved, justification)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            str(uuid.uuid4()),
            memory_id,
            requester,
            datetime.utcnow().isoformat(),
            1 if approved else 0,
            justification
        ))

    def _get_last_successful_recall_time(self, cursor, memory_id: str):
        cursor.execute('''
            SELECT timestamp FROM recall_log 
            WHERE memory_id = ? AND approved = 1 
            ORDER BY timestamp DESC LIMIT 1
        ''', (memory_id,))
        row = cursor.fetchone()
        return datetime.fromisoformat(row[0]) if row else None
