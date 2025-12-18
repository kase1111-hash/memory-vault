import sqlite3
import json
import getpass
import os
from datetime import datetime, timedelta
import uuid
import hashlib

from .models import MemoryObject
from .crypto import (
    derive_key_from_passphrase,
    load_key_from_file,
    encrypt_memory,
    decrypt_memory
)
from .db import DB_PATH, init_db
from .boundary import check_recall


class MemoryVault:
    def __init__(self):
        init_db()
        self.profile_keys = {}  # Cache: profile_id -> key (bytes)

    def _get_key_for_profile(self, profile_id: str, profile_key_source: str) -> bytes:
        if profile_id in self.profile_keys:
            return self.profile_keys[profile_id]

        if profile_key_source == "HumanPassphrase":
            if profile_id == "default-passphrase":
                passphrase = getpass.getpass(f"Enter passphrase for profile '{profile_id}': ")
                key, _ = derive_key_from_passphrase(passphrase)
                self.profile_keys[profile_id] = key
                return key
            else:
                raise ValueError("Custom passphrase profiles not yet supported")

        elif profile_key_source == "KeyFile":
            keyfile_path = os.path.expanduser(f"~/.memory_vault/keys/{profile_id}.key")
            key = load_key_from_file(keyfile_path)
            self.profile_keys[profile_id] = key
            return key

        else:
            raise NotImplementedError(f"Key source '{profile_key_source}' not supported")

    def store_memory(self, obj: MemoryObject):
        if obj.classification < 0 or obj.classification > 5:
            raise ValueError("Invalid classification")

        # Validate profile exists
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT key_source FROM encryption_profiles WHERE profile_id = ?', (obj.encryption_profile,))
        profile_row = c.fetchone()
        if not profile_row:
            conn.close()
            raise ValueError(f"Encryption profile '{obj.encryption_profile}' not found")
        key_source = profile_row[0]

        # Get key and encrypt
        key = self._get_key_for_profile(obj.encryption_profile, key_source)
        ciphertext, nonce = encrypt_memory(key, obj.content_plaintext)
        obj.content_hash = hashlib.sha256(obj.content_plaintext).hexdigest()

        # Generate per-memory salt (for passphrase-derived keys)
        salt = nacl.utils.random(nacl.pwhash.SALTBYTES) if key_source == "HumanPassphrase" else None

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
        print(f"Stored memory {obj.memory_id} using profile '{obj.encryption_profile}' at level {obj.classification}")

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

        # Boundary daemon check
        permitted, reason = check_recall(classification)
        if not permitted:
            self._log_recall(c, memory_id, requester, False, justification + f" (boundary: {reason})")
            conn.commit()
            conn.close()
            raise PermissionError(f"Boundary check failed: {reason}")

        # Human approval for high classification
        if classification >= 3:
            print(f"[Level {classification}] Human approval required for recall.")
            approve = input("Approve recall? (yes/no): ").strip().lower()
            if approve != "yes":
                self._log_recall(c, memory_id, requester, False, justification + " (human denied)")
                conn.commit()
                conn.close()
                raise PermissionError("Recall denied by human")

        # Cooldown enforcement
        cooldown_seconds = access_policy.get("cooldown_seconds", 0)
        if cooldown_seconds > 0:
            last_time = self._get_last_successful_recall_time(c, memory_id)
            if last_time:
                elapsed = datetime.utcnow() - last_time
                if elapsed < timedelta(seconds=cooldown_seconds):
                    remaining = int(cooldown_seconds - elapsed.total_seconds())
                    self._log_recall(c, memory_id, requester, False, justification + f" (cooldown: {remaining}s remaining)")
                    conn.commit()
                    conn.close()
                    raise PermissionError(f"Cooldown active: {remaining} seconds remaining")

        # Get key for this memory's profile
        c.execute('SELECT key_source FROM encryption_profiles WHERE profile_id = ?', (encryption_profile,))
        key_source = c.fetchone()[0]
        key = self._get_key_for_profile(encryption_profile, key_source)

        # If passphrase-derived and salt exists, re-derive using stored salt
        if key_source == "HumanPassphrase" and salt:
            passphrase = getpass.getpass(f"Re-enter passphrase for profile '{encryption_profile}': ")
            key, _ = derive_key_from_passphrase(passphrase, salt)

        # Decrypt
        plaintext = decrypt_memory(key, ciphertext, nonce)

        # Log success
        self._log_recall(c, memory_id, requester, True, justification)
        conn.commit()
        conn.close()
        return plaintext

    def _log_recall(self, cursor, memory_id: str, requester: str, approved: bool, justification: str):
        cursor.execute('INSERT INTO recall_log VALUES (?, ?, ?, ?, ?, ?)',
                       (str(uuid.uuid4()), memory_id, requester,
                        datetime.utcnow().isoformat(), 1 if approved else 0, justification))

    def _get_last_successful_recall_time(self, cursor, memory_id: str):
        cursor.execute('''
            SELECT timestamp FROM recall_log 
            WHERE memory_id = ? AND approved = 1 
            ORDER BY timestamp DESC LIMIT 1
        ''', (memory_id,))
        row = cursor.fetchone()
        return datetime.fromisoformat(row[0]) if row else None
