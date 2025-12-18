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
    generate_keyfile,
    load_or_create_signing_key,
    sign_root
)
from .db import DB_PATH, init_db
from .boundary import check_recall
from .merkle import hash_leaf, build_tree


class MemoryVault:
    def __init__(self):
        init_db()
        self.profile_keys = {}  # Cache non-TPM keys
        self.signing_key = load_or_create_signing_key()  # For signed Merkle roots

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
        from .crypto import TPM_AVAILABLE  # Local import to avoid circular issues

        allowed = ["HumanPassphrase", "KeyFile"]
        if key_source == "TPM" and TPM_AVAILABLE:
            allowed.append("TPM")

        if key_source not in allowed:
            raise ValueError(f"Unsupported or unavailable key_source: {key_source}")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT 1 FROM encryption_profiles WHERE profile_id = ?', (profile_id,))
        if c.fetchone():
            conn.close()
            raise ValueError(f"Profile '{profile_id}' already exists")

        if key_source == "KeyFile" and generate_keyfile:
            from .crypto import generate_keyfile
            keyfile_path = generate_keyfile(profile_id)
            print(f"Generated keyfile: {keyfile_path}")

        c.execute('''
            INSERT INTO encryption_profiles 
            (profile_id, cipher, key_source, rotation_policy, exportable) 
            VALUES (?, ?, ?, ?, ?)
        ''', (profile_id, cipher, key_source, rotation_policy, int(exportable)))
        conn.commit()
        conn.close()
        print(f"Created profile: {profile_id} ({key_source})")

    def list_profiles(self) -> list[dict]:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT profile_id, cipher, key_source, rotation_policy, exportable FROM encryption_profiles')
        rows = c.fetchall()
        conn.close()
        return [
            {"profile_id": r[0], "cipher": r[1], "key_source": r[2],
             "rotation_policy": r[3], "exportable": bool(r[4])}
            for r in rows
        ]

    # ==================== Key Handling ====================

    def _get_or_prompt_key(self, profile_id: str, key_source: str, salt: bytes = None) -> bytes:
        if profile_id in self.profile_keys:
            return self.profile_keys[profile_id]

        if key_source == "HumanPassphrase":
            passphrase = getpass.getpass(f"Enter passphrase for profile '{profile_id}': ")
            key, _ = derive_key_from_passphrase(passphrase, salt)
        elif key_source == "KeyFile":
            keyfile_path = os.path.expanduser(f"~/.memory_vault/keys/{profile_id}.key")
            key = load_key_from_file(keyfile_path)
        else:
            raise ValueError("Unsupported key_source in cache path")

        self.profile_keys[profile_id] = key
        return key

    # ==================== Memory Operations ====================

    def store_memory(self, obj: MemoryObject):
        if not 0 <= obj.classification <= 5:
            raise ValueError("Classification must be 0-5")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT key_source FROM encryption_profiles WHERE profile_id = ?', (obj.encryption_profile,))
        row = c.fetchone()
        if not row:
            conn.close()
            raise ValueError(f"Profile '{obj.encryption_profile}' not found")
        key_source = row[0]

        salt = nacl_random(16) if key_source == "HumanPassphrase" else None
        sealed_blob = None
        ciphertext = None
        nonce = None

        if key_source == "TPM":
            from .crypto import tpm_create_and_persist_primary, tpm_generate_sealed_key
            tpm_create_and_persist_primary()
            ephemeral_key = nacl_random(32)
            ciphertext, nonce = encrypt_memory(ephemeral_key, obj.content_plaintext)
            sealed_blob = tpm_generate_sealed_key()  # Seals ephemeral_key
        else:
            key = self._get_or_prompt_key(obj.encryption_profile, key_source, salt)
            ciphertext, nonce = encrypt_memory(key, obj.content_plaintext)

        obj.content_hash = hashlib.sha256(obj.content_plaintext).hexdigest()

        c.execute('''
            INSERT INTO memories VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            obj.audit_proof,
            sealed_blob
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

        columns = [d[0] for d in c.description]
        row_dict = dict(zip(columns, row))

        classification = row_dict["classification"]
        encryption_profile = row_dict["encryption_profile"]
        ciphertext = row_dict["ciphertext"]
        nonce = row_dict["nonce"]
        salt = row_dict["salt"]
        sealed_blob = row_dict["sealed_blob"]
        access_policy = json.loads(row_dict["access_policy"] or '{"cooldown_seconds": 0}')

        # 1. Boundary check
        permitted, reason = check_recall(classification)
        if not permitted:
            self._log_recall(c, memory_id, requester, False, justification + f" | boundary: {reason}")
            conn.commit()
            conn.close()
            raise PermissionError(f"Boundary check failed: {reason}")

        # 2. Human approval
        if classification >= 3:
            print(f"[Level {classification}] Human approval required.")
            approve = input("Approve recall? (yes/no): ").strip().lower()
            if approve != "yes":
                self._log_recall(c, memory_id, requester, False, justification + " | human denied")
                conn.commit()
                conn.close()
                raise PermissionError("Recall denied by human")

        # 3. Cooldown
        cooldown = access_policy.get("cooldown_seconds", 0)
        if cooldown > 0:
            last_time = self._get_last_successful_recall_time(c, memory_id)
            if last_time and (datetime.utcnow() - last_time) < timedelta(seconds=cooldown):
                remaining = int(cooldown - (datetime.utcnow() - last_time).total_seconds())
                self._log_recall(c, memory_id, requester, False, f"cooldown: {remaining}s")
                conn.commit()
                conn.close()
                raise PermissionError(f"Cooldown active — {remaining}s remaining")

        # 4. Key & decrypt
        c.execute('SELECT key_source FROM encryption_profiles WHERE profile_id = ?', (encryption_profile,))
        key_source = c.fetchone()[0]

        try:
            if key_source == "TPM":
                from .crypto import tpm_unseal_key
                if not sealed_blob:
                    raise PermissionError("TPM sealed key missing")
                key = tpm_unseal_key(sealed_blob)
            else:
                key = self._get_or_prompt_key(encryption_profile, key_source, salt)
        except Exception as e:
            self._log_recall(c, memory_id, requester, False, f"key error: {e}")
            conn.commit()
            conn.close()
            raise PermissionError(f"Key access failed: {e}")

        try:
            plaintext = decrypt_memory(key, ciphertext, nonce)
        except Exception as e:
            self._log_recall(c, memory_id, requester, False, f"decrypt error: {e}")
            conn.commit()
            conn.close()
            raise RuntimeError("Decryption failed")

        # 5. Log success + update Merkle tree
        self._log_recall(c, memory_id, requester, True, justification)
        conn.commit()
        conn.close()
        return plaintext

    # ==================== Audit Logging + Merkle + Signing ====================

    def _log_recall(self, cursor, memory_id: str, requester: str, approved: bool, justification: str):
        request_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()

        cursor.execute('''
            INSERT INTO recall_log 
            (request_id, memory_id, requester, timestamp, approved, justification)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (request_id, memory_id, requester, timestamp, int(approved), justification))

        log_entry = f"{request_id}|{memory_id}|{requester}|{timestamp}|{int(approved)}|{justification or ''}"
        leaf_hash = hash_leaf(log_entry)

        cursor.execute("INSERT INTO merkle_leaves (request_id, leaf_hash) VALUES (?, ?)", (request_id, leaf_hash))

        # Rebuild tree
        conn = cursor.connection
        c2 = conn.cursor()
        c2.execute("SELECT leaf_hash FROM merkle_leaves ORDER BY leaf_id")
        leaves = [r[0] for r in c2.fetchall()]
        new_root, proofs = build_tree(leaves)

        c2.execute("SELECT COALESCE(MAX(seq), 0) FROM merkle_roots")
        next_seq = c2.fetchone()[0] + 1

        signature = sign_root(self.signing_key, new_root, next_seq, timestamp)

        c2.execute('''
            INSERT INTO merkle_roots (seq, root_hash, timestamp, leaf_count, signature)
            VALUES (?, ?, ?, ?, ?)
        ''', (next_seq, new_root, timestamp, len(leaves), signature))

        # Update proof for this memory
        if leaves:
            leaf_idx = len(leaves) - 1
            proof_json = json.dumps(proofs[leaf_idx]) if leaf_idx < len(proofs) else "[]"
            c2.execute("UPDATE memories SET audit_proof = ? WHERE memory_id = ?", (proof_json, memory_id))

    def _get_last_successful_recall_time(self, cursor, memory_id: str):
        cursor.execute('''
            SELECT timestamp FROM recall_log 
            WHERE memory_id = ? AND approved = 1 
            ORDER BY timestamp DESC LIMIT 1
        ''', (memory_id,))
        row = cursor.fetchone()
        return datetime.fromisoformat(row[0]) if row else None
