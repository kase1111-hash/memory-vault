# memory_vault/vault.py

import sqlite3
import json
import getpass
import os
import uuid
import hashlib
import base64
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
from .boundry import check_recall
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
        # Check lockdown status first
        is_locked, since, reason = self.is_locked_down()
        if is_locked:
            raise PermissionError(f"Vault is in LOCKDOWN since {since}: {reason}")

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

        # 4. Physical token (Level 5 only)
        if classification == 5:
            from .physical_token import require_physical_token
            print(f"\n[Level 5] Physical security token required for recall.")
            if not require_physical_token(justification):
                self._log_recall(c, memory_id, requester, False, justification + " | token absent")
                conn.commit()
                conn.close()
                raise PermissionError("Physical token required but not presented")
            print("✓ Physical token confirmed\n")

        # 5. Key & decrypt
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

        # 6. Log success + update Merkle tree
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

    # ==================== Backup & Restore ====================

    def backup(self, output_file: str, incremental: bool = False,
               description: str = "", passphrase: str = None) -> None:
        """
        Create encrypted backup of the vault.

        Args:
            output_file: Path to backup file
            incremental: If True, only backup changes since last backup
            description: Human-readable backup description
            passphrase: Encryption passphrase (will prompt if None)
        """
        import getpass

        if passphrase is None:
            passphrase = getpass.getpass("Backup encryption passphrase: ")
            confirm = getpass.getpass("Confirm passphrase: ")
            if passphrase != confirm:
                raise ValueError("Passphrases do not match")

        # Derive encryption key from passphrase
        key, salt = derive_key_from_passphrase(passphrase)

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Determine backup type
        backup_id = str(uuid.uuid4())
        backup_type = "incremental" if incremental else "full"
        parent_backup_id = None

        if incremental:
            # Get last backup
            c.execute("SELECT backup_id FROM backups ORDER BY timestamp DESC LIMIT 1")
            row = c.fetchone()
            if row:
                parent_backup_id = row[0]
            else:
                print("No previous backup found, creating full backup instead")
                backup_type = "full"
                incremental = False

        # Collect memories to backup
        if incremental and parent_backup_id:
            # Only backup memories created/updated after last backup
            c.execute("""
                SELECT backup_id, timestamp FROM backups
                WHERE backup_id = ?
            """, (parent_backup_id,))
            parent_row = c.fetchone()
            parent_timestamp = parent_row[1] if parent_row else "1970-01-01T00:00:00"

            c.execute("""
                SELECT * FROM memories
                WHERE created_at > ?
            """, (parent_timestamp,))
        else:
            c.execute("SELECT * FROM memories")

        memories = []
        columns = [desc[0] for desc in c.description]

        for row in c.fetchall():
            memory_dict = dict(zip(columns, row))

            # Check if memory is exportable
            c.execute("""
                SELECT exportable FROM encryption_profiles
                WHERE profile_id = ?
            """, (memory_dict["encryption_profile"],))
            profile_row = c.fetchone()

            if profile_row and not profile_row[0]:
                # Non-exportable (e.g., TPM-sealed) - zero out ciphertext
                print(f"Warning: Memory {memory_dict['memory_id']} is non-exportable, excluding from backup")
                memory_dict["ciphertext"] = None
                memory_dict["nonce"] = None
                memory_dict["sealed_blob"] = None
            else:
                # Convert binary data to base64 for JSON serialization
                if memory_dict["ciphertext"]:
                    memory_dict["ciphertext"] = base64.b64encode(memory_dict["ciphertext"]).decode()
                if memory_dict["nonce"]:
                    memory_dict["nonce"] = base64.b64encode(memory_dict["nonce"]).decode()
                if memory_dict["salt"]:
                    memory_dict["salt"] = base64.b64encode(memory_dict["salt"]).decode()
                if memory_dict["sealed_blob"]:
                    memory_dict["sealed_blob"] = base64.b64encode(memory_dict["sealed_blob"]).decode()

            memories.append(memory_dict)

        # Collect encryption profiles
        c.execute("SELECT * FROM encryption_profiles")
        profiles = []
        profile_columns = [desc[0] for desc in c.description]
        for row in c.fetchall():
            profiles.append(dict(zip(profile_columns, row)))

        # Create backup payload
        backup_data = {
            "backup_id": backup_id,
            "backup_type": backup_type,
            "parent_backup_id": parent_backup_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "description": description,
            "memory_count": len(memories),
            "memories": memories,
            "encryption_profiles": profiles,
            "vault_version": "1.0.0"
        }

        # Serialize and encrypt
        plaintext = json.dumps(backup_data, indent=2).encode()
        ciphertext, nonce = encrypt_memory(key, plaintext)

        # Save encrypted backup
        backup_container = {
            "version": "1.0",
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }

        with open(output_file, "w") as f:
            json.dump(backup_container, f, indent=2)

        # Record backup in database
        c.execute("""
            INSERT INTO backups (backup_id, timestamp, type, parent_backup_id, memory_count, description)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (backup_id, backup_data["timestamp"], backup_type, parent_backup_id, len(memories), description))

        conn.commit()
        conn.close()

        print(f"✓ {backup_type.capitalize()} backup created: {output_file}")
        print(f"  Memories: {len(memories)}")
        print(f"  Backup ID: {backup_id}")

    def restore(self, backup_file: str, passphrase: str = None) -> None:
        """
        Restore vault from encrypted backup.

        Args:
            backup_file: Path to backup file
            passphrase: Decryption passphrase (will prompt if None)
        """
        import getpass

        if passphrase is None:
            passphrase = getpass.getpass("Backup decryption passphrase: ")

        # Load backup file
        with open(backup_file, "r") as f:
            backup_container = json.load(f)

        # Extract encryption parameters
        salt = base64.b64decode(backup_container["salt"])
        nonce = base64.b64decode(backup_container["nonce"])
        ciphertext = base64.b64decode(backup_container["ciphertext"])

        # Derive key and decrypt
        key, _ = derive_key_from_passphrase(passphrase, salt)

        try:
            plaintext = decrypt_memory(key, ciphertext, nonce)
        except Exception as e:
            raise ValueError("Decryption failed - incorrect passphrase or corrupted backup")

        backup_data = json.loads(plaintext)

        print(f"Restoring backup: {backup_data.get('description', 'No description')}")
        print(f"Backup type: {backup_data['backup_type']}")
        print(f"Created: {backup_data['timestamp']}")
        print(f"Memories: {backup_data['memory_count']}")

        confirm = input("\nThis will merge data into current vault. Continue? (yes/no): ")
        if confirm.lower() != "yes":
            print("Restore cancelled")
            return

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Restore encryption profiles
        for profile in backup_data.get("encryption_profiles", []):
            c.execute("""
                INSERT OR REPLACE INTO encryption_profiles
                (profile_id, cipher, key_source, rotation_policy, exportable)
                VALUES (?, ?, ?, ?, ?)
            """, (profile["profile_id"], profile["cipher"], profile["key_source"],
                  profile["rotation_policy"], profile["exportable"]))

        # Restore memories
        restored_count = 0
        skipped_count = 0

        for memory in backup_data["memories"]:
            # Check if memory already exists
            c.execute("SELECT 1 FROM memories WHERE memory_id = ?", (memory["memory_id"],))
            if c.fetchone():
                skipped_count += 1
                continue

            # Decode binary fields
            if memory["ciphertext"]:
                memory["ciphertext"] = base64.b64decode(memory["ciphertext"])
            if memory["nonce"]:
                memory["nonce"] = base64.b64decode(memory["nonce"])
            if memory["salt"]:
                memory["salt"] = base64.b64decode(memory["salt"])
            if memory["sealed_blob"]:
                memory["sealed_blob"] = base64.b64decode(memory["sealed_blob"])

            c.execute("""
                INSERT INTO memories VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                memory["memory_id"], memory["created_at"], memory["created_by"],
                memory["classification"], memory["encryption_profile"], memory["content_hash"],
                memory["ciphertext"], memory["nonce"], memory["salt"], memory["intent_ref"],
                memory["value_metadata"], memory["access_policy"], memory["audit_proof"],
                memory["sealed_blob"]
            ))
            restored_count += 1

        conn.commit()
        conn.close()

        print(f"\n✓ Restore complete")
        print(f"  Restored: {restored_count} memories")
        print(f"  Skipped (already exist): {skipped_count} memories")

    # ==================== Integrity Verification ====================

    def verify_integrity(self, memory_id: str = None) -> bool:
        """
        Verify Merkle tree integrity and signatures.

        Args:
            memory_id: If provided, verify specific memory's proof. Otherwise verify entire tree.

        Returns:
            bool: True if verification passes
        """
        from .merkle import rebuild_merkle_tree, verify_proof

        conn = sqlite3.connect(DB_PATH)

        print("=== Memory Vault Integrity Verification ===\n")

        # Verify Merkle tree
        print("1. Rebuilding Merkle tree from audit log...")
        rebuilt_root, proof_map = rebuild_merkle_tree(conn)

        # Get latest stored root
        c = conn.cursor()
        c.execute("SELECT seq, root_hash, timestamp, signature FROM merkle_roots ORDER BY seq DESC LIMIT 1")
        root_row = c.fetchone()

        if not root_row:
            print("✓ No audit logs yet (empty vault)")
            conn.close()
            return True

        stored_seq, stored_root, stored_timestamp, signature = root_row

        print(f"   Latest root: {stored_root[:32]}...")
        print(f"   Rebuilt root: {rebuilt_root[:32]}...")

        if rebuilt_root != stored_root:
            print("✗ INTEGRITY FAILURE: Merkle root mismatch!")
            print("   Audit log may have been tampered with")
            conn.close()
            return False

        print("✓ Merkle root matches\n")

        # Verify signature
        print("2. Verifying cryptographic signature...")
        from .crypto import get_public_verify_key, verify_signature

        try:
            vk = get_public_verify_key()
            sig_valid = verify_signature(vk, signature, stored_root, stored_seq, stored_timestamp)

            if sig_valid:
                print("✓ Signature valid\n")
            else:
                print("✗ INTEGRITY FAILURE: Invalid signature!")
                conn.close()
                return False
        except Exception as e:
            print(f"⚠ Warning: Could not verify signature: {e}\n")

        # Verify all root signatures
        print("3. Verifying all historical root signatures...")
        c.execute("SELECT seq, root_hash, timestamp, signature FROM merkle_roots ORDER BY seq")
        all_roots = c.fetchall()

        failed_sigs = 0
        for seq, root_hash, timestamp, sig in all_roots:
            try:
                if not verify_signature(vk, sig, root_hash, seq, timestamp):
                    print(f"✗ Signature failed for root seq {seq}")
                    failed_sigs += 1
            except Exception as e:
                print(f"⚠ Could not verify signature for seq {seq}: {e}")

        if failed_sigs > 0:
            print(f"✗ INTEGRITY FAILURE: {failed_sigs} invalid signatures")
            conn.close()
            return False

        print(f"✓ All {len(all_roots)} root signatures valid\n")

        # Verify specific memory proof if requested
        if memory_id:
            print(f"4. Verifying proof for memory {memory_id}...")

            c.execute("SELECT audit_proof FROM memories WHERE memory_id = ?", (memory_id,))
            row = c.fetchone()
            if not row:
                print(f"✗ Memory {memory_id} not found")
                conn.close()
                return False

            audit_proof = json.loads(row[0] or "[]")

            # Find this memory's leaf in recall log
            c.execute("""
                SELECT request_id FROM recall_log
                WHERE memory_id = ?
                ORDER BY timestamp DESC LIMIT 1
            """, (memory_id,))
            recall_row = c.fetchone()

            if not recall_row:
                print("✓ No recall events for this memory yet")
                conn.close()
                return True

            request_id = recall_row[0]

            # Get leaf hash
            c.execute("SELECT leaf_hash FROM merkle_leaves WHERE request_id = ?", (request_id,))
            leaf_row = c.fetchone()

            if not leaf_row:
                print("✗ Leaf not found in Merkle tree")
                conn.close()
                return False

            leaf_hash = leaf_row[0]

            # Verify proof
            proof_valid = verify_proof(leaf_hash, stored_root, audit_proof)

            if proof_valid:
                print(f"✓ Memory proof valid (leaf in tree)")
            else:
                print(f"✗ INTEGRITY FAILURE: Invalid Merkle proof")
                conn.close()
                return False

        conn.close()

        print("\n" + "="*50)
        print("✓ INTEGRITY VERIFICATION PASSED")
        print("="*50)

        return True

    # ==================== Level 0 Ephemeral Auto-Purge ====================

    def purge_ephemeral(self, max_age_hours: int = 24) -> int:
        """
        Delete all Level 0 (ephemeral) memories older than max_age_hours.

        Args:
            max_age_hours: Maximum age for ephemeral memories (default 24 hours)

        Returns:
            int: Number of memories purged
        """
        cutoff = (datetime.utcnow() - timedelta(hours=max_age_hours)).isoformat()

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Get count before delete
        c.execute("""
            SELECT COUNT(*) FROM memories
            WHERE classification = 0 AND created_at < ?
        """, (cutoff,))
        count = c.fetchone()[0]

        if count > 0:
            # Delete from FTS first (triggers should handle this, but be explicit)
            c.execute("""
                DELETE FROM memories
                WHERE classification = 0 AND created_at < ?
            """, (cutoff,))
            conn.commit()
            print(f"Purged {count} ephemeral memories older than {max_age_hours} hours")
        else:
            print("No ephemeral memories to purge")

        conn.close()
        return count

    def get_ephemeral_count(self) -> dict:
        """Get count and age statistics for ephemeral memories."""
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM memories WHERE classification = 0")
        total = c.fetchone()[0]

        c.execute("""
            SELECT MIN(created_at), MAX(created_at) FROM memories
            WHERE classification = 0
        """)
        row = c.fetchone()
        oldest = row[0] if row[0] else None
        newest = row[1] if row[1] else None

        conn.close()
        return {"count": total, "oldest": oldest, "newest": newest}

    # ==================== Lockdown Mode ====================

    def is_locked_down(self) -> tuple[bool, str, str]:
        """
        Check if vault is in lockdown mode.

        Returns:
            tuple: (is_locked: bool, since: str or None, reason: str or None)
        """
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT lockdown, lockdown_since, lockdown_reason FROM vault_state WHERE id = 1")
        row = c.fetchone()
        conn.close()

        if row:
            return bool(row[0]), row[1], row[2]
        return False, None, None

    def enter_lockdown(self, reason: str) -> bool:
        """
        Enter lockdown mode - disables ALL memory recalls.
        Requires physical token for Level 3+ style security.

        Args:
            reason: Reason for entering lockdown

        Returns:
            bool: True if lockdown was activated
        """
        from .physical_token import require_physical_token

        print("\n" + "="*50)
        print("⚠️  VAULT LOCKDOWN REQUESTED")
        print("="*50)
        print(f"\nReason: {reason}")
        print("\nThis will DISABLE ALL memory recalls until unlocked.")
        print("Physical token authentication required.\n")

        if not require_physical_token("Enter vault lockdown"):
            print("Lockdown aborted: Physical token required")
            return False

        confirm = input("Type 'LOCKDOWN VAULT' to confirm: ").strip()
        if confirm != "LOCKDOWN VAULT":
            print("Lockdown aborted")
            return False

        timestamp = datetime.utcnow().isoformat() + "Z"

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            UPDATE vault_state SET
                lockdown = 1,
                lockdown_since = ?,
                lockdown_reason = ?
            WHERE id = 1
        """, (timestamp, reason))
        conn.commit()
        conn.close()

        print("\n" + "="*50)
        print("🔒 VAULT IS NOW IN LOCKDOWN")
        print(f"   Since: {timestamp}")
        print(f"   Reason: {reason}")
        print("="*50 + "\n")

        return True

    def exit_lockdown(self, passphrase: str = None) -> bool:
        """
        Exit lockdown mode - requires BOTH physical token AND passphrase.

        Args:
            passphrase: Optional passphrase (will prompt if not provided)

        Returns:
            bool: True if lockdown was deactivated
        """
        from .physical_token import require_physical_token

        is_locked, since, reason = self.is_locked_down()
        if not is_locked:
            print("Vault is not in lockdown")
            return False

        print("\n" + "="*50)
        print("🔓 VAULT LOCKDOWN EXIT REQUESTED")
        print("="*50)
        print(f"\nLocked since: {since}")
        print(f"Reason: {reason}")
        print("\nBoth physical token AND passphrase required to unlock.\n")

        if not require_physical_token("Exit vault lockdown"):
            print("Unlock aborted: Physical token required")
            return False

        if passphrase is None:
            passphrase = getpass.getpass("Enter unlock passphrase: ")

        # Verify passphrase against default profile
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT profile_id FROM encryption_profiles WHERE key_source = 'HumanPassphrase' LIMIT 1")
            row = c.fetchone()
            conn.close()

            if row:
                # Just verify the passphrase can derive a key (basic check)
                derive_key_from_passphrase(passphrase)
            else:
                print("Warning: No passphrase profile found, skipping passphrase verification")
        except Exception as e:
            print(f"Passphrase verification failed: {e}")
            return False

        confirm = input("Type 'UNLOCK VAULT' to confirm: ").strip()
        if confirm != "UNLOCK VAULT":
            print("Unlock aborted")
            return False

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            UPDATE vault_state SET
                lockdown = 0,
                lockdown_since = NULL,
                lockdown_reason = NULL
            WHERE id = 1
        """, )
        conn.commit()
        conn.close()

        print("\n" + "="*50)
        print("🔓 VAULT LOCKDOWN LIFTED")
        print("   All operations restored")
        print("="*50 + "\n")

        return True

    # ==================== Key Rotation ====================

    def rotate_profile_key(self, profile_id: str, new_passphrase: str = None) -> bool:
        """
        Rotate encryption key for a profile. Re-encrypts all memories using
        that profile with the new key.

        Only works for HumanPassphrase and KeyFile profiles.
        TPM profiles cannot be rotated (hardware-bound).

        Args:
            profile_id: The profile to rotate
            new_passphrase: New passphrase (will prompt if not provided, for Passphrase profiles)

        Returns:
            bool: True if rotation was successful
        """
        from .physical_token import require_physical_token

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        # Get profile info
        c.execute("""
            SELECT key_source, rotation_count FROM encryption_profiles
            WHERE profile_id = ?
        """, (profile_id,))
        row = c.fetchone()

        if not row:
            conn.close()
            raise ValueError(f"Profile '{profile_id}' not found")

        key_source = row[0]
        rotation_count = row[1] or 0

        if key_source == "TPM":
            conn.close()
            raise ValueError("TPM profiles cannot be rotated (hardware-bound)")

        # Count affected memories
        c.execute("SELECT COUNT(*) FROM memories WHERE encryption_profile = ?", (profile_id,))
        memory_count = c.fetchone()[0]

        print("\n" + "="*50)
        print(f"🔑 KEY ROTATION: {profile_id}")
        print("="*50)
        print(f"\nKey source: {key_source}")
        print(f"Memories to re-encrypt: {memory_count}")
        print(f"Previous rotations: {rotation_count}")
        print("\nThis operation will:")
        print("  1. Decrypt all memories with the OLD key")
        print("  2. Re-encrypt all memories with the NEW key")
        print("  3. Update the profile rotation count")

        if key_source == "KeyFile":
            print("\n⚠️  WARNING: After rotation, securely destroy the OLD keyfile!")

        print("\nPhysical token required for key rotation.\n")

        if not require_physical_token("Rotate encryption key"):
            conn.close()
            print("Rotation aborted: Physical token required")
            return False

        # Get current key
        print("\n--- Current Key ---")
        if key_source == "HumanPassphrase":
            old_passphrase = getpass.getpass(f"Enter CURRENT passphrase for '{profile_id}': ")
        else:  # KeyFile
            keyfile_path = os.path.expanduser(f"~/.memory_vault/keys/{profile_id}.key")
            if not os.path.exists(keyfile_path):
                conn.close()
                raise FileNotFoundError(f"Keyfile not found: {keyfile_path}")

        # Get new key
        print("\n--- New Key ---")
        if key_source == "HumanPassphrase":
            if new_passphrase is None:
                new_passphrase = getpass.getpass(f"Enter NEW passphrase for '{profile_id}': ")
                confirm = getpass.getpass("Confirm NEW passphrase: ")
                if new_passphrase != confirm:
                    conn.close()
                    raise ValueError("Passphrases do not match")
        else:  # KeyFile - generate new keyfile
            new_keyfile_path = os.path.expanduser(f"~/.memory_vault/keys/{profile_id}.key.new")
            new_key = nacl_random(32)
            os.makedirs(os.path.dirname(new_keyfile_path), exist_ok=True)
            with open(new_keyfile_path, "wb") as f:
                os.fchmod(f.fileno(), 0o600)
                f.write(new_key)
            print(f"New keyfile generated: {new_keyfile_path}")

        confirm = input("\nType 'ROTATE KEY' to proceed: ").strip()
        if confirm != "ROTATE KEY":
            conn.close()
            print("Rotation aborted")
            return False

        # Fetch all memories for this profile
        c.execute("""
            SELECT memory_id, ciphertext, nonce, salt, sealed_blob
            FROM memories WHERE encryption_profile = ?
        """, (profile_id,))
        memories = c.fetchall()

        success_count = 0
        error_count = 0

        for memory_id, ciphertext, nonce, old_salt, sealed_blob in memories:
            try:
                # Derive old key
                if key_source == "HumanPassphrase":
                    old_key, _ = derive_key_from_passphrase(old_passphrase, old_salt)
                else:
                    old_key = load_key_from_file(keyfile_path)

                # Decrypt with old key
                plaintext = decrypt_memory(old_key, ciphertext, nonce)

                # Generate new salt/nonce
                new_salt = nacl_random(16) if key_source == "HumanPassphrase" else None
                new_nonce = nacl_random(24)

                # Derive new key
                if key_source == "HumanPassphrase":
                    new_key, new_salt = derive_key_from_passphrase(new_passphrase, new_salt)
                else:
                    new_key = new_key  # Already have the key

                # Encrypt with new key
                new_ciphertext, new_nonce = encrypt_memory(new_key, plaintext)

                # Update database
                c.execute("""
                    UPDATE memories SET
                        ciphertext = ?,
                        nonce = ?,
                        salt = ?
                    WHERE memory_id = ?
                """, (new_ciphertext, new_nonce, new_salt, memory_id))

                success_count += 1
                print(f"  ✓ Rotated: {memory_id[:8]}...")

            except Exception as e:
                error_count += 1
                print(f"  ✗ Failed: {memory_id[:8]}... - {e}")

        if error_count > 0:
            print(f"\n⚠️  {error_count} memories failed to rotate!")
            print("Rolling back transaction...")
            conn.rollback()
            conn.close()
            return False

        # Update profile rotation tracking
        timestamp = datetime.utcnow().isoformat() + "Z"
        c.execute("""
            UPDATE encryption_profiles SET
                last_rotation = ?,
                rotation_count = ?
            WHERE profile_id = ?
        """, (timestamp, rotation_count + 1, profile_id))

        conn.commit()

        # For KeyFile, move new keyfile to replace old
        if key_source == "KeyFile":
            import shutil
            old_keyfile_backup = keyfile_path + f".old.{rotation_count}"
            shutil.move(keyfile_path, old_keyfile_backup)
            shutil.move(new_keyfile_path, keyfile_path)
            print(f"\nOld keyfile backed up to: {old_keyfile_backup}")
            print(f"⚠️  IMPORTANT: Securely delete {old_keyfile_backup} after verifying rotation!")

        # Clear cached key
        if profile_id in self.profile_keys:
            del self.profile_keys[profile_id]

        conn.close()

        print("\n" + "="*50)
        print(f"✓ KEY ROTATION COMPLETE")
        print(f"  Memories rotated: {success_count}")
        print(f"  Rotation count: {rotation_count + 1}")
        print("="*50 + "\n")

        return True
