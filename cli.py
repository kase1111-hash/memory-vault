#!/usr/bin/env python3
import argparse
import json
import sys
import os
import getpass
import uuid
from datetime import datetime

import sqlite3

from memory_vault.vault import MemoryVault
from memory_vault.models import MemoryObject
from memory_vault.db import search_memories_metadata, search_recall_justifications
from memory_vault.crypto import derive_key_from_passphrase, encrypt_memory, decrypt_memory
from memory_vault.merkle import rebuild_merkle_tree, verify_proof
from memory_vault.crypto import get_public_verify_key, verify_signature

DB_PATH = os.path.expanduser("~/.memory_vault/vault.db")


def encrypt_backup(data: bytes, passphrase: str) -> dict:
    key, salt = derive_key_from_passphrase(passphrase)
    ciphertext, nonce = encrypt_memory(key, data)
    return {
        "format": "memory-vault-backup-v1",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }


def decrypt_backup(backup_data: dict, passphrase: str) -> bytes:
    salt = bytes.fromhex(backup_data["salt"])
    key, _ = derive_key_from_passphrase(passphrase, salt)
    ciphertext = bytes.fromhex(backup_data["ciphertext"])
    nonce = bytes.fromhex(backup_data["nonce"])
    return decrypt_memory(key, ciphertext, nonce)


def get_last_backup_timestamp(conn) -> str | None:
    c = conn.cursor()
    c.execute("SELECT timestamp FROM backups ORDER BY timestamp DESC LIMIT 1")
    row = c.fetchone()
    return row[0] if row else None


def register_backup(conn, backup_id: str, backup_type: str, parent_id: str | None, count: int, description: str = ""):
    c = conn.cursor()
    c.execute('''
        INSERT INTO backups (backup_id, timestamp, type, parent_backup_id, memory_count, description)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (backup_id, datetime.utcnow().isoformat() + "Z", backup_type, parent_id, count, description))
    conn.commit()


def main():
    parser = argparse.ArgumentParser(description="Memory Vault CLI - Sovereign, auditable, hardware-anchored memory")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- Profile Management ---
    p_create = subparsers.add_parser("create-profile", help="Create a new encryption profile")
    p_create.add_argument("profile_id", help="Unique profile name")
    p_create.add_argument("--key-source", default="HumanPassphrase", choices=["HumanPassphrase", "KeyFile", "TPM"])
    p_create.add_argument("--generate-keyfile", action="store_true")
    p_create.add_argument("--exportable", action="store_true")

    p_list = subparsers.add_parser("list-profiles", help="List all encryption profiles")

    # --- Memory Operations ---
    p_store = subparsers.add_parser("store", help="Store a new memory")
    p_store.add_argument("--id", help="Memory ID (optional)")
    p_store.add_argument("--content", required=True, help="Content to store")
    p_store.add_argument("--classification", type=int, default=1, choices=range(0, 6))
    p_store.add_argument("--profile", default="default-passphrase")
    p_store.add_argument("--cooldown", type=int, default=0)
    p_store.add_argument("--metadata", default="{}", help="JSON metadata (searchable)")

    p_recall = subparsers.add_parser("recall", help="Recall a memory")
    p_recall.add_argument("memory_id")
    p_recall.add_argument("--justification", default="")

    # --- Search ---
    p_search_meta = subparsers.add_parser("search-metadata", help="Full-text search memory metadata")
    p_search_meta.add_argument("query")
    p_search_meta.add_argument("--limit", type=int, default=20)

    p_search_just = subparsers.add_parser("search-justifications", help="Full-text search recall justifications")
    p_search_just.add_argument("query")
    p_search_just.add_argument("--limit", type=int, default=20)

    # --- Backup & Restore ---
    p_backup = subparsers.add_parser("backup", help="Create encrypted backup")
    p_backup.add_argument("output_file")
    p_backup.add_argument("--incremental", action="store_true")
    p_backup.add_argument("--description", default="")
    p_backup.add_argument("--passphrase-file")

    p_list_backups = subparsers.add_parser("list-backups", help="List backup history")

    p_restore = subparsers.add_parser("restore", help="Restore from backup(s)")
    p_restore.add_argument("backup_file", nargs="+")
    p_restore.add_argument("--passphrase-file")
    p_restore.add_argument("--dry-run", action="store_true")

    # --- Integrity & Audit ---
    p_verify = subparsers.add_parser("verify-integrity", help="Verify signed Merkle audit trail")
    p_verify.add_argument("--memory-id", help="Also verify proof for specific memory's latest recall")

    args = parser.parse_args()
    vault = MemoryVault()

    def get_passphrase(prompt="Passphrase: "):
        if getattr(args, "passphrase_file", None):
            with open(args.passphrase_file, "r") as f:
                return f.read().strip()
        return getpass.getpass(prompt)

    # ==================== Command Handlers ====================

    if args.command == "create-profile":
        vault.create_profile(
            profile_id=args.profile_id,
            key_source=args.key_source,
            exportable=args.exportable,
            generate_keyfile=args.generate_keyfile and args.key_source == "KeyFile"
        )

    elif args.command == "list-profiles":
        print(json.dumps(vault.list_profiles(), indent=2))

    elif args.command == "store":
        try:
            metadata_dict = json.loads(args.metadata)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON in --metadata: {e}")
            sys.exit(1)
        obj = MemoryObject(
            memory_id=args.id,
            content_plaintext=args.content.encode('utf-8'),
            classification=args.classification,
            encryption_profile=args.profile,
            access_policy={"cooldown_seconds": args.cooldown},
            value_metadata=metadata_dict
        )
        vault.store_memory(obj)

    elif args.command == "recall":
        try:
            plaintext = vault.recall_memory(args.memory_id, justification=args.justification)
            print("\n=== DECRYPTED CONTENT ===")
            print(plaintext.decode('utf-8', errors='replace'))
            print("=========================\n")
        except Exception as e:
            print(f"Recall failed: {e}")

    elif args.command == "search-metadata":
        results = search_memories_metadata(args.query, limit=args.limit)
        print(f"{len(results)} match(es):\n")
        for r in results:
            print(f"ID: {r['memory_id']} | Level: {r['classification']}")
            print(f"Preview: {r['preview']}\n")

    elif args.command == "search-justifications":
        results = search_recall_justifications(args.query, limit=args.limit)
        print(f"{len(results)} recall(s) found:\n")
        for r in results:
            status = "APPROVED" if r['approved'] else "DENIED"
            ts = datetime.fromisoformat(r['timestamp'].rstrip("Z") + "+00:00").strftime("%Y-%m-%d %H:%M")
            print(f"{ts} | {status} | Memory: {r['memory_id']}")
            print(f"Preview: {r['preview']}\n")

    elif args.command == "backup":
        passphrase = get_passphrase("Backup passphrase: ")
        conn = sqlite3.connect(DB_PATH)
        backup_id = str(uuid.uuid4())
        last_ts = get_last_backup_timestamp(conn) if args.incremental else None

        where = " WHERE created_at > ?" if args.incremental and last_ts else ""
        params = [last_ts] if args.incremental and last_ts else []

        c = conn.cursor()
        c.execute(f"SELECT * FROM memories{where}", params)
        rows = c.fetchall()
        columns = [d[0] for d in c.description]
        memories = []
        for row in rows:
            mem = dict(zip(columns, row))
            c.execute("SELECT exportable FROM encryption_profiles WHERE profile_id = ?", (mem["encryption_profile"],))
            exportable = bool(c.fetchone()[0])
            if not exportable:
                for f in ["ciphertext", "nonce", "salt", "sealed_blob"]:
                    mem[f] = None
            for f in ["ciphertext", "nonce", "salt", "sealed_blob"]:
                if mem[f] is not None:
                    mem[f] = mem[f].hex() if isinstance(mem[f], (bytes, bytearray)) else mem[f]
            memories.append(mem)

        backup_obj = {
            "backup_id": backup_id,
            "type": "incremental" if args.incremental else "full",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "memory_count": len(memories),
            "description": args.description,
            "memories": memories
        }
        if args.incremental and last_ts:
            c.execute("SELECT backup_id FROM backups ORDER BY timestamp DESC LIMIT 1")
            parent = c.fetchone()
            if parent:
                backup_obj["parent_backup_id"] = parent[0]

        encrypted = encrypt_backup(json.dumps(backup_obj, indent=2).encode(), passphrase)
        with open(args.output_file, "w") as f:
            json.dump(encrypted, f, indent=2)

        register_backup(conn, backup_id, backup_obj["type"], backup_obj.get("parent_backup_id"), len(memories), args.description)
        conn.close()
        print(f"{'Incremental' if args.incremental else 'Full'} backup saved: {args.output_file} ({len(memories)} memories)")

    elif args.command == "list-backups":
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT backup_id, timestamp, type, parent_backup_id, memory_count, description FROM backups ORDER BY timestamp")
        rows = c.fetchall()
        if not rows:
            print("No backups.")
        else:
            print("Backup history:")
            for r in rows:
                ts = datetime.fromisoformat(r[1].rstrip("Z") + "+00:00").strftime("%Y-%m-%d %H:%M:%S")
                parent = f" ← {r[3][:8]}..." if r[3] else ""
                desc = f" — {r[5]}" if r[5] else ""
                print(f"  {ts} | {r[2]:10} | {r[4]:4} mem | {r[0][:8]}...{parent}{desc}")
        conn.close()

    elif args.command == "restore":
        # ... (unchanged from previous version) ...

    elif args.command == "verify-integrity":
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT seq, root_hash, timestamp, signature FROM merkle_roots ORDER BY seq")
        roots = c.fetchall()
        if not roots:
            print("No audit trail yet.")
            conn.close()
            return

        try:
            vk = get_public_verify_key()
        except Exception as e:
            print(f"Could not load public key: {e}")
            conn.close()
            return

        current_root, _ = rebuild_merkle_tree(conn)
        latest_stored_root = roots[-1][1]

        print("Verifying signed Merkle root chain...\n")
        all_valid = True
        for seq, root, ts, sig in roots:
            valid_sig = verify_signature(vk, sig, root, seq, ts)
            status = "VALID" if valid_sig else "INVALID"
            mark = " (latest)" if root == latest_stored_root else ""
            print(f"Seq {seq:4} | {ts.split('T')[0]} | {status}{mark}")
            if not valid_sig:
                all_valid = False

        if current_root != latest_stored_root:
            print("\nTAMPER DETECTED: Rebuilt root ≠ latest stored root")
            all_valid = False
        elif all_valid:
            print("\nAll signatures valid and audit trail intact.")

        if args.memory_id:
            c.execute("SELECT audit_proof FROM memories WHERE memory_id = ?", (args.memory_id,))
            proof_row = c.fetchone()
            if proof_row and proof_row[0]:
                proof = json.loads(proof_row[0])
                # Get latest recall for this memory
                c.execute('''
                    SELECT rl.request_id, rl.timestamp, rl.approved, rl.justification
                    FROM recall_log rl
                    JOIN merkle_leaves ml ON ml.request_id = rl.request_id
                    WHERE rl.memory_id = ? ORDER BY rl.timestamp DESC LIMIT 1
                ''', (args.memory_id,))
                rec = c.fetchone()
                if rec:
                    entry = f"{rec[0]}|{args.memory_id}|...|{rec[1]}|{rec[2]}|{rec[3] or ''}"
                    leaf = hash_leaf(entry)
                    if verify_proof(leaf, current_root, proof):
                        print(f"\nProof VALID for latest recall of {args.memory_id}")
                    else:
                        print(f"\nProof INVALID for {args.memory_id}")
        conn.close()

if __name__ == "__main__":
    main()
