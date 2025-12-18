#!/usr/bin/env python3
import argparse
import json
import sys
import os
import getpass
from datetime import datetime

from memory_vault.vault import MemoryVault
from memory_vault.models import MemoryObject
from memory_vault.db import search_memories_metadata, search_recall_justifications
from memory_vault.crypto import derive_key_from_passphrase, encrypt_memory, decrypt_memory
import sqlite3


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


def main():
    parser = argparse.ArgumentParser(description="Memory Vault CLI - Secure cognitive artifact storage")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- Profile Management ---
    p_create = subparsers.add_parser("create-profile", help="Create a new encryption profile")
    p_create.add_argument("profile_id", help="Unique profile name")
    p_create.add_argument("--key-source", default="HumanPassphrase",
                          choices=["HumanPassphrase", "KeyFile", "TPM"])
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
    p_search_meta = subparsers.add_parser("search-metadata", help="Search memory metadata")
    p_search_meta.add_argument("query")
    p_search_meta.add_argument("--limit", type=int, default=20)

    p_search_just = subparsers.add_parser("search-justifications", help="Search recall justifications")
    p_search_just.add_argument("query")
    p_search_just.add_argument("--limit", type=int, default=20)

    # --- Backup / Export ---
    p_backup = subparsers.add_parser("backup", help="Create encrypted full backup")
    p_backup.add_argument("output_file", help="Path to save backup (e.g., vault-backup.json)")
    p_backup.add_argument("--passphrase-file", help="Read passphrase from file instead of prompt")

    p_export = subparsers.add_parser("export", help="Export memories (filtered) to encrypted JSON")
    p_export.add_argument("output_file")
    p_export.add_argument("--classification-min", type=int, help="Min classification to include")
    p_export.add_argument("--classification-max", type=int, help="Max classification to include")
    p_export.add_argument("--profile", help="Only include memories from this profile")
    p_export.add_argument("--passphrase-file", help="Read passphrase from file")

    p_restore = subparsers.add_parser("restore", help="Restore from encrypted backup (DANGEROUS - overwrites current vault)")
    p_restore.add_argument("backup_file")
    p_restore.add_argument("--passphrase-file", help="Read passphrase from file")
    p_restore.add_argument("--dry-run", action="store_true", help="Show what would be restored without writing")

    args = parser.parse_args()
    vault = MemoryVault()

    # Helper to get passphrase
    def get_backup_passphrase():
        if getattr(args, "passphrase_file", None):
            with open(args.passphrase_file, "r") as f:
                return f.read().strip()
        return getpass.getpass("Backup passphrase: ")

    if args.command == "create-profile":
        vault.create_profile(
            profile_id=args.profile_id,
            key_source=args.key_source,
            exportable=args.exportable,
            generate_keyfile=args.generate_keyfile and args.key_source == "KeyFile"
        )

    elif args.command == "list-profiles":
        profiles = vault.list_profiles()
        print(json.dumps(profiles, indent=2))

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
        if not results:
            print("No matches.")
        else:
            print(f"{len(results)} memories found:\n")
            for r in results:
                print(f"ID: {r['memory_id']} | Level: {r['classification']}")
                print(f"Preview: {r['preview']}\n")

    elif args.command == "search-justifications":
        results = search_recall_justifications(args.query, limit=args.limit)
        if not results:
            print("No matches.")
        else:
            print(f"{len(results)} recall attempts found:\n")
            for r in results:
                status = "APPROVED" if r['approved'] else "DENIED"
                ts = datetime.fromisoformat(r['timestamp'].rstrip("Z") + "+00:00").strftime("%Y-%m-%d %H:%M")
                print(f"{ts} | {status} | Memory: {r['memory_id']}")
                print(f"Justification preview: {r['preview']}\n")

    elif args.command in ["backup", "export"]:
        passphrase = get_backup_passphrase()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        query = "SELECT * FROM memories"
        params = []
        if args.command == "export":
            conditions = []
            if args.classification_min is not None:
                conditions.append("classification >= ?")
                params.append(args.classification_min)
            if args.classification_max is not None:
                conditions.append("classification <= ?")
                params.append(args.classification_max)
            if args.profile:
                conditions.append("encryption_profile = ?")
                params.append(args.profile)
            if conditions:
                query += " WHERE " + " AND ".join(conditions)

        c.execute(query, params)
        rows = c.fetchall()
        columns = [desc[0] for desc in c.description]

        memories = []
        for row in rows:
            mem = dict(zip(columns, row))
            profile_id = mem["encryption_profile"]
            c.execute("SELECT exportable FROM encryption_profiles WHERE profile_id = ?", (profile_id,))
            exportable = c.fetchone()[0] if c.fetchone() else 0

            if not exportable:
                # Zero out sensitive fields for non-exportable profiles (e.g., TPM)
                mem["ciphertext"] = None
                mem["nonce"] = None
                mem["salt"] = None
                mem["sealed_blob"] = None

            # Convert BLOBs to hex
            for k in ["ciphertext", "nonce", "salt", "sealed_blob"]:
                if mem[k] is not None:
                    mem[k] = mem[k].hex() if isinstance(mem[k], (bytes, bytearray)) else mem[k]
            memories.append(mem)

        backup_obj = {
            "exported_at": datetime.utcnow().isoformat() + "Z",
            "memory_count": len(memories),
            "memories": memories
        }

        backup_json = json.dumps(backup_obj, indent=2).encode('utf-8')
        encrypted_backup = encrypt_backup(backup_json, passphrase)

        with open(args.output_file, "w") as f:
            json.dump(encrypted_backup, f, indent=2)

        print(f"Backup/export written to {args.output_file} ({len(memories)} memories)")

    elif args.command == "restore":
        if not args.dry_run:
            confirm = input("WARNING: This will OVERWRITE your current vault. Type 'RESTORE' to continue: ")
            if confirm != "RESTORE":
                print("Restore aborted.")
                sys.exit(0)

        passphrase = get_backup_passphrase()
        with open(args.backup_file, "r") as f:
            encrypted_data = json.load(f)

        try:
            decrypted_json = decrypt_backup(encrypted_data, passphrase)
            backup_obj = json.loads(decrypted_json)
        except Exception as e:
            print(f"Decryption failed: {e}")
            sys.exit(1)

        print(f"Restore file valid. Contains {backup_obj.get('memory_count', 0)} memories.")
        if args.dry_run:
            print("Dry run complete.")
            sys.exit(0)

        # Simple full replace (drop and recreate memories)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM memories")
        c.execute("DELETE FROM recall_log")
        c.execute("VACUUM")
        conn.commit()
        conn.close()

        # Re-init to ensure structure
        from memory_vault.db import init_db
        init_db()

        print("Vault cleared. Restoring memories...")
        for mem in backup_obj["memories"]:
            # Re-insert (skip non-exportable ciphertext if null)
            if mem["ciphertext"] is None:
                print(f"Skipping non-exportable memory {mem['memory_id']}")
                continue
            # Convert hex back to bytes
            for k in ["ciphertext", "nonce", "salt", "sealed_blob"]:
                if mem[k] is not None:
                    mem[k] = bytes.fromhex(mem[k])

            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('''
                INSERT INTO memories VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                mem["memory_id"],
                mem["created_at"],
                mem["created_by"],
                mem["classification"],
                mem["encryption_profile"],
                mem["content_hash"],
                mem["ciphertext"],
                mem["nonce"],
                mem["salt"],
                mem["intent_ref"],
                mem["value_metadata"],
                mem["access_policy"],
                mem["audit_proof"],
                mem["sealed_blob"]
            ))
            conn.commit()
            conn.close()

        print(f"Restore complete. {len(backup_obj['memories'])} memories processed.")

if __name__ == "__main__":
    main()
