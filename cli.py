
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
import uuid

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
    parser = argparse.ArgumentParser(description="Memory Vault CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ... [previous commands unchanged: create-profile, list-profiles, store, recall, search-metadata, search-justifications] ...

    # --- Backup / Export / Restore ---
    p_backup = subparsers.add_parser("backup", help="Create encrypted backup")
    p_backup.add_argument("output_file", help="Output file path")
    p_backup.add_argument("--incremental", action="store_true", help="Create incremental backup (only changes since last backup)")
    p_backup.add_argument("--description", default="", help="Description for this backup")
    p_backup.add_argument("--passphrase-file", help="Read passphrase from file")

    p_export = subparsers.add_parser("export", help="Export filtered memories (one-time, no tracking)")
    p_export.add_argument("output_file")
    p_export.add_argument("--classification-min", type=int)
    p_export.add_argument("--classification-max", type=int)
    p_export.add_argument("--profile")
    p_export.add_argument("--passphrase-file")

    p_restore = subparsers.add_parser("restore", help="Restore from backup (full + incremental chain)")
    p_restore.add_argument("backup_file", nargs="+", help="One or more backup files (full first, then incrementals)")
    p_restore.add_argument("--passphrase-file", help="Read passphrase from file")
    p_restore.add_argument("--dry-run", action="store_true")

    p_list_backups = subparsers.add_parser("list-backups", help="List backup history")
    
    # ... [parse args] ...
    args = parser.parse_args()
    vault = MemoryVault()

    def get_backup_passphrase():
        if getattr(args, "passphrase_file", None):
            with open(args.passphrase_file, "r") as f:
                return f.read().strip()
        return getpass.getpass("Backup passphrase: ")

    if args.command == "backup":
        passphrase = get_backup_passphrase()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        backup_id = str(uuid.uuid4())
        last_ts = get_last_backup_timestamp(conn) if args.incremental else None

        query = "SELECT * FROM memories"
        params = []
        if args.incremental and last_ts:
            query += " WHERE created_at > ?"
            params.append(last_ts)

        c.execute(query, params)
        rows = c.fetchall()
        columns = [desc[0] for desc in c.description]

        memories = []
        for row in rows:
            mem = dict(zip(columns, row))
            profile_id = mem["encryption_profile"]
            c.execute("SELECT exportable FROM encryption_profiles WHERE profile_id = ?", (profile_id,))
            exportable = bool(c.fetchone()[0])

            if not exportable:
                mem["ciphertext"] = mem["nonce"] = mem["salt"] = mem["sealed_blob"] = None

            for k in ["ciphertext", "nonce", "salt", "sealed_blob"]:
                if mem[k] is not None:
                    mem[k] = mem[k].hex() if isinstance(mem[k], (bytes, bytearray)) else mem[k]
            memories.append(mem)

        backup_obj = {
            "backup_id": backup_id,
            "type": "incremental" if args.incremental else "full",
            "parent_backup_id": None,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "memory_count": len(memories),
            "description": args.description,
            "memories": memories
        }

        if args.incremental and last_ts:
            # Find parent
            c.execute("SELECT backup_id FROM backups ORDER BY timestamp DESC LIMIT 1")
            parent_row = c.fetchone()
            if parent_row:
                backup_obj["parent_backup_id"] = parent_row[0]

        backup_json = json.dumps(backup_obj, indent=2).encode('utf-8')
        encrypted = encrypt_backup(backup_json, passphrase)

        with open(args.output_file, "w") as f:
            json.dump(encrypted, f, indent=2)

        register_backup(conn, backup_id, backup_obj["type"], backup_obj.get("parent_backup_id"), len(memories), args.description)
        conn.close()

        btype = "incremental" if args.incremental else "full"
        print(f"{btype.capitalize()} backup created: {args.output_file} ({len(memories)} memories)")

    elif args.command == "list-backups":
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT backup_id, timestamp, type, parent_backup_id, memory_count, description FROM backups ORDER BY timestamp")
        rows = c.fetchall()
        if not rows:
            print("No backups recorded.")
        else:
            print("Backup history:")
            for r in rows:
                ts = datetime.fromisoformat(r[1].rstrip("Z") + "+00:00").strftime("%Y-%m-%d %H:%M:%S")
                parent = f" (parent: {r[3][:8]}...)" if r[3] else ""
                desc = f" — {r[5]}" if r[5] else ""
                print(f"  {ts} | {r[2]:10} | {r[4]:4} memories | {r[0]}{parent}{desc}")
        conn.close()

    elif args.command == "restore":
        if not args.dry_run:
            confirm = input("DANGEROUS: This will overwrite current vault. Type 'RESTORE ALL' to proceed: ")
            if confirm != "RESTORE ALL":
                print("Aborted.")
                sys.exit(0)

        passphrase = get_backup_passphrase()
        all_memories = []

        for file_path in args.backup_file:
            with open(file_path, "r") as f:
                encrypted = json.load(f)
            try:
                decrypted = decrypt_backup(encrypted, passphrase)
                backup_obj = json.loads(decrypted)
            except Exception as e:
                print(f"Failed to decrypt {file_path}: {e}")
                sys.exit(1)

            print(f"Loaded {backup_obj['type']} backup {backup_obj.get('backup_id', 'unknown')} with {len(backup_obj['memories'])} memories")
            all_memories.extend(backup_obj["memories"])

        if args.dry_run:
            print(f"Dry run: Would restore {len(all_memories)} memories total.")
            sys.exit(0)

        # Clear and restore
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("DELETE FROM memories")
        c.execute("DELETE FROM recall_log")
        c.execute("DELETE FROM backups")
        conn.commit()

        restored = 0
        skipped = 0
        for mem in all_memories:
            if mem["ciphertext"] is None:
                skipped += 1
                continue

            for k in ["ciphertext", "nonce", "salt", "sealed_blob"]:
                if mem[k] is not None:
                    mem[k] = bytes.fromhex(mem[k])

            c.execute('''
                INSERT OR REPLACE INTO memories VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                mem["memory_id"], mem["created_at"], mem["created_by"], mem["classification"],
                mem["encryption_profile"], mem["content_hash"], mem["ciphertext"], mem["nonce"],
                mem["salt"], mem["intent_ref"], mem["value_metadata"], mem["access_policy"],
                mem["audit_proof"], mem["sealed_blob"]
            ))
            restored += 1

        conn.commit()
        conn.close()
        print(f"Restore complete: {restored} memories restored, {skipped} skipped (non-exportable)")

    # ... [other commands unchanged] ...

if __name__ == "__main__":
    main()
