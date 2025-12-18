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
from memory_vault.deadman import (
    init_deadman_switch,
    arm_deadman_switch,
    checkin_deadman_switch,
    disarm_deadman_switch,
    is_deadman_triggered,
    get_payload_memory_ids,
    add_heir,
    list_heirs,
    encrypt_payload_for_heirs,
    get_heir_release_packages
)

DB_PATH = os.path.expanduser("~/.memory_vault/vault.db")


def main():
    parser = argparse.ArgumentParser(description="Memory Vault CLI - Sovereign Cognitive Fortress")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- Profile Management ---
    p_create = subparsers.add_parser("create-profile", help="Create encryption profile")
    p_create.add_argument("profile_id")
    p_create.add_argument("--key-source", default="HumanPassphrase", choices=["HumanPassphrase", "KeyFile", "TPM"])
    p_create.add_argument("--generate-keyfile", action="store_true")
    p_create.add_argument("--exportable", action="store_true")

    p_list = subparsers.add_parser("list-profiles", help="List profiles")

    # --- Memory Operations ---
    p_store = subparsers.add_parser("store", help="Store memory")
    p_store.add_argument("--id", help="Memory ID (optional)")
    p_store.add_argument("--content", required=True)
    p_store.add_argument("--classification", type=int, default=1, choices=range(0,6))
    p_store.add_argument("--profile", default="default-passphrase")
    p_store.add_argument("--cooldown", type=int, default=0)
    p_store.add_argument("--metadata", default="{}")

    p_recall = subparsers.add_parser("recall", help="Recall memory")
    p_recall.add_argument("memory_id")
    p_recall.add_argument("--justification", default="")

    # --- Search ---
    p_search_meta = subparsers.add_parser("search-metadata", help="Search metadata")
    p_search_meta.add_argument("query")
    p_search_meta.add_argument("--limit", type=int, default=20)

    p_search_just = subparsers.add_parser("search-justifications", help="Search justifications")
    p_search_just.add_argument("query")
    p_search_just.add_argument("--limit", type=int, default=20)

    # --- Backup & Restore ---
    p_backup = subparsers.add_parser("backup", help="Create backup")
    p_backup.add_argument("output_file")
    p_backup.add_argument("--incremental", action="store_true")
    p_backup.add_argument("--description", default="")
    p_backup.add_argument("--passphrase-file")

    p_list_backups = subparsers.add_parser("list-backups", help="List backup history")

    # --- Integrity ---
    p_verify = subparsers.add_parser("verify-integrity", help="Verify audit trail")
    p_verify.add_argument("--memory-id", help="Verify specific memory proof")

    # --- Dead-Man Switch ---
    p_dms_arm = subparsers.add_parser("dms-arm", help="Arm dead-man switch")
    p_dms_arm.add_argument("days", type=int)
    p_dms_arm.add_argument("--memory-ids", required=True, help="Comma-separated memory IDs")
    p_dms_arm.add_argument("--justification", required=True)

    p_dms_checkin = subparsers.add_parser("dms-checkin", help="Check in (prove aliveness)")

    p_dms_status = subparsers.add_parser("dms-status", help="Show DMS status")

    p_dms_disarm = subparsers.add_parser("dms-disarm", help="Disarm dead-man switch")

    p_dms_heir_add = subparsers.add_parser("dms-heir-add", help="Add heir (public key)")
    p_dms_heir_add.add_argument("name")
    p_dms_heir_add.add_argument("public_key_b64")

    p_dms_heir_list = subparsers.add_parser("dms-heir-list", help="List heirs")

    p_dms_encrypt = subparsers.add_parser("dms-encrypt-payload", help="Encrypt payload for heirs")

    p_dms_release = subparsers.add_parser("dms-release-packages", help="Export release packages (triggered)")

    args = parser.parse_args()
    vault = MemoryVault()
    init_deadman_switch()  # Ensure tables exist

    def get_passphrase(prompt="Passphrase: "):
        if getattr(args, "passphrase_file", None):
            with open(args.passphrase_file, "r") as f:
                return f.read().strip()
        return getpass.getpass(prompt)

    # ==================== Command Execution ====================

    if args.command == "create-profile":
        vault.create_profile(
            profile_id=args.profile_id,
            key_source=args.key_source,
            exportable=args.exportable,
            generate_keyfile=args.generate_keyfile
        )

    elif args.command == "list-profiles":
        print(json.dumps(vault.list_profiles(), indent=2))

    elif args.command == "store":
        try:
            metadata = json.loads(args.metadata)
        except json.JSONDecodeError as e:
            print(f"Invalid metadata JSON: {e}")
            sys.exit(1)
        obj = MemoryObject(
            memory_id=args.id,
            content_plaintext=args.content.encode(),
            classification=args.classification,
            encryption_profile=args.profile,
            access_policy={"cooldown_seconds": args.cooldown},
            value_metadata=metadata
        )
        vault.store_memory(obj)

    elif args.command == "recall":
        try:
            plain = vault.recall_memory(args.memory_id, justification=args.justification)
            print("\n=== DECRYPTED CONTENT ===")
            print(plain.decode('utf-8', errors='replace'))
            print("=========================\n")
        except Exception as e:
            print(f"Recall failed: {e}")

    elif args.command == "search-metadata":
        results = search_memories_metadata(args.query, args.limit)
        for r in results:
            print(f"{r['memory_id']} (Level {r['classification']}): {r['preview']}\n")

    elif args.command == "search-justifications":
        results = search_recall_justifications(args.query, args.limit)
        for r in results:
            status = "APPROVED" if r['approved'] else "DENIED"
            ts = datetime.fromisoformat(r['timestamp'].rstrip("Z") + "+00:00").strftime("%Y-%m-%d %H:%M")
            print(f"{ts} | {status} | {r['memory_id']}: {r['preview']}\n")

    # Backup/restore and verify-integrity commands remain as previously implemented...

    elif args.command == "dms-arm":
        ids = [i.strip() for i in args.memory_ids.split(",")]
        arm_deadman_switch(args.days, ids, args.justification)

    elif args.command == "dms-checkin":
        checkin_deadman_switch()

    elif args.command == "dms-status":
        triggered = is_deadman_triggered()
        print(f"Dead-man switch: {'TRIGGERED' if triggered else 'Armed/Safe'}")
        if triggered:
            ids = get_payload_memory_ids()
            print(f"Payload ready for release: {len(ids)} memories")

    elif args.command == "dms-disarm":
        disarm_deadman_switch()

    elif args.command == "dms-heir-add":
        add_heir(args.name, args.public_key_b64)

    elif args.command == "dms-heir-list":
        for h in list_heirs():
            print(f"{h['name']}: {h['public_key'][:32]}...")

    elif args.command == "dms-encrypt-payload":
        encrypt_payload_for_heirs(vault)

    elif args.command == "dms-release-packages":
        packages = get_heir_release_packages()
        if not packages:
            print("No release packages")
        else:
            for pkg in packages:
                filename = f"dms-release-{pkg['heir'].lower().replace(' ', '_')}.json"
                with open(filename, "w") as f:
                    json.dump(pkg, f, indent=2)
                print(f"Package for {pkg['heir']} → {filename}")

if __name__ == "__main__":
    main()
