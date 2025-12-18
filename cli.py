#!/usr/bin/env python3
import argparse
import json
from memory_vault.vault import MemoryVault
from memory_vault.models import MemoryObject
from datetime import datetime

def main():
    parser = argparse.ArgumentParser(description="Memory Vault CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Profile management
    p_create = subparsers.add_parser("create-profile", help="Create a new encryption profile")
    p_create.add_argument("profile_id", help="Unique profile name")
    p_create.add_argument("--key-source", default="HumanPassphrase", choices=["HumanPassphrase", "KeyFile", "TPM"])
    p_create.add_argument("--generate-keyfile", action="store_true", help="Auto-generate keyfile for KeyFile profiles")
    p_create.add_argument("--exportable", action="store_true")

    p_list = subparsers.add_parser("list-profiles", help="List all profiles")

    # Memory operations
    p_store = subparsers.add_parser("store", help="Store a memory")
    p_store.add_argument("--id", help="Memory ID (optional)")
    p_store.add_argument("--content", required=True, help="Content to store")
    p_store.add_argument("--classification", type=int, default=1, choices=range(0,6))
    p_store.add_argument("--profile", default="default-passphrase", help="Encryption profile")
    p_store.add_argument("--cooldown", type=int, default=0, help="Cooldown seconds")

    p_recall = subparsers.add_parser("recall", help="Recall a memory")
    p_recall.add_argument("memory_id", help="Memory ID to recall")
    p_recall.add_argument("--justification", default="", help="Reason for recall")

    args = parser.parse_args()
    vault = MemoryVault()

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
        obj = MemoryObject(
            memory_id=args.id,
            content_plaintext=args.content.encode('utf-8'),
            classification=args.classification,
            encryption_profile=args.profile,
            access_policy={"cooldown_seconds": args.cooldown}
        )
        vault.store_memory(obj)

    elif args.command == "recall":
        try:
            plaintext = vault.recall_memory(args.memory_id, justification=args.justification)
            print("Decrypted content:")
            print(plaintext.decode('utf-8'))
        except Exception as e:
            print(f"Recall failed: {e}")

if __name__ == "__main__":
    main()
