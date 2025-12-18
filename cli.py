#!/usr/bin/env python3
import argparse
import json
import sys
from datetime import datetime

from memory_vault.vault import MemoryVault
from memory_vault.models import MemoryObject
from memory_vault.db import search_memories_metadata, search_recall_justifications


def main():
    parser = argparse.ArgumentParser(description="Memory Vault CLI - Secure cognitive artifact storage")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- Profile Management ---
    p_create = subparsers.add_parser("create-profile", help="Create a new encryption profile")
    p_create.add_argument("profile_id", help="Unique profile name")
    p_create.add_argument("--key-source", default="HumanPassphrase",
                          choices=["HumanPassphrase", "KeyFile", "TPM"] if hasattr(sys.modules.get("__main__"), "TPM_AVAILABLE") else ["HumanPassphrase", "KeyFile"])
    p_create.add_argument("--generate-keyfile", action="store_true", help="Auto-generate keyfile for KeyFile profiles")
    p_create.add_argument("--exportable", action="store_true")

    p_list = subparsers.add_parser("list-profiles", help="List all encryption profiles")

    # --- Memory Operations ---
    p_store = subparsers.add_parser("store", help="Store a new memory")
    p_store.add_argument("--id", help="Memory ID (optional, auto-generated if omitted)")
    p_store.add_argument("--content", required=True, help="Content to store (string)")
    p_store.add_argument("--classification", type=int, default=1, choices=range(0, 6), help="Security level 0-5")
    p_store.add_argument("--profile", default="default-passphrase", help="Encryption profile to use")
    p_store.add_argument("--cooldown", type=int, default=0, help="Cooldown period in seconds")
    p_store.add_argument("--metadata", default="{}", help="JSON string for value_metadata (searchable)")

    p_recall = subparsers.add_parser("recall", help="Recall (decrypt) a memory")
    p_recall.add_argument("memory_id", help="Memory ID to recall")
    p_recall.add_argument("--justification", default="", help="Justification for recall (logged and searchable)")

    # --- Full-Text Search Commands ---
    p_search_meta = subparsers.add_parser("search-metadata", help="Full-text search in memory value_metadata")
    p_search_meta.add_argument("query", help="FTS5 query (e.g., 'private key', 'seed OR mnemonic', 'recovery -test')")
    p_search_meta.add_argument("--limit", type=int, default=20, help="Max results (default: 20)")

    p_search_just = subparsers.add_parser("search-justifications", help="Full-text search in recall justifications")
    p_search_just.add_argument("query", help="FTS5 query (e.g., 'emergency', 'recovery OR restore')")
    p_search_just.add_argument("--limit", type=int, default=20, help="Max results (default: 20)")

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
        try:
            metadata_dict = json.loads(args.metadata)
        except json.JSONDecodeError:
            print("Error: --metadata must be valid JSON")
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
            print("No memories found matching the query.")
        else:
            print(f"Found {len(results)} matching memories:\n")
            for r in results:
                print(f"ID: {r['memory_id']}")
                print(f"Level: {r['classification']}")
                print(f"Preview: {r['preview']}")
                print("-" * 50)

    elif args.command == "search-justifications":
        results = search_recall_justifications(args.query, limit=args.limit)
        if not results:
            print("No recall attempts found matching the query.")
        else:
            print(f"Found {len(results)} recall attempts:\n")
            for r in results:
                status = "APPROVED" if r['approved'] else "DENIED"
                ts = datetime.fromisoformat(r['timestamp'].replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S")
                print(f"Time: {ts} | {status}")
                print(f"Memory ID: {r['memory_id']}")
                print(f"Request ID: {r['request_id']}")
                print(f"Preview: {r['preview']}")
                print("-" * 60)

if __name__ == "__main__":
    main()
