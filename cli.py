#!/usr/bin/env python3
import argparse
import json
import sys
import getpass
from datetime import datetime

import sqlite3

from memory_vault.vault import MemoryVault
from memory_vault.models import MemoryObject
from memory_vault.db import DB_PATH, search_memories_metadata, search_recall_justifications
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



def main():
    parser = argparse.ArgumentParser(description="Memory Vault CLI - Sovereign Cognitive Fortress")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- Profile Management ---
    p_create = subparsers.add_parser("create-profile", help="Create encryption profile")
    p_create.add_argument("profile_id")
    p_create.add_argument("--key-source", default="HumanPassphrase", choices=["HumanPassphrase", "KeyFile", "TPM"])
    p_create.add_argument("--generate-keyfile", action="store_true")
    p_create.add_argument("--exportable", action="store_true")

    subparsers.add_parser("list-profiles", help="List profiles")

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

    subparsers.add_parser("list-backups", help="List backup history")

    # --- Integrity ---
    p_verify = subparsers.add_parser("verify-integrity", help="Verify audit trail")
    p_verify.add_argument("--memory-id", help="Verify specific memory proof")

    # --- Dead-Man Switch ---
    p_dms_arm = subparsers.add_parser("dms-arm", help="Arm dead-man switch")
    p_dms_arm.add_argument("days", type=int)
    p_dms_arm.add_argument("--memory-ids", required=True, help="Comma-separated memory IDs")
    p_dms_arm.add_argument("--justification", required=True)

    subparsers.add_parser("dms-checkin", help="Check in (prove aliveness)")

    subparsers.add_parser("dms-status", help="Show DMS status")

    subparsers.add_parser("dms-disarm", help="Disarm dead-man switch")

    p_dms_heir_add = subparsers.add_parser("dms-heir-add", help="Add heir (public key)")
    p_dms_heir_add.add_argument("name")
    p_dms_heir_add.add_argument("public_key_b64")

    subparsers.add_parser("dms-heir-list", help="List heirs")

    subparsers.add_parser("dms-encrypt-payload", help="Encrypt payload for heirs")

    subparsers.add_parser("dms-release-packages", help="Export release packages (triggered)")

    # --- Ephemeral Purge ---
    p_purge = subparsers.add_parser("purge-ephemeral", help="Purge old Level 0 ephemeral memories")
    p_purge.add_argument("--max-age-hours", type=int, default=24, help="Max age in hours (default 24)")

    subparsers.add_parser("ephemeral-status", help="Show ephemeral memory statistics")

    # --- Lockdown Mode ---
    p_lockdown = subparsers.add_parser("lockdown", help="Enter vault lockdown (disable ALL recalls)")
    p_lockdown.add_argument("reason", help="Reason for lockdown")

    subparsers.add_parser("unlock", help="Exit vault lockdown")

    subparsers.add_parser("lockdown-status", help="Show lockdown status")

    # --- Key Rotation ---
    p_rotate = subparsers.add_parser("rotate-key", help="Rotate encryption key for a profile")
    p_rotate.add_argument("profile_id", help="Profile to rotate")

    # --- Memory Tombstones ---
    p_tombstone = subparsers.add_parser("tombstone", help="Mark memory as inaccessible (retained for audit)")
    p_tombstone.add_argument("memory_id", help="Memory to tombstone")
    p_tombstone.add_argument("--reason", required=True, help="Reason for tombstoning")

    subparsers.add_parser("tombstone-list", help="List all tombstoned memories")

    p_tombstone_check = subparsers.add_parser("tombstone-check", help="Check if a memory is tombstoned")
    p_tombstone_check.add_argument("memory_id", help="Memory to check")

    # --- IntentLog Integration ---
    p_intent_link = subparsers.add_parser("intent-link", help="Link a memory to an intent ID")
    p_intent_link.add_argument("memory_id")
    p_intent_link.add_argument("intent_id")

    p_intent_unlink = subparsers.add_parser("intent-unlink", help="Remove intent link from memory")
    p_intent_unlink.add_argument("memory_id")
    p_intent_unlink.add_argument("intent_id")

    p_intent_search = subparsers.add_parser("intent-search", help="Search memories by intent")
    p_intent_search.add_argument("query", help="Intent ID or pattern")
    p_intent_search.add_argument("--limit", type=int, default=20)

    p_intent_get = subparsers.add_parser("intent-get", help="Get intents for a memory")
    p_intent_get.add_argument("memory_id")

    # --- Zero-Knowledge Proofs ---
    p_zk_commitment = subparsers.add_parser("zk-commitment", help="Generate existence commitment for a memory")
    p_zk_commitment.add_argument("memory_id")
    p_zk_commitment.add_argument("--output", help="Output file for commitment JSON")

    p_zk_verify = subparsers.add_parser("zk-verify", help="Verify an existence commitment")
    p_zk_verify.add_argument("commitment_file", help="Path to commitment JSON")
    p_zk_verify.add_argument("memory_id")
    p_zk_verify.add_argument("created_at")

    p_zk_time = subparsers.add_parser("zk-time-proof", help="Generate time-bound existence proof")
    p_zk_time.add_argument("memory_id")
    p_zk_time.add_argument("before_timestamp", help="ISO timestamp to prove existence before")

    # --- Key Escrow ---
    p_escrow_create = subparsers.add_parser("escrow-create", help="Create escrowed key shards")
    p_escrow_create.add_argument("profile_id", help="Profile to escrow")
    p_escrow_create.add_argument("--threshold", type=int, required=True, help="Minimum shards for recovery")
    p_escrow_create.add_argument("--recipients", required=True, help="Comma-separated name:pubkey_b64 pairs")

    p_escrow_list = subparsers.add_parser("escrow-list", help="List escrows")
    p_escrow_list.add_argument("--profile", help="Filter by profile")

    p_escrow_info = subparsers.add_parser("escrow-info", help="Get escrow details")
    p_escrow_info.add_argument("escrow_id")

    p_escrow_export = subparsers.add_parser("escrow-export", help="Export shard for a recipient")
    p_escrow_export.add_argument("escrow_id")
    p_escrow_export.add_argument("recipient_name")
    p_escrow_export.add_argument("--output", help="Output file")

    p_escrow_delete = subparsers.add_parser("escrow-delete", help="Delete an escrow")
    p_escrow_delete.add_argument("escrow_id")

    # --- NatLangChain Integration ---
    p_chain_anchor = subparsers.add_parser("chain-anchor", help="Anchor memory to NatLangChain blockchain")
    p_chain_anchor.add_argument("memory_id")
    p_chain_anchor.add_argument("--author", default="memory_vault", help="Author identifier")

    p_chain_verify = subparsers.add_parser("chain-verify", help="Verify memory anchor on NatLangChain")
    p_chain_verify.add_argument("memory_id")

    p_chain_history = subparsers.add_parser("chain-history", help="Get NatLangChain history for a memory")
    p_chain_history.add_argument("memory_id")

    subparsers.add_parser("chain-status", help="Check NatLangChain connection status")

    # --- Effort Tracking (MP-02) ---
    p_effort_start = subparsers.add_parser("effort-start", help="Start effort observation segment")
    p_effort_start.add_argument("--reason", default="manual_start", help="Reason for starting")

    p_effort_stop = subparsers.add_parser("effort-stop", help="Stop current effort observation")
    p_effort_stop.add_argument("--reason", default="manual_stop", help="Reason for stopping")

    p_effort_signal = subparsers.add_parser("effort-signal", help="Record an effort signal")
    p_effort_signal.add_argument("signal_type", choices=[
        "text_edit", "command", "tool_interaction", "voice_transcript",
        "file_operation", "search_query", "decision", "annotation", "pause", "marker"
    ])
    p_effort_signal.add_argument("content")
    p_effort_signal.add_argument("--metadata", default="{}", help="JSON metadata")

    p_effort_marker = subparsers.add_parser("effort-marker", help="Add explicit boundary marker")
    p_effort_marker.add_argument("description")

    subparsers.add_parser("effort-status", help="Show current effort observation status")

    p_effort_validate = subparsers.add_parser("effort-validate", help="Validate an effort segment")
    p_effort_validate.add_argument("segment_id")

    p_effort_receipt = subparsers.add_parser("effort-receipt", help="Generate effort receipt for a segment")
    p_effort_receipt.add_argument("segment_id")
    p_effort_receipt.add_argument("--memory-id", help="Link to memory ID")
    p_effort_receipt.add_argument("--no-anchor", action="store_true", help="Don't anchor to NatLangChain")

    p_effort_link = subparsers.add_parser("effort-link", help="Link effort receipt to memory")
    p_effort_link.add_argument("receipt_id")
    p_effort_link.add_argument("memory_id")

    subparsers.add_parser("effort-pending", help="List pending (unvalidated) segments")

    p_effort_get = subparsers.add_parser("effort-get", help="Get effort receipts for a memory")
    p_effort_get.add_argument("memory_id")

    # --- Agent-OS Governance ---
    subparsers.add_parser("governance-status", help="Show governance summary")

    subparsers.add_parser("boundary-status", help="Show Agent-OS boundary daemon status")

    p_governance_check = subparsers.add_parser("governance-check", help="Check governance permission")
    p_governance_check.add_argument("agent_id")
    p_governance_check.add_argument("action", choices=["recall", "store", "delete"])
    p_governance_check.add_argument("memory_id")

    args = parser.parse_args()
    vault = MemoryVault()
    init_deadman_switch()  # Ensure tables exist

    def get_passphrase(prompt="Passphrase: "):
        if getattr(args, "passphrase_file", None):
            with open(args.passphrase_file) as f:
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

        # Build kwargs, only include memory_id if provided
        obj_kwargs = {
            "content_plaintext": args.content.encode(),
            "classification": args.classification,
            "encryption_profile": args.profile,
            "access_policy": {"cooldown_seconds": args.cooldown},
            "value_metadata": metadata
        }
        if args.id:
            obj_kwargs["memory_id"] = args.id

        obj = MemoryObject(**obj_kwargs)
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

    elif args.command == "backup":
        passphrase = get_passphrase("Backup encryption passphrase: ") if not getattr(args, "passphrase_file", None) else None
        try:
            vault.backup(
                output_file=args.output_file,
                incremental=args.incremental,
                description=args.description,
                passphrase=passphrase
            )
        except Exception as e:
            print(f"Backup failed: {e}")
            sys.exit(1)

    elif args.command == "list-backups":
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""
            SELECT backup_id, timestamp, type, memory_count, description
            FROM backups
            ORDER BY timestamp DESC
        """)
        print("\n=== Backup History ===\n")
        for backup_id, timestamp, btype, count, desc in c.fetchall():
            ts = datetime.fromisoformat(timestamp.rstrip("Z")).strftime("%Y-%m-%d %H:%M")
            print(f"{ts} | {btype:12} | {count:3} memories | {backup_id}")
            if desc:
                print(f"  Description: {desc}")
            print()
        conn.close()

    elif args.command == "verify-integrity":
        try:
            result = vault.verify_integrity(memory_id=args.memory_id if hasattr(args, 'memory_id') else None)
            sys.exit(0 if result else 1)
        except Exception as e:
            print(f"Verification failed: {e}")
            sys.exit(1)

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

    # ==================== Ephemeral Purge Commands ====================

    elif args.command == "purge-ephemeral":
        count = vault.purge_ephemeral(max_age_hours=args.max_age_hours)
        sys.exit(0)

    elif args.command == "ephemeral-status":
        stats = vault.get_ephemeral_count()
        print("\n=== Ephemeral Memory Status ===\n")
        print(f"Count: {stats['count']}")
        if stats['oldest']:
            print(f"Oldest: {stats['oldest']}")
        if stats['newest']:
            print(f"Newest: {stats['newest']}")
        print()

    # ==================== Lockdown Commands ====================

    elif args.command == "lockdown":
        try:
            result = vault.enter_lockdown(args.reason)
            sys.exit(0 if result else 1)
        except Exception as e:
            print(f"Lockdown failed: {e}")
            sys.exit(1)

    elif args.command == "unlock":
        try:
            result = vault.exit_lockdown()
            sys.exit(0 if result else 1)
        except Exception as e:
            print(f"Unlock failed: {e}")
            sys.exit(1)

    elif args.command == "lockdown-status":
        is_locked, since, reason = vault.is_locked_down()
        print("\n=== Vault Lockdown Status ===\n")
        if is_locked:
            print("🔒 VAULT IS LOCKED DOWN")
            print(f"   Since: {since}")
            print(f"   Reason: {reason}")
        else:
            print("🔓 Vault is NOT in lockdown")
            print("   All operations permitted")
        print()

    # ==================== Key Rotation Commands ====================

    elif args.command == "rotate-key":
        try:
            result = vault.rotate_profile_key(args.profile_id)
            sys.exit(0 if result else 1)
        except Exception as e:
            print(f"Key rotation failed: {e}")
            sys.exit(1)

    # ==================== Memory Tombstone Commands ====================

    elif args.command == "tombstone":
        try:
            result = vault.tombstone_memory(args.memory_id, args.reason)
            sys.exit(0 if result else 1)
        except Exception as e:
            print(f"Tombstone failed: {e}")
            sys.exit(1)

    elif args.command == "tombstone-list":
        memories = vault.get_tombstoned_memories()
        print("\n=== Tombstoned Memories ===\n")
        if not memories:
            print("No tombstoned memories")
        else:
            for m in memories:
                print(f"{m['memory_id'][:12]}... | Level {m['classification']} | {m['tombstoned_at']}")
                print(f"  Reason: {m['reason']}")
                print()
        sys.exit(0)

    elif args.command == "tombstone-check":
        try:
            is_tomb, tomb_at, reason = vault.is_tombstoned(args.memory_id)
            if is_tomb:
                print(f"\nMemory {args.memory_id} is TOMBSTONED")
                print(f"  Since: {tomb_at}")
                print(f"  Reason: {reason}\n")
            else:
                print(f"\nMemory {args.memory_id} is NOT tombstoned\n")
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

    # ==================== IntentLog Commands ====================

    elif args.command == "intent-link":
        from memory_vault.intentlog import link_intent
        try:
            link_intent(args.memory_id, args.intent_id)
        except Exception as e:
            print(f"Link failed: {e}")
            sys.exit(1)

    elif args.command == "intent-unlink":
        from memory_vault.intentlog import unlink_intent
        try:
            unlink_intent(args.memory_id, args.intent_id)
        except Exception as e:
            print(f"Unlink failed: {e}")
            sys.exit(1)

    elif args.command == "intent-search":
        from memory_vault.intentlog import search_by_intent
        results = search_by_intent(args.query, args.limit)
        print(f"\n=== Intent Search: '{args.query}' ===\n")
        if not results:
            print("No matches found")
        else:
            for r in results:
                tomb = " [TOMBSTONED]" if r['tombstoned'] else ""
                print(f"{r['memory_id'][:12]}... | Level {r['classification']}{tomb}")
                print(f"  Intents: {', '.join(r['intent_refs']) if r['intent_refs'] else 'None'}")
                print()

    elif args.command == "intent-get":
        from memory_vault.intentlog import get_intents_for_memory
        try:
            intents = get_intents_for_memory(args.memory_id)
            print(f"\n=== Intents for {args.memory_id} ===\n")
            if not intents:
                print("No linked intents")
            else:
                for intent in intents:
                    print(f"  - {intent}")
            print()
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

    # ==================== Zero-Knowledge Proof Commands ====================

    elif args.command == "zk-commitment":
        from memory_vault.zkproofs import generate_existence_commitment
        try:
            commitment = generate_existence_commitment(args.memory_id)
            if args.output:
                with open(args.output, "w") as f:
                    json.dump(commitment, f, indent=2)
                print(f"Commitment saved to {args.output}")
            else:
                print(json.dumps(commitment, indent=2))
        except Exception as e:
            print(f"Commitment generation failed: {e}")
            sys.exit(1)

    elif args.command == "zk-verify":
        from memory_vault.zkproofs import verify_existence_commitment
        try:
            with open(args.commitment_file) as f:
                commitment = json.load(f)
            is_valid, message = verify_existence_commitment(
                commitment, args.memory_id, args.created_at
            )
            if is_valid:
                print(f"\n✓ {message}\n")
                sys.exit(0)
            else:
                print(f"\n✗ {message}\n")
                sys.exit(1)
        except Exception as e:
            print(f"Verification failed: {e}")
            sys.exit(1)

    elif args.command == "zk-time-proof":
        from memory_vault.zkproofs import generate_time_bound_proof
        try:
            proof = generate_time_bound_proof(args.memory_id, args.before_timestamp)
            print(json.dumps(proof, indent=2))
            if proof['existed_before']:
                print(f"\n✓ Memory existed before {args.before_timestamp}\n")
            else:
                print(f"\n✗ Memory was created AFTER {args.before_timestamp}\n")
        except Exception as e:
            print(f"Proof generation failed: {e}")
            sys.exit(1)

    # ==================== Escrow Commands ====================

    elif args.command == "escrow-create":
        from memory_vault.escrow import create_escrow
        try:
            # Parse recipients: "name1:pubkey1,name2:pubkey2"
            recipients = []
            for pair in args.recipients.split(","):
                name, pubkey = pair.strip().split(":", 1)
                recipients.append((name.strip(), pubkey.strip()))

            escrow_id = create_escrow(
                args.profile_id,
                args.threshold,
                recipients
            )
            if escrow_id:
                print(f"\nEscrow created: {escrow_id}\n")
        except Exception as e:
            print(f"Escrow creation failed: {e}")
            sys.exit(1)

    elif args.command == "escrow-list":
        from memory_vault.escrow import list_escrows
        escrows = list_escrows(args.profile if hasattr(args, 'profile') else None)
        print("\n=== Key Escrows ===\n")
        if not escrows:
            print("No escrows found")
        else:
            for e in escrows:
                print(f"{e['escrow_id'][:12]}... | {e['profile_id']} | {e['threshold']}-of-{e['total_shards']}")
                print(f"  Created: {e['created_at']}")
                print()

    elif args.command == "escrow-info":
        from memory_vault.escrow import get_escrow_info
        try:
            info = get_escrow_info(args.escrow_id)
            print(f"\n=== Escrow: {info['escrow_id']} ===\n")
            print(f"Profile: {info['profile_id']}")
            print(f"Threshold: {info['threshold']} of {info['total_shards']}")
            print(f"Created: {info['created_at']}")
            print("\nRecipients:")
            for r in info['recipients']:
                print(f"  Shard {r['index']}: {r['name']}")
            print()
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)

    elif args.command == "escrow-export":
        from memory_vault.escrow import export_shard_package
        try:
            package = export_shard_package(args.escrow_id, args.recipient_name)
            if args.output:
                with open(args.output, "w") as f:
                    json.dump(package, f, indent=2)
                print(f"Shard package exported to {args.output}")
            else:
                print(json.dumps(package, indent=2))
        except Exception as e:
            print(f"Export failed: {e}")
            sys.exit(1)

    elif args.command == "escrow-delete":
        from memory_vault.escrow import delete_escrow
        try:
            result = delete_escrow(args.escrow_id)
            sys.exit(0 if result else 1)
        except Exception as e:
            print(f"Delete failed: {e}")
            sys.exit(1)

    # ==================== NatLangChain Commands ====================

    elif args.command == "chain-anchor":
        try:
            entry_id = vault.anchor_to_chain(args.memory_id, author=args.author)
            if entry_id:
                print("\n✓ Memory anchored to NatLangChain")
                print(f"  Entry ID: {entry_id}\n")
            else:
                print("\n✗ Failed to anchor memory\n")
                sys.exit(1)
        except Exception as e:
            print(f"Anchor failed: {e}")
            sys.exit(1)

    elif args.command == "chain-verify":
        try:
            result = vault.verify_chain_anchor(args.memory_id)
            print(f"\n=== Chain Verification: {args.memory_id} ===\n")
            if result:
                print(f"Entry ID: {result.get('entry_id', 'N/A')}")
                print(f"Anchored At: {result.get('anchored_at', 'N/A')}")
                print(f"Verified: {'✓ Yes' if result.get('verified') else '✗ No'}")
                if result.get('block_proof'):
                    print(f"Block Hash: {result['block_proof'].get('block_hash', 'N/A')[:16]}...")
            else:
                print("Memory not anchored to chain")
            print()
        except Exception as e:
            print(f"Verification failed: {e}")
            sys.exit(1)

    elif args.command == "chain-history":
        try:
            history = vault.get_chain_history(args.memory_id)
            print(f"\n=== Chain History: {args.memory_id} ===\n")
            if not history:
                print("No chain entries found")
            else:
                for entry in history:
                    verified = "✓" if entry.get('verified') else "○"
                    print(f"{verified} {entry['anchor_type']} | {entry['anchored_at']}")
                    print(f"    Entry: {entry['entry_id'][:16]}...")
                    print()
        except Exception as e:
            print(f"History lookup failed: {e}")
            sys.exit(1)

    elif args.command == "chain-status":
        try:
            from memory_vault.natlangchain import NatLangChainClient
            client = NatLangChainClient()
            print("\n=== NatLangChain Status ===\n")
            if client.health_check():
                print(f"✓ Connected to: {client.api_url}")
                print(f"  Version: {client.get_version()}")
                stats = client.get_chain_stats()
                if stats:
                    print(f"  Blocks: {stats.get('block_count', 'N/A')}")
                    print(f"  Entries: {stats.get('entry_count', 'N/A')}")
            else:
                print(f"✗ Cannot connect to NatLangChain at {client.api_url}")
                print("  Set NATLANGCHAIN_API_URL environment variable to configure")
            print()
        except Exception as e:
            print(f"Status check failed: {e}")

    # ==================== Effort Tracking Commands ====================

    elif args.command == "effort-start":
        from memory_vault.effort import EffortObserver
        try:
            observer = EffortObserver()
            segment_id = observer.start_observation(reason=args.reason)
            print("\n✓ Effort observation started")
            print(f"  Segment ID: {segment_id}\n")
        except Exception as e:
            print(f"Start failed: {e}")
            sys.exit(1)

    elif args.command == "effort-stop":
        from memory_vault.effort import EffortObserver
        try:
            observer = EffortObserver()
            segment = observer.stop_observation(reason=args.reason)
            if segment:
                print("\n✓ Effort observation stopped")
                print(f"  Segment ID: {segment.segment_id}")
                print(f"  Signals: {segment.signal_count()}")
                print(f"  Duration: {segment.duration_seconds():.1f}s\n")
            else:
                print("\nNo active observation to stop\n")
        except Exception as e:
            print(f"Stop failed: {e}")
            sys.exit(1)

    elif args.command == "effort-signal":
        from memory_vault.effort import EffortObserver, SignalType
        try:
            observer = EffortObserver()
            metadata = json.loads(args.metadata)
            signal_type = SignalType(args.signal_type)
            signal = observer.record_signal(signal_type, args.content, metadata)
            if signal:
                print(f"✓ Signal recorded: {signal.signal_id[:8]}...")
            else:
                print("✗ Not observing. Start observation first.")
                sys.exit(1)
        except Exception as e:
            print(f"Signal recording failed: {e}")
            sys.exit(1)

    elif args.command == "effort-marker":
        from memory_vault.effort import EffortObserver
        try:
            observer = EffortObserver()
            signal = observer.add_marker(args.description)
            if signal:
                print(f"✓ Marker added: {args.description}")
            else:
                print("✗ Not observing. Start observation first.")
                sys.exit(1)
        except Exception as e:
            print(f"Marker failed: {e}")
            sys.exit(1)

    elif args.command == "effort-status":
        from memory_vault.effort import EffortObserver
        observer = EffortObserver()
        print("\n=== Effort Observation Status ===\n")
        if observer.is_observing():
            print("✓ Observing")
            print(f"  Segment: {observer.current_segment_id()}")
        else:
            print("○ Not currently observing")
        print()

    elif args.command == "effort-validate":
        from memory_vault.effort import EffortObserver, EffortValidator
        try:
            observer = EffortObserver()
            segment = observer.get_segment(args.segment_id)
            if not segment:
                print(f"Segment {args.segment_id} not found")
                sys.exit(1)

            validator = EffortValidator()
            result = validator.validate_segment(segment)

            print(f"\n=== Effort Validation: {args.segment_id[:12]}... ===\n")
            print(f"Valid: {'✓ Yes' if result.is_valid else '✗ No'}")
            print(f"Coherence: {result.coherence_score:.2f}")
            print(f"Progression: {result.progression_score:.2f}")
            print(f"Uncertainty: {result.uncertainty:.2f}")
            print(f"\nSummary: {result.effort_summary}")
            if result.dissent_notes:
                print(f"\nNotes: {result.dissent_notes}")
            print()
        except Exception as e:
            print(f"Validation failed: {e}")
            sys.exit(1)

    elif args.command == "effort-receipt":
        from memory_vault.effort import (
            EffortObserver, EffortValidator, generate_receipt
        )
        try:
            observer = EffortObserver()
            segment = observer.get_segment(args.segment_id)
            if not segment:
                print(f"Segment {args.segment_id} not found")
                sys.exit(1)

            validator = EffortValidator()
            validation = validator.validate_segment(segment)

            if not validation.is_valid:
                print("Warning: Segment validation failed. Generating receipt anyway.")

            receipt = generate_receipt(
                segment=segment,
                validation=validation,
                memory_id=args.memory_id if hasattr(args, 'memory_id') else None,
                anchor_to_chain=not args.no_anchor
            )

            print("\n=== MP-02 Effort Receipt Generated ===\n")
            print(f"Receipt ID: {receipt.receipt_id}")
            print(f"Segment ID: {receipt.segment_id}")
            print(f"Time Bounds: {receipt.time_bounds_start} to {receipt.time_bounds_end}")
            print(f"Signals: {receipt.signal_count}")
            print(f"Summary: {receipt.effort_summary[:100]}...")
            if receipt.ledger_entry_id:
                print(f"Chain Entry: {receipt.ledger_entry_id}")
            print()
        except Exception as e:
            print(f"Receipt generation failed: {e}")
            sys.exit(1)

    elif args.command == "effort-link":
        try:
            vault.link_effort_receipt(args.memory_id, args.receipt_id)
            print(f"✓ Linked receipt {args.receipt_id[:8]}... to memory {args.memory_id[:8]}...")
        except Exception as e:
            print(f"Link failed: {e}")
            sys.exit(1)

    elif args.command == "effort-pending":
        from memory_vault.effort import list_pending_segments
        segments = list_pending_segments()
        print("\n=== Pending Effort Segments ===\n")
        if not segments:
            print("No pending segments")
        else:
            for seg in segments:
                print(f"{seg['segment_id'][:12]}... | {seg['signal_count']} signals")
                print(f"  {seg['start_time']} to {seg['end_time']}")
                print()

    elif args.command == "effort-get":
        receipts = vault.get_effort_receipts(args.memory_id)
        print(f"\n=== Effort Receipts for {args.memory_id[:12]}... ===\n")
        if not receipts:
            print("No effort receipts linked")
        else:
            for r in receipts:
                print(f"{r['receipt_id'][:12]}... | {r['signal_count']} signals")
                print(f"  Time: {r['time_start']} to {r['time_end']}")
                print(f"  Summary: {r['effort_summary'][:60]}...")
                if r['ledger_entry_id']:
                    print(f"  Chain: {r['ledger_entry_id'][:16]}...")
                print()

    # ==================== Agent-OS Governance Commands ====================

    elif args.command == "governance-status":
        summary = vault.get_governance_summary()
        print("\n=== Agent-OS Governance Summary ===\n")
        if not summary.get('available', True):
            print(f"Agent-OS integration: {summary.get('message', summary.get('error', 'Not available'))}")
        else:
            print(f"Total decisions: {summary.get('total_decisions', 0)}")
            print(f"Approved: {summary.get('approved', 0)}")
            print(f"Denied: {summary.get('denied', 0)}")
            print(f"Human overrides: {summary.get('human_overrides', 0)}")
            if summary.get('approval_rate'):
                print(f"Approval rate: {summary['approval_rate']:.1%}")
            if summary.get('by_action'):
                print("\nBy action:")
                for action, count in summary['by_action'].items():
                    print(f"  {action}: {count}")
        print()

    elif args.command == "boundary-status":
        status = vault.get_boundary_status()
        print("\n=== Agent-OS Boundary Status ===\n")
        if status.get('available'):
            print("✓ Boundary daemon connected")
            if 'mode' in status:
                print(f"  Mode: {status['mode']}")
            if 'human_present' in status:
                print(f"  Human present: {'Yes' if status['human_present'] else 'No'}")
        else:
            print(f"○ Boundary daemon: {status.get('reason', status.get('error', 'Not available'))}")
        print()

    elif args.command == "governance-check":
        try:
            permitted, reason = vault.check_governance_permission(
                args.agent_id, args.action, args.memory_id
            )
            print("\n=== Governance Permission Check ===\n")
            print(f"Agent: {args.agent_id}")
            print(f"Action: {args.action}")
            print(f"Resource: {args.memory_id}")
            print(f"\nResult: {'✓ PERMITTED' if permitted else '✗ DENIED'}")
            print(f"Reason: {reason}")
            print()
            sys.exit(0 if permitted else 1)
        except Exception as e:
            print(f"Check failed: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
