Memory Vault – Comprehensive Documentation
Version: 1.0 (December 17, 2025)
Author: kase1111-hash with Grok
Repository: https://github.com/kase1111-hash/memory-vault
Overview
Memory Vault is a secure, owner-sovereign, offline-first storage system designed specifically for high-value cognitive artifacts in AI agent ecosystems. It provides cryptographically enforced classification-bound access, tamper-evident auditing, hardware-bound secrets, and human-in-the-loop controls.
It is built on the core principles of Agent-OS:

Human sovereignty first
Explicit consent for persistence and recall
Refusal as security
Local-first, airgap-capable design

Key Features

FeatureDescriptionClassification Levels (0–5)0–2: agent recall
3–4: human approval + boundary checks
5: extreme caution (future physical token)Multiple Encryption ProfilesPassphrase, keyfile, optional TPM-sealed keysBoundary Daemon IntegrationRuntime environment checks via Unix socketHuman Approval GatesExplicit yes/no for high-classification recallCooldown EnforcementConfigurable per-memory cooldown periodsFull-Text SearchFTS5 on metadata and recall justificationsIncremental Encrypted BackupsFull + incremental chain with trackingTamper-Evident Audit TrailMerkle tree over recall logSigned Merkle RootsEd25519 signatures with optional TPM-sealed private keyHardware-Bound SecretsOptional TPM sealing for both memory keys and signing key
Architecture
textmemory_vault/
├── vault.py        - Core API (MemoryVault class)
├── db.py           - SQLite schema, migrations, FTS, indexes
├── crypto.py       - All cryptographic operations
├── merkle.py       - Merkle tree construction & verification
├── boundary.py     - Integration with boundary-daemon
├── models.py       - Dataclasses (MemoryObject, etc.)
├── cli.py          - Full command-line interface
└── vault.db        - Local encrypted database (~/.memory_vault/vault.db)
Security Model
Encryption

AES-256-GCM via libsodium (PyNaCl)
Per-memory nonce + optional per-memory salt
Keys derived with Argon2id (sensitive parameters)

Key Sources

SourceExportableHardware-BoundNotesHumanPassphraseYesNoArgon2id derivationKeyFileYesNoStatic pre-shared keyTPMNoYesSealed to PCRs 0–7
Audit Trail

Every recall (success/failure) logged
Leaf hash = double-SHA256 of log entry
Merkle root rebuilt on each log entry
Root signed with Ed25519 key
Signing key optionally sealed in TPM (non-exportable, PCR-bound)

CLI Usage
Bash# Profile management
memory-vault create-profile my-tpm-profile --key-source TPM
memory-vault create-profile secure-file --key-source KeyFile --generate-keyfile
memory-vault list-profiles

# Store a memory
memory-vault store \
  --content "master seed phrase: ..." \
  --classification 5 \
  --profile my-tpm-profile \
  --cooldown 604800 \
  --metadata '{"type":"seed","purpose":"recovery"}'

# Recall (with gates)
memory-vault recall <memory_id> --justification "System recovery"

# Search
memory-vault search-metadata "seed OR private key"
memory-vault search-justifications "emergency"

# Backup
memory-vault backup full-backup.json --description "Monthly full"
memory-vault backup incr-2025-12-17.json --incremental

memory-vault list-backups

# Integrity verification
memory-vault verify-integrity
memory-vault verify-integrity --memory-id <id>
Integrity Verification
The verify-integrity command:

Rebuilds the Merkle tree from leaves
Compares with latest stored root
Verifies every root signature using the public key
Optionally verifies proof for a specific memory's latest recall

Tamper detection triggers if:

Recall log modified
Root hashes altered
Signatures invalid
TPM PCRs changed (if using TPM-sealed signing key)

Backup & Restore

Backups are encrypted with AES-256-GCM (passphrase-derived)
Non-exportable memories (e.g., TPM profile) have ciphertext zeroed
Incremental backups only include changes since last backup
restore handles full + incremental chain

Integration with synth-mind
The vault is designed to replace or augment synth-mind's existing memory.db:

Use MemoryVault.store_memory() for high-value artifacts
Use MemoryVault.recall_memory() with justification logging
Search via FTS helpers for reflection
Boundary checks enforce airgap/offline policies

Dependencies
txtpynacl>=1.5.0
tpm2-pytss>=0.4.0      # optional, for TPM features
sqlite3                # stdlib
Security Considerations

Never auto-recall level 3+ memories
TPM features require trusted platform (no remote attestation yet)
Backup passphrases must be strong and stored separately
Signing public key should be backed up for long-term verification

Future Enhancements

Level 5 physical token support
Remote attestation for TPM keys
Signed backup manifests
Web-based audit viewer
Integration with IntentLog repo
