# Memory Vault

**Secure, Owner-Sovereign, Offline-First Storage for AI Agent Ecosystems**

Version: 1.0 (December 17, 2025)
Author: kase1111-hash with Grok
Repository: https://github.com/kase1111-hash/memory-vault

## Overview

Memory Vault is a cryptographically enforced storage system designed for high-value cognitive artifacts in AI agent ecosystems. It provides classification-bound access, tamper-evident auditing, hardware-bound secrets, and human-in-the-loop controls.

Built on the core principles of Agent-OS:
- Human sovereignty first
- Explicit consent for persistence and recall
- Refusal as security
- Local-first, airgap-capable design

## Key Features

| Feature | Description |
|---------|-------------|
| Classification Levels (0–5) | 0–2: agent recall; 3–4: human approval + boundary checks; 5: physical token required |
| Multiple Encryption Profiles | Passphrase, keyfile, optional TPM-sealed keys |
| Boundary Daemon Integration | Runtime environment checks via Unix socket |
| Human Approval Gates | Explicit yes/no for high-classification recall |
| Cooldown Enforcement | Configurable per-memory cooldown periods |
| Full-Text Search | FTS5 on metadata and recall justifications |
| Incremental Encrypted Backups | Full + incremental chain with tracking |
| Tamper-Evident Audit Trail | Merkle tree over recall log |
| Signed Merkle Roots | Ed25519 signatures with optional TPM-sealed private key |
| Hardware-Bound Secrets | Optional TPM sealing for memory keys and signing key |
| Dead-Man Switch | Encrypted release to heirs on trigger |

## Architecture

```
memory_vault/
├── vault.py        # Core API (MemoryVault class)
├── db.py           # SQLite schema, migrations, FTS, indexes
├── crypto.py       # All cryptographic operations
├── merkle.py       # Merkle tree construction & verification
├── boundary.py     # Integration with boundary-daemon
├── deadman.py      # Dead-man switch & heir release
├── models.py       # Dataclasses (MemoryObject, etc.)
├── cli.py          # Full command-line interface
└── vault.db        # Local encrypted database (~/.memory_vault/vault.db)
```

## Security Model

### Encryption
- AES-256-GCM via libsodium (PyNaCl)
- Per-memory nonce + optional per-memory salt
- Keys derived with Argon2id (sensitive parameters)

### Key Sources

| Source | Exportable | Hardware-Bound | Notes |
|--------|------------|----------------|-------|
| HumanPassphrase | Yes | No | Argon2id derivation |
| KeyFile | Yes | No | Static pre-shared key |
| TPM | No | Yes | Sealed to PCRs 0–7 |

### Audit Trail
- Every recall (success/failure) logged
- Leaf hash = double-SHA256 of log entry
- Merkle root rebuilt on each log entry
- Root signed with Ed25519 key
- Signing key optionally sealed in TPM (non-exportable, PCR-bound)

## CLI Usage

```bash
# Profile management
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

# Dead-man switch
memory-vault dms-arm 180 --memory-ids root-seed-1 --justification "Succession plan"
memory-vault dms-checkin
memory-vault dms-heir-add "Alice" age1ql3...
memory-vault dms-encrypt-payload
```

## Integrity Verification

The `verify-integrity` command:
1. Rebuilds the Merkle tree from leaves
2. Compares with latest stored root
3. Verifies every root signature using the public key
4. Optionally verifies proof for a specific memory's latest recall

Tamper detection triggers if:
- Recall log modified
- Root hashes altered
- Signatures invalid
- TPM PCRs changed (if using TPM-sealed signing key)

## Backup & Restore

- Backups are encrypted with AES-256-GCM (passphrase-derived)
- Non-exportable memories (e.g., TPM profile) have ciphertext zeroed
- Incremental backups only include changes since last backup
- `restore` handles full + incremental chain

## Dependencies

```
pynacl>=1.5.0
tpm2-pytss>=0.4.0      # optional, for TPM features
sqlite3                # stdlib
fido2                  # optional, for physical token support
pyotp                  # optional, for TOTP fallback
```

## Security Considerations

- Never auto-recall level 3+ memories
- TPM features require trusted platform (no remote attestation yet)
- Backup passphrases must be strong and stored separately
- Signing public key should be backed up for long-term verification

## Documentation

- [Specification](./SPECIFICATION.md) - Formal specification and design principles
- [Integrations](./docs/INTEGRATIONS.md) - Boundary daemon, IntentLog, physical tokens, and heir release
- [MP-02 Spec](./MP-02-spec.md) - Proof-of-Effort Receipt Protocol

## License

See [LICENSE](./LICENSE) file.
