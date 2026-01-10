# Memory Vault

**Sovereign AI memory storage for cognitive artifacts — own your AI's memory with offline-capable, encrypted cognitive storage.**

Memory Vault is an **AI memory vault** and **private AI knowledge base** designed for AI agent ecosystems. It provides **owner-controlled AI storage** with classification-bound access control, tamper-evident auditing, hardware-bound secrets, and human-in-the-loop controls. Built for **digital sovereignty**, Memory Vault ensures your AI's memories remain private, self-hosted, and under your complete control.

[![Tests](https://github.com/kase1111-hash/memory-vault/actions/workflows/test.yml/badge.svg)](https://github.com/kase1111-hash/memory-vault/actions/workflows/test.yml)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

**Version:** 0.1.0-alpha | **Status:** Alpha (Feature Complete, Seeking Feedback)

> ⚠️ **Alpha Release**: This is the first public release. Core functionality is stable and tested,
> but some features (TPM hardware sealing, FIDO2 credential lifecycle) require additional validation.
> API may change based on community feedback.

## What Problem Does This Solve?

- **How do I own my AI's memory?** Memory Vault gives you complete AI memory ownership with self-hosted infrastructure that never phones home.
- **Where can I store private AI knowledge?** A personal AI knowledge vault with military-grade encryption that works completely offline.
- **How do I keep my AI's data sovereign?** Sovereign data for AI agents — no cloud dependencies, no third-party access, full data ownership.
- **Can AI memory be self-hosted?** Yes. Memory Vault is designed as self-hosted AI memory that runs on your own hardware, from Raspberry Pi to enterprise servers.
- **How do I protect sensitive cognitive artifacts?** Private agent memory with 6-level classification, hardware-bound encryption, and human approval gates.

## Features

### Core Security
- **6-Level Classification System** (0-5): From ephemeral to physically-gated secrets
- **Multiple Encryption Profiles**: Passphrase, keyfile, or TPM-sealed keys
- **AES-256-GCM Encryption**: Authenticated encryption via libsodium
- **Argon2id Key Derivation**: Maximum security parameters (1GB memory)
- **Hardware-Bound Secrets**: Optional TPM sealing for maximum security

### Access Control
- **Boundary Daemon Integration**: Runtime environment checks via Unix socket
- **Human Approval Gates**: Explicit consent for high-classification recalls
- **Cooldown Enforcement**: Configurable per-memory access throttling
- **Physical Token Support**: Level 5 memories require FIDO2/YubiKey/TOTP
- **Lockdown Mode**: Emergency disable of all recalls

### Audit & Integrity
- **Tamper-Evident Audit Trail**: Merkle tree over all recall events
- **Signed Merkle Roots**: Ed25519 signatures with optional TPM sealing
- **Zero-Knowledge Proofs**: Prove memory existence without revealing content
- **NatLangChain Anchoring**: Immutable blockchain audit trails

### Recovery & Succession
- **Encrypted Backups**: Full + incremental backup chain with tracking
- **Dead-Man Switch**: Encrypted heir release on owner absence
- **Key Escrow**: Shamir's Secret Sharing for quorum recovery
- **Memory Tombstones**: Mark inaccessible but retain for audit

### Integrations
- **IntentLog Adapter**: Bidirectional linking with intent tracking systems
- **Agent-OS Governance**: Constitution-based access control
- **MP-02 Proof-of-Effort**: Cryptographic effort receipts for human work
- **Full-Text Search**: FTS5 on metadata and recall justifications

## Installation

```bash
# Clone the repository
git clone https://github.com/kase1111-hash/memory-vault.git
cd memory-vault

# Install with pip (recommended)
pip install .

# Or install with development dependencies
pip install -e ".[dev]"

# Optional: Install with all extras (TPM, tokens)
pip install -e ".[all]"
```

### Optional Dependencies

```bash
# TPM 2.0 support (Linux only)
pip install ".[tpm]"

# Physical token support (FIDO2, TOTP)
pip install ".[tokens]"
```

## Quick Start

### 1. Create Encryption Profile

```bash
# Passphrase-based (default)
python -m memory_vault.cli create-profile my-profile --key-source HumanPassphrase

# Keyfile-based
python -m memory_vault.cli create-profile secure-file --key-source KeyFile --generate-keyfile

# TPM-sealed (requires TPM hardware)
python -m memory_vault.cli create-profile tpm-profile --key-source TPM
```

### 2. Store a Memory

```bash
python -m memory_vault.cli store \
  --content "My secret data" \
  --classification 2 \
  --profile my-profile \
  --cooldown 3600 \
  --metadata '{"type":"credential","importance":"high"}'
```

### 3. Recall a Memory

```bash
python -m memory_vault.cli recall <memory_id> --justification "System recovery"
```

## Classification Levels

| Level | Name      | Key Requirements                    |
|-------|-----------|------------------------------------|
| 0     | Ephemeral | Auto-recall, auto-purge            |
| 1     | Working   | Auto-recall                        |
| 2     | Private   | Auto-recall                        |
| 3     | Sealed    | Human approval + boundary check    |
| 4     | Vaulted   | + offline/airgap mode              |
| 5     | Black     | + physical token                   |

See [SPECIFICATION.md](SPECIFICATION.md#3-memory-classification-model) for full classification details.

## Physical Token Setup (Level 5)

### FIDO2/U2F (Recommended)

```bash
# YubiKey, Nitrokey, OnlyKey - no setup needed
# Just insert token when prompted
```

### TOTP (Software Fallback)

```bash
# Generate TOTP secret
python -m memory_vault.physical_token setup-totp

# Scan QR code with authenticator app
```

### Test Token

```bash
python -m memory_vault.physical_token test
```

## Backup & Restore

### Create Backup

```bash
# Full backup
python -m memory_vault.cli backup full-backup.json --description "Monthly full"

# Incremental backup
python -m memory_vault.cli backup incr-2025-12.json --incremental --description "December changes"

# List backups
python -m memory_vault.cli list-backups
```

### Restore

```bash
python -m memory_vault.cli restore full-backup.json
```

## Integrity Verification

```bash
# Verify entire vault
python -m memory_vault.cli verify-integrity

# Verify specific memory
python -m memory_vault.cli verify-integrity --memory-id <id>
```

## Dead-Man Switch

### Setup Heirs

```bash
# Add heir with their public key (age/x25519)
python -m memory_vault.cli dms-heir-add "Alice" age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# List heirs
python -m memory_vault.cli dms-heir-list
```

### Arm Switch

```bash
# Arm for 180 days with specific memories
python -m memory_vault.cli dms-arm 180 \
  --memory-ids "mem-id-1,mem-id-2" \
  --justification "Succession plan"

# Encrypt payload for heirs
python -m memory_vault.cli dms-encrypt-payload
```

### Check-In (Prove Aliveness)

```bash
python -m memory_vault.cli dms-checkin
```

### Release (When Triggered)

```bash
# Check status
python -m memory_vault.cli dms-status

# Export encrypted packages for heirs
python -m memory_vault.cli dms-release-packages
```

## Search

```bash
# Search metadata
python -m memory_vault.cli search-metadata "credential OR key"

# Search recall justifications
python -m memory_vault.cli search-justifications "emergency"
```

## Lockdown Mode

```bash
# Enable lockdown (disables ALL recalls)
python -m memory_vault.cli lockdown --reason "Security incident"

# Check status
python -m memory_vault.cli lockdown-status

# Disable lockdown
python -m memory_vault.cli unlock
```

## Key Rotation

```bash
# Rotate encryption key for a profile
python -m memory_vault.cli rotate-key my-profile
```

## Memory Tombstones

```bash
# Tombstone a memory (mark inaccessible, retain for audit)
python -m memory_vault.cli tombstone <memory_id> --reason "Deprecated"

# List tombstoned memories
python -m memory_vault.cli tombstone-list

# Check if a memory is tombstoned
python -m memory_vault.cli tombstone-check <memory_id>
```

## IntentLog Integration

```bash
# Link a memory to an intent ID
python -m memory_vault.cli intent-link <memory_id> <intent_id>

# Unlink an intent
python -m memory_vault.cli intent-unlink <memory_id> <intent_id>

# Search memories by intent
python -m memory_vault.cli intent-search "goal:complete-feature"

# Get all intents for a memory
python -m memory_vault.cli intent-get <memory_id>
```

## Zero-Knowledge Proofs

```bash
# Generate existence commitment (proves memory exists without revealing content)
python -m memory_vault.cli zk-commitment <memory_id>

# Verify an existence commitment
python -m memory_vault.cli zk-verify <commitment_json>

# Generate time-bound existence proof
python -m memory_vault.cli zk-time-proof <memory_id>
```

## Key Escrow (Shamir's Secret Sharing)

```bash
# Create 3-of-5 key escrow
python -m memory_vault.cli escrow-create my-profile \
  --threshold 3 \
  --recipients "alice:pubkey1,bob:pubkey2,charlie:pubkey3,dave:pubkey4,eve:pubkey5"

# List escrows
python -m memory_vault.cli escrow-list

# Get escrow details
python -m memory_vault.cli escrow-info <escrow_id>

# Export shard for recipient
python -m memory_vault.cli escrow-export <escrow_id> alice --output alice-shard.json

# Delete escrow
python -m memory_vault.cli escrow-delete <escrow_id>
```

## NatLangChain Blockchain

```bash
# Set API endpoint
export NATLANGCHAIN_API_URL="http://localhost:8000"

# Anchor memory to blockchain
python -m memory_vault.cli chain-anchor <memory_id>

# Verify blockchain anchor
python -m memory_vault.cli chain-verify <memory_id>

# Get chain history
python -m memory_vault.cli chain-history <memory_id>

# Check connection status
python -m memory_vault.cli chain-status
```

## MP-02 Proof-of-Effort

```bash
# Start effort observation
python -m memory_vault.cli effort-start --reason "Implementing feature X"

# Record effort signals
python -m memory_vault.cli effort-signal text_edit "Updated authentication handler"
python -m memory_vault.cli effort-signal decision "Chose JWT over sessions"
python -m memory_vault.cli effort-marker "Phase 1 complete"

# Stop observation
python -m memory_vault.cli effort-stop --reason "Feature complete"

# Validate effort segment
python -m memory_vault.cli effort-validate <segment_id>

# Generate signed receipt (optionally anchored to blockchain)
python -m memory_vault.cli effort-receipt <segment_id> --memory-id <memory_id>

# List pending segments
python -m memory_vault.cli effort-pending

# Get receipts for a memory
python -m memory_vault.cli effort-get <memory_id>
```

## Agent-OS Governance

```bash
# View governance summary
python -m memory_vault.cli governance-status

# Check boundary daemon status
python -m memory_vault.cli boundary-status

# Check governance permission
python -m memory_vault.cli governance-check <agent_id> <action> <memory_id>
```

## Architecture

```
memory_vault/
├── __init__.py         - Package initialization & exports
├── vault.py            - Core MemoryVault API (~1,700 lines)
├── db.py               - SQLite schema, migrations, FTS5, indexes
├── crypto.py           - AES-256-GCM, Argon2id, Ed25519, TPM sealing
├── merkle.py           - Merkle tree construction & verification
├── models.py           - Dataclasses (MemoryObject, etc.)
├── errors.py           - Exception hierarchy with SIEM integration
├── siem_reporter.py    - Boundary-SIEM event reporting
├── cli.py              - Command-line interface (~40 subcommands)
├── boundry.py          - Boundary daemon client & connection protection
├── physical_token.py   - FIDO2, HMAC, TOTP token authentication
├── deadman.py          - Dead-man switch & heir management
├── intentlog.py        - IntentLog bidirectional linking adapter
├── zkproofs.py         - Zero-knowledge existence proofs
├── escrow.py           - Shamir's Secret Sharing key escrow
├── natlangchain.py     - NatLangChain blockchain anchoring
├── effort.py           - MP-02 Proof-of-Effort receipts
└── agent_os.py         - Agent-OS governance integration
```

## Security Integrations

### SIEM Reporting

Memory Vault can report security events to Boundary-SIEM:

```python
from memory_vault import MemoryVault, SIEMConfig

# Configure SIEM (or use environment variables)
config = SIEMConfig(
    endpoint="http://siem.example.com/v1/events",
    api_key="your-api-key",
    enabled=True
)

vault = MemoryVault(siem_config=config)
```

Environment variables:
- `SIEM_ENDPOINT` - SIEM API endpoint
- `SIEM_API_KEY` - API authentication key
- `SIEM_ENABLED` - Enable/disable reporting (default: true)

### Boundary Daemon

The boundary daemon enforces operational mode restrictions:

```python
from memory_vault import BoundaryClient, OperationalMode

client = BoundaryClient()

# Check current mode
status = client.get_status()
if status.operational_mode == OperationalMode.AIRGAP:
    print("Running in airgap mode - network disabled")

# Request connection protection
granted, token = client.request_connection_protection(
    connection_type="database",
    target="/path/to/vault.db",
    duration_seconds=300
)
```

## Security

- **AES-256-GCM** encryption via libsodium (PyNaCl)
- **Argon2id** key derivation with maximum security parameters (1GB memory, 4 iterations)
- **Ed25519** signed Merkle audit trail
- **TPM support** for hardware-bound keys (optional)
- **Zero-knowledge proofs** for existence verification without content exposure

See [SPECIFICATION.md](SPECIFICATION.md) for detailed security model and threat analysis.

## Dependencies

### Required
- `pynacl>=1.5.0` - Core cryptography (AES-256-GCM, Argon2id, Ed25519)
- Python 3.7+ standard library (sqlite3, json, hashlib, uuid, datetime, base64)

### Optional
- `tpm2-pytss>=2.1.0` - TPM 2.0 support (Linux only)
- `fido2>=1.1.0` - FIDO2/U2F hardware tokens
- `pyotp>=2.8.0` - TOTP/HOTP software tokens

## Related Documentation

| Document | Purpose |
|----------|---------|
| [SPECIFICATION.md](SPECIFICATION.md) | Full technical specification and threat model |
| [RECOVERY.md](RECOVERY.md) | Emergency data recovery using only PyNaCl |
| [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) | Detailed integration guides for all external systems |

## License

See LICENSE file.

## Author

**kase1111-hash**

Built with principles from Agent-OS: Human sovereignty, explicit consent, refusal as security, local-first design.

---

## Part of the Agent-OS Ecosystem

Memory Vault is a core component of the **Agent-OS** ecosystem for natural language native AI agent infrastructure. These connected repositories work together to enable owned AI infrastructure with human-AI collaboration at its core.

### Agent-OS Core

| Repository | Description |
|------------|-------------|
| [Agent-OS](https://github.com/kase1111-hash/Agent-OS) | Natural language native operating system for AI agents — the coordination layer for multi-agent systems |
| [synth-mind](https://github.com/kase1111-hash/synth-mind) | Psychological AI architecture with six interconnected modules for emergent continuity and empathy |
| [boundary-daemon-](https://github.com/kase1111-hash/boundary-daemon-) | Trust enforcement layer defining cognition boundaries — controls where AI can think |
| [value-ledger](https://github.com/kase1111-hash/value-ledger) | Economic accounting layer for cognitive work — tracks value of ideas, effort, and novelty |
| [learning-contracts](https://github.com/kase1111-hash/learning-contracts) | Safety protocols for AI learning and data governance — controls what AI can learn |

### NatLangChain Ecosystem

| Repository | Description |
|------------|-------------|
| [NatLangChain](https://github.com/kase1111-hash/NatLangChain) | Prose-first, intent-native blockchain protocol for recording human intent in natural language |
| [IntentLog](https://github.com/kase1111-hash/IntentLog) | Git for human reasoning — version control for tracking "why" changes happen via prose commits |
| [Finite-Intent-Executor](https://github.com/kase1111-hash/Finite-Intent-Executor) | Posthumous execution of predefined intent via Solidity smart contracts |
| [mediator-node](https://github.com/kase1111-hash/mediator-node) | LLM mediation layer for matching, negotiation, and closure proposals |
| [ILR-module](https://github.com/kase1111-hash/ILR-module) | IP & Licensing Reconciliation — dispute resolution for intellectual property conflicts |
| [RRA-Module](https://github.com/kase1111-hash/RRA-Module) | Revenant Repo Agent — converts abandoned repositories into autonomous licensing agents |

### Security Infrastructure

| Repository | Description |
|------------|-------------|
| [Boundary-SIEM](https://github.com/kase1111-hash/Boundary-SIEM) | Security Information and Event Management for AI agent systems |

---

**Memory as capital, not cache.**

The vault enforces restraint. A system that remembers everything becomes dangerous. The Memory Vault exists to prevent that — ensuring cognitive artifact storage remains sovereign, private, and under human control.
