# Memory Vault

**Secure, owner-sovereign, offline-first storage for high-value cognitive artifacts.**

Memory Vault is a cryptographically enforced storage system designed for AI agent ecosystems, providing classification-bound access control, tamper-evident auditing, hardware-bound secrets, and human-in-the-loop controls.

## Features

- **6-Level Classification System** (0-5): From ephemeral to physically-gated secrets
- **Multiple Encryption Profiles**: Passphrase, keyfile, or TPM-sealed keys
- **Boundary Daemon Integration**: Runtime environment checks via Unix socket
- **Human Approval Gates**: Explicit consent for high-classification recalls
- **Cooldown Enforcement**: Configurable per-memory access throttling
- **Full-Text Search**: FTS5 on metadata and recall justifications
- **Encrypted Backups**: Full + incremental backup chain with tracking
- **Tamper-Evident Audit Trail**: Merkle tree over all recall events
- **Signed Merkle Roots**: Ed25519 signatures with optional TPM sealing
- **Physical Token Support**: Level 5 memories require FIDO2/YubiKey/TOTP
- **Dead-Man Switch**: Encrypted heir release on owner absence
- **Hardware-Bound Secrets**: Optional TPM sealing for maximum security

## Installation

```bash
# Clone the repository
git clone https://github.com/kase1111-hash/memory-vault.git
cd memory-vault

# Install core dependencies
pip install -r requirements.txt

# Optional: Install TPM support (Linux with TPM 2.0)
pip install tpm2-pytss

# Optional: Install physical token support
pip install fido2 pyotp
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

## Architecture

```
memory_vault/
├── __init__.py       - Package initialization
├── vault.py          - Core MemoryVault API
├── db.py             - SQLite schema, migrations, FTS, indexes
├── crypto.py         - All cryptographic operations
├── merkle.py         - Merkle tree construction & verification
├── boundry.py        - Boundary daemon integration
├── models.py         - Dataclasses (MemoryObject, etc.)
├── physical_token.py - Physical token authentication
├── deadman.py        - Dead-man switch functionality
└── cli.py            - Command-line interface
```

## Security

- **AES-256-GCM** encryption via libsodium (PyNaCl)
- **Argon2id** key derivation with maximum security parameters
- **Ed25519** signed Merkle audit trail
- **TPM support** for hardware-bound keys (optional)

See [SPECIFICATION.md](SPECIFICATION.md) for detailed security model and threat analysis.

## Dependencies

- `pynacl>=1.5.0` - Core cryptography (required)
- `tpm2-pytss>=2.1.0` - TPM support (optional, Linux only)
- `fido2>=1.1.0` - FIDO2/U2F tokens (optional)
- `pyotp>=2.8.0` - TOTP/HOTP fallback (optional)

## License

See LICENSE file.

## Author

**kase1111-hash**

Built with principles from Agent-OS: Human sovereignty, explicit consent, refusal as security, local-first design.

---

**Memory as capital, not cache.**

The vault enforces restraint. A system that remembers everything becomes dangerous. The Memory Vault exists to prevent that.
