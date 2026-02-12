# Claude Code Guidelines for Memory Vault

## Project Overview

Memory Vault is a sovereign, offline-capable AI memory storage system with XSalsa20-Poly1305 encryption and Argon2id key derivation. It provides encrypted knowledge storage for AI agents with owner-controlled access, classification-bound permissions, and tamper-evident auditing.

**Status:** v0.1.0-alpha (Feature Complete)
**Python:** 3.8+ recommended (3.7 minimum)
**License:** GPL-3.0-or-later

## Quick Commands

```bash
# Install for development
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ --cov=. --cov-report=html

# Lint check
ruff check .

# Format check
ruff format --check .

# Security audit
pip-audit

# Run pre-commit hooks
pre-commit run --all-files
```

## Project Structure

```
vault.py          - Core MemoryVault class (store/recall/backup/restore)
cli.py            - CLI interface
crypto.py         - XSalsa20-Poly1305, Argon2id, Ed25519 cryptography
db.py             - SQLite schema, FTS5 full-text search, migrations
errors.py         - Exception hierarchy (19 structured types)
models.py         - Core dataclasses (MemoryObject, etc.)
merkle.py         - Merkle tree construction & verification
boundary.py       - Boundary daemon Unix socket client
intentlog.py      - IntentLog bidirectional linking
escrow.py         - Shamir's Secret Sharing key escrow (experimental)
physical_token.py - FIDO2, HMAC, TOTP authentication (experimental)
deadman.py        - Dead-man switch & heir management (experimental)
zkproofs.py       - Zero-knowledge existence proofs (experimental)
examples/         - Integration examples (LangChain adapter)
tests/            - pytest test suite
```

## Coding Conventions

- **Line Length:** 120 characters max (enforced by ruff)
- **Type Hints:** Use throughout function signatures
- **Docstrings:** Required for public functions and classes
- **Imports:** Explicit imports only, no wildcards
- **Error Handling:** Use structured exceptions from `errors.py`

## Security Principles

This codebase follows strict security principles that must be maintained:

1. **Fail-Closed:** Default to denying access when uncertain
2. **No Plaintext on Disk:** Encrypt immediately, decrypt in-memory only
3. **Immutable Classification:** Set at write-time, cannot be changed
4. **Audit Everything:** All operations logged to Merkle tree with Ed25519 signatures
5. **Defense in Depth:** Multiple security layers (encryption + boundary + tokens)

## Classification Levels

- **Level 0:** Ephemeral (auto-purge)
- **Level 1:** Working (short-term)
- **Level 2:** Private (owner-only)
- **Level 3:** Sealed (human approval required)
- **Level 4:** Vaulted (hardware-bound, air-gap)
- **Level 5:** Black (physical token required)

## Testing Guidelines

- Tests are in `tests/` directory using pytest
- Use fixtures from `conftest.py` for shared setup
- Class-based organization: `TestClassName`
- Method naming: `test_description_of_behavior()`
- Each test gets isolated temporary directory
- Run specific test: `pytest tests/test_smoke.py::TestClass::test_func -v`

## Key Patterns

### Profile ID Validation
```python
PROFILE_ID_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$')
```

### Error Handling
Always use structured exceptions from `errors.py`:
```python
from errors import DecryptionError, CooldownError, LockdownError
```

### Database Operations
Use the schema and helpers in `db.py`. Tables include:
- `encryption_profiles`, `memories`, `recall_log`, `backups`
- `merkle_leaves`, `merkle_roots`, `vault_state`

## Dependencies

**Core:**
- `pynacl >= 1.5.0` - Cryptography (libsodium)

**Optional:**
- `tpm2-pytss >= 2.1.0` - TPM hardware support
- `fido2 >= 1.1.0` - FIDO2/U2F tokens
- `pyotp >= 2.8.0` - TOTP/HOTP

**Dev:**
- `pytest >= 7.0.0`, `pytest-cov >= 4.0.0`
- `ruff >= 0.1.0`, `pip-audit >= 2.6.0`

## Important Notes

- Never log or expose encryption keys or plaintext content
- Boundary daemon socket: `~/.agent-os/api/boundary.sock`
