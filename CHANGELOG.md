# Changelog

All notable changes to Memory Vault are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-01-01

### Added
- `pyproject.toml` for standard Python packaging (`pip install .`)
- Basic test suite with pytest (36 tests covering core functionality)
- CLI entry point `memory-vault` after pip install

### Changed
- Updated all documentation with complete module inventory
- SPECIFICATION.md updated to v1.7

## [1.0.0] - 2025-12-31

### Added
- **Core Features**
  - 6-level classification system (Ephemeral → Black)
  - Multiple encryption profiles (HumanPassphrase, KeyFile, TPM)
  - AES-256-GCM encryption via libsodium
  - Argon2id key derivation (SENSITIVE parameters)
  - Ed25519 signed Merkle audit trail
  - Full-text search (FTS5) on metadata and justifications

- **Access Control**
  - Boundary daemon integration for environment validation
  - Human approval gates for Level 3+ recalls
  - Cooldown enforcement per-memory
  - Physical token support (FIDO2, HMAC, TOTP) for Level 5
  - Lockdown mode (emergency disable all recalls)

- **Recovery & Succession**
  - Full and incremental encrypted backups
  - Dead-man switch with heir release
  - Key escrow via Shamir's Secret Sharing
  - Memory tombstones (mark inaccessible, retain for audit)
  - Key rotation

- **Integrations**
  - IntentLog bidirectional linking adapter
  - Zero-knowledge existence proofs
  - NatLangChain blockchain anchoring
  - MP-02 Proof-of-Effort receipt protocol
  - Agent-OS governance integration

- **CLI** (~40 subcommands)
  - Profile management
  - Memory store/recall
  - Backup/restore
  - Dead-man switch management
  - Integrity verification
  - Search operations
  - Effort tracking
  - Governance status

### Security
- Fail-closed design (daemon unavailable → recalls denied)
- No plaintext written to disk
- TPM sealing support (code complete, untested on hardware)
- Classification immutable after write

## Version History (Pre-1.0)

| Version | Date | Changes |
|---------|------|---------|
| 0.6 | Dec 22, 2025 | Implemented tombstones, IntentLog adapter, ZK proofs, Shamir escrow |
| 0.5 | Dec 22, 2025 | Implemented Level 0 auto-purge, lockdown mode, key rotation |
| 0.4 | Dec 22, 2025 | Fixed file references, import bugs, consolidated documentation |
| 0.3 | Dec 19, 2025 | Physical tokens, backup/restore, verify-integrity fully implemented |
| 0.2 | Dec 19, 2025 | Added implementation status, plans, MP-02 integration |
| 0.1 | Dec 2025 | Initial specification and core implementation |

---

## Upgrade Notes

### 1.0.0 → 1.1.0
- No breaking changes
- New `pip install .` support (previously manual installation only)
- Run `pip install .[dev]` to get test dependencies

### Pre-1.0 → 1.0.0
- Database schema includes new tables (`vault_state`, `escrow_shards`, `effort_*`, `dms_heirs`)
- Existing databases will be migrated automatically on first use
