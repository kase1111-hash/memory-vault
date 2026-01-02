# Changelog

All notable changes to Memory Vault are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha] - 2026-01-01

**First public alpha release.** This release consolidates all core functionality
with production-grade error handling and security integrations.

### Added
- **Error Handling Framework** (`errors.py`)
  - 30+ structured exception types with SIEM-compatible event conversion
  - 10-level severity scale (DEBUG to BREACH_DETECTED)
  - Full actor/target tracking for security auditing
  - Automatic traceback capture for debugging

- **SIEM Integration** (`siem_reporter.py`)
  - Boundary-SIEM HTTP/JSON API support (`POST /v1/events`)
  - CEF protocol support (UDP/TCP) for traditional SIEM systems
  - Async event reporting with background worker thread
  - Event batching and automatic retry with exponential backoff
  - Environment-based configuration

- **Enhanced Boundary Daemon** (`boundry.py`)
  - `BoundaryClient` class with full protocol support
  - Connection protection requests
  - Vault registration with boundary-daemon
  - Operational mode querying (ONLINE/OFFLINE/AIRGAP/COLDROOM)
  - Status caching for performance

- **Production Readiness**
  - Comprehensive security documentation (SECURITY.md)
  - Contribution guidelines (CONTRIBUTING.md)
  - Pre-commit hooks for code quality
  - GitHub Actions CI with security scanning

### Changed
- `MemoryVault` now initializes SIEM reporter and boundary client
- `recall_memory()` uses structured exceptions and reports to SIEM
- Updated `pyproject.toml` with new modules

### Fixed
- TOML parsing error in pyproject.toml
- Test isolation issues with db_path parameter
- Relative import issues for standalone usage

### Known Issues
- TPM sealing untested on real hardware
- FIDO2 full credential lifecycle incomplete
- Some pre-existing test mismatches (merkle.py, models.py)

## [Unreleased]

Previous development versions (1.0.0, 1.1.0) have been consolidated into this
alpha release. See below for historical context.

---

## Historical Development (Pre-Alpha)

## [1.1.0] - 2025-12-31

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
