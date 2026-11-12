# Changelog

All notable changes to Memory Vault are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0-alpha] - 2026-11-12

**AI integration and key-handling correctness.**

### Added

- **MCP server** (`memory-vault-mcp`, `mcp_server.py`, optional `mcp` extra): exposes the
  vault to Model Context Protocol clients (Claude Code, Claude Desktop, Cursor, agent SDKs)
  as `remember`, `search_memories`, `list_memories`, `recall`, `forget` and `vault_status`
  tools. Level 3-4 recalls ask the human for approval through the client (MCP elicitation);
  Level 5 is never recallable through the server. Tested end-to-end over stdio against MCP
  SDK 1.23, 1.30 and 2.3.
- **`VaultToolkit`**: the same operations as plain functions, for tool-calling loops that do
  not use MCP.
- **Non-interactive mode**: `MemoryVault(interactive=False)` never prompts on the terminal;
  missing passphrases raise `ProfileKeyMissingError` and human gates fail closed.
- **Approval callback**: `MemoryVault(approver=...)` decides Level 3+ recalls in place of the
  terminal prompt.
- **Discovery API**: `search_memories()` (free-text search over metadata, safe for
  model-written queries), `list_memories()` and `get_memory_info()`; none decrypt content.

### Fixed

- **Data loss in the key cache**: a passphrase-derived key was cached per profile and reused
  for memories with a different salt. Storing a second memory without re-supplying the
  passphrase saved it under a key that did not match its salt, making it undecryptable with
  the correct passphrase; recalling without a passphrase failed for all but the most recent
  memory. Keys are now cached per `(profile, salt)` and only after they are proven correct.
  *A memory written by the affected path in an earlier version was encrypted with the key
  for another memory's salt, so it can usually be recovered by trying the passphrase with
  the salts of the other memories in the same profile (see `RECOVERY.md`).*
- **Corrupted keyfiles**: `load_key_from_file` whitespace-stripped the raw key, so roughly 5%
  of generated keys (those beginning or ending with a whitespace byte) were rejected as the
  wrong length.
- **Keyfile overwrite**: `generate_keyfile` silently replaced an existing key, orphaning
  every memory encrypted with it. It now refuses.
- **Wrong passphrase accepted on store**: a mistyped passphrase silently encrypted the new
  memory under an unknown key. Stores are now checked against the profile's existing memories.
- **Python version**: the code used syntax that fails to import on Python 3.8 and 3.9 despite
  advertising 3.8+. The supported floor is now 3.10, stated consistently.
- **CI**: the lint job failed on unformatted files and the security-scan job failed on
  low-severity example findings, so the test matrix never ran. Both are fixed; the matrix is
  now Python 3.10/3.12/3.13 on Linux and macOS, with Windows as best-effort.
- `examples/langchain_memory.py` crashed on its second run and targeted a deprecated
  LangChain interface; replaced by `examples/agent_memory.py`.
- CLI `store` and `create-profile` report failures without a traceback.

### Changed

- **One Argon2id salt per profile** instead of per memory, so the 1 GB key derivation runs
  once per session rather than on every store and recall (recalls after the first dropped
  from ~2.5 s to milliseconds). Each memory row still records its salt, so `RECOVERY.md`
  procedures and existing vaults (per-memory salts) keep working unchanged.
- Key rotation re-encrypts a profile under a single new salt and derives each old key once.
- Database initialisation logs at DEBUG instead of printing to stdout.
- Requires Python 3.10+.

### Also included (previously unreleased)

**Functionality verification pass.** Exercised every README-advertised workflow
end-to-end and fixed everything that did not work as documented.

### Fixed

- **Packaging**: `pip install .` now actually installs a `memory_vault` package, making
  `from memory_vault import MemoryVault`, `python -m memory_vault.cli`, and the
  `memory-vault` console script work as documented (`pyproject.toml`). Previously the
  modules were installed flat at site-packages top level and the console script crashed
  on import.
- **Boundary fail-closed scope**: Level 0-2 memories are auto-recall per the
  classification model, but recalls failed hard when the boundary daemon was absent —
  breaking the Quick Start on any machine without Agent-OS. Levels 0-2 now remain
  recallable when the daemon is unreachable; an explicit daemon denial still blocks
  them, and Level 3+ stays fail-closed (`boundary.py`)
- **Backups were empty by default**: memories in non-exportable profiles were stripped
  from backups, and the seeded `default-passphrase` profile is non-exportable — so
  default-profile vaults produced backups with no recoverable content, and `restore`
  crashed on the NULL ciphertext. Backup now only strips hardware-bound (TPM) content;
  restore skips stripped entries gracefully (`vault.py`)
- **Missing `restore` CLI command**: documented in the README but not implemented; added
  `restore <backup_file> [--passphrase-file] [--yes]` (`cli.py`)
- **Physical-token gates blocked advertised flows**: `lockdown`, `unlock`, `rotate-key`,
  escrow create/delete, all dead-man switch operations, and Level 3+ tombstoning
  unconditionally required a physical token, making them unusable on machines without
  token hardware/secrets (token deps are optional extras) — dead-man switch arming even
  failed *silently* with exit code 0. The token is now required only when one is actually
  configured; Level 5 recalls still hard-require a token
  (`vault.py`, `escrow.py`, `deadman.py`, `physical_token.py` — new `any_token_configured()`)
- **`backup --passphrase-file` inverted**: passing the flag triggered an interactive
  prompt instead of reading the file (`cli.py`)
- **`search-justifications` crash**: timestamp parsing failed on stored
  `+00:00Z`-suffixed timestamps (`cli.py`)
- **`escrow-create` silent failure**: an aborted escrow exited 0 with no output; now
  reports the abort and exits 1 (`cli.py`)
- **Dead-man switch payload encryption crashed**: `encrypt_payload_for_heirs()` passed
  raw bytes to `SealedBox` instead of a `PublicKey` — the code path was previously
  unreachable because the token gate always aborted first (`deadman.py`)
- **`boundary.py` import crash** when imported as part of the installed package (bare
  `from errors import ...` without the package-relative fallback)
- Version metadata aligned to 0.2.1-alpha in `pyproject.toml` and `__init__.py`
  (previously still 0.2.0-alpha)

### Documentation

- README Quick Start fixed: it created a profile named `default` while `MemoryObject`
  defaults to the `default-passphrase` profile (which is auto-seeded), so the example
  failed with "Profile not found"
- README CLI examples corrected: `lockdown` takes a positional reason (not `--reason`);
  `zk-verify` requires the memory id and creation timestamp; `zk-time-proof` requires a
  timestamp; `dms-heir-add` takes a base64 x25519 key (not an age bech32 key)
- SPECIFICATION and INTEGRATIONS docs updated to state the fail-closed boundary policy
  applies to Level 3+ while Levels 0-2 remain available offline

## [0.2.1-alpha] - 2026-02-20

**Security hardening release.** Remediated all 15 findings from the Agent-OS
Post-Moltbook security audit.

### Security

- Fixed TOCTOU race in signing key creation — uses `os.fchmod()` before writing (`crypto.py`)
- Disabled HMAC file-only authentication by default — requires `MEMORY_VAULT_ALLOW_HMAC_FILE_ONLY=1` opt-in (`physical_token.py`)
- Added post-decryption content hash verification — defense-in-depth SHA256 check (`vault.py`)
- Fixed `exit_lockdown()` passphrase verification — now performs trial decryption (`vault.py`)
- Set database directory permissions to `0o700` and file permissions to `0o600` (`db.py`)
- Set signing key directory permissions to `0o700`, public key to `0o644` (`crypto.py`)
- Added `requirements-lock.txt` with pinned dependency hashes for supply chain protection
- Added `detect-secrets` scanning to CI pipeline (`.github/workflows/test.yml`)

### Added

- `register_memory_auditor()` — callback hook for injection pattern detection on recalled content (`vault.py`)
- `archive_audit_logs()` — export signed Merkle root snapshots for audit log management (`vault.py`)
- Documented O(N) Merkle tree rebuild cost with incremental optimization plan (`vault.py`)

### Changed

- Replaced mock API key pattern in example with non-secret content (`examples/langchain_memory.py`)

### Documentation

- Consolidated documentation: merged 6 overlapping/stale docs into 2
- Updated security audit report with remediation status for all 15 findings

## [0.2.0-alpha] - 2026-02-12

**Refocus release.** Stripped ecosystem integrations and SIEM infrastructure to
focus Memory Vault on its core mission: encrypted, classification-gated storage
for AI agent memories.

### Removed
- **Ecosystem modules extracted** (belong in their own packages):
  - `natlangchain.py` - NatLangChain blockchain anchoring
  - `effort.py` - MP-02 Proof-of-Effort receipts
  - `agent_os.py` - Agent-OS governance SDK
  - `siem_reporter.py` - Boundary-SIEM event reporting
- Removed SIEM wiring from vault.py (~15 call sites) and boundary.py
- Removed 18 unused exception classes from errors.py

### Changed
- Simplified `MemoryVault.__init__` to single `db_path` parameter
- Simplified `MemoryVaultError` base class (dropped actor/metadata/cause/timestamp)
- Simplified `__init__.py` from 203 lines to 85 lines
- Simplified `errors.py` from 377 lines / 37 classes to 188 lines / 19 classes
- Renamed `boundry.py` to `boundary.py` (fixed typo)
- Deduplicated `validate_profile_id` into `crypto.py`
- All methods in vault.py now use `self._conn` (no per-method sqlite3.connect calls)
- Marked zkproofs, deadman, escrow, physical_token as experimental

### Fixed
- Cipher documentation: corrected "AES-256-GCM" to "XSalsa20-Poly1305" across all docs
- Connection management: replaced 19 separate sqlite3.connect() calls with shared self._conn

### Added
- `examples/langchain_memory.py` - Framework integration example with LangChain adapter pattern
- Python-first quickstart in README (3-line store/recall example)

## [0.1.0-alpha] - 2026-01-01

**First public alpha release.** This release consolidates all core functionality
with error handling and boundary daemon integration.

### Added
- **Error Handling Framework** (`errors.py`)
  - Structured exception types with severity levels
  - 10-level severity scale (DEBUG to BREACH_DETECTED)

- **Boundary Daemon Client** (`boundary.py`)
  - `BoundaryClient` class with full protocol support
  - Connection protection requests
  - Operational mode querying (ONLINE/OFFLINE/AIRGAP/COLDROOM)
  - Status caching for performance

- **Production Readiness**
  - Comprehensive security documentation (SECURITY.md)
  - Contribution guidelines (CONTRIBUTING.md)
  - Pre-commit hooks for code quality
  - GitHub Actions CI with security scanning

### Changed
- `MemoryVault` now initializes boundary client on construction
- `recall_memory()` uses structured exceptions
- Updated `pyproject.toml` with new modules

### Fixed
- TOML parsing error in pyproject.toml
- Test isolation issues with db_path parameter
- Relative import issues for standalone usage

### Known Issues
- TPM sealing untested on real hardware
- FIDO2 full credential lifecycle incomplete

## [0.3.0-alpha] - 2026-11-12

**AI integration and key-handling correctness.**

### Added

- **MCP server** (`memory-vault-mcp`, `mcp_server.py`, optional `mcp` extra): exposes the
  vault to Model Context Protocol clients (Claude Code, Claude Desktop, Cursor, agent SDKs)
  as `remember`, `search_memories`, `list_memories`, `recall`, `forget` and `vault_status`
  tools. Level 3-4 recalls ask the human for approval through the client (MCP elicitation);
  Level 5 is never recallable through the server. Tested end-to-end over stdio against MCP
  SDK 1.23, 1.30 and 2.3.
- **`VaultToolkit`**: the same operations as plain functions, for tool-calling loops that do
  not use MCP.
- **Non-interactive mode**: `MemoryVault(interactive=False)` never prompts on the terminal;
  missing passphrases raise `ProfileKeyMissingError` and human gates fail closed.
- **Approval callback**: `MemoryVault(approver=...)` decides Level 3+ recalls in place of the
  terminal prompt.
- **Discovery API**: `search_memories()` (free-text search over metadata, safe for
  model-written queries), `list_memories()` and `get_memory_info()`; none decrypt content.

### Fixed

- **Data loss in the key cache**: a passphrase-derived key was cached per profile and reused
  for memories with a different salt. Storing a second memory without re-supplying the
  passphrase saved it under a key that did not match its salt, making it undecryptable with
  the correct passphrase; recalling without a passphrase failed for all but the most recent
  memory. Keys are now cached per `(profile, salt)` and only after they are proven correct.
  *A memory written by the affected path in an earlier version was encrypted with the key
  for another memory's salt, so it can usually be recovered by trying the passphrase with
  the salts of the other memories in the same profile (see `RECOVERY.md`).*
- **Corrupted keyfiles**: `load_key_from_file` whitespace-stripped the raw key, so roughly 5%
  of generated keys (those beginning or ending with a whitespace byte) were rejected as the
  wrong length.
- **Keyfile overwrite**: `generate_keyfile` silently replaced an existing key, orphaning
  every memory encrypted with it. It now refuses.
- **Wrong passphrase accepted on store**: a mistyped passphrase silently encrypted the new
  memory under an unknown key. Stores are now checked against the profile's existing memories.
- **Python version**: the code used syntax that fails to import on Python 3.8 and 3.9 despite
  advertising 3.8+. The supported floor is now 3.10, stated consistently.
- **CI**: the lint job failed on unformatted files and the security-scan job failed on
  low-severity example findings, so the test matrix never ran. Both are fixed; the matrix is
  now Python 3.10/3.12/3.13 on Linux and macOS, with Windows as best-effort.
- `examples/langchain_memory.py` crashed on its second run and targeted a deprecated
  LangChain interface; replaced by `examples/agent_memory.py`.
- CLI `store` and `create-profile` report failures without a traceback.

### Changed

- **One Argon2id salt per profile** instead of per memory, so the 1 GB key derivation runs
  once per session rather than on every store and recall (recalls after the first dropped
  from ~2.5 s to milliseconds). Each memory row still records its salt, so `RECOVERY.md`
  procedures and existing vaults (per-memory salts) keep working unchanged.
- Key rotation re-encrypts a profile under a single new salt and derives each old key once.
- Database initialisation logs at DEBUG instead of printing to stdout.
- Requires Python 3.10+.

### Also included (previously unreleased)

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
  - XSalsa20-Poly1305 encryption via libsodium
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

- **Advanced Features**
  - IntentLog bidirectional linking adapter
  - Zero-knowledge existence proofs
  - Dead-man switch with heir management
  - Key escrow via Shamir's Secret Sharing

- **CLI**
  - Profile management
  - Memory store/recall
  - Backup/restore
  - Integrity verification
  - Search operations

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
- Database schema includes new tables (`vault_state`, `escrow_shards`, `dms_heirs`)
- Existing databases will be migrated automatically on first use
