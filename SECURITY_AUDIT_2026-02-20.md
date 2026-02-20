# Memory Vault - Agent-OS Security Audit Report

**Audit Date:** 2026-02-20
**Auditor:** Automated Security Audit (Agent-OS Post-Moltbook Hardening Guide v1.0)
**Version:** 0.2.0-alpha
**Repository:** memory-vault
**Methodology:** [Agentic Security Audit Checklist](https://github.com/kase1111-hash/Claude-prompts/blob/main/Agentic-Security-Audit.md)

---

## Executive Summary

This audit evaluates Memory Vault against the Agent-OS Post-Moltbook Hardening Guide, a tiered security framework designed to identify vulnerabilities exposed by the Moltbook/OpenClaw security incident. The audit covers all three tiers: Architectural Defaults, Core Enforcement, and Protocol-Level Maturity.

**Overall Assessment:** Memory Vault demonstrates strong cryptographic fundamentals and a defense-in-depth architecture. The core encryption (XSalsa20-Poly1305 via libsodium), key derivation (Argon2id), and fail-closed design are sound. However, several findings require attention before production deployment, primarily around incomplete hardware token authentication, database hardening, and memory integrity provenance.

| Tier | Status | Findings |
|------|--------|----------|
| Tier 1: Immediate Wins | **Mostly Compliant** | 3 findings (1 medium, 2 low) |
| Tier 2: Core Enforcement | **Partially Compliant** | 7 findings (2 high, 3 medium, 2 low) |
| Tier 3: Protocol-Level | **Partially Compliant** | 5 findings (1 high, 2 medium, 2 low) |

**Critical: 0 | High: 3 | Medium: 6 | Low: 6 | Total: 15**

---

## TIER 1: Immediate Wins (Architectural Defaults)

### 1.1 Credential Storage

| Check | Status | Notes |
|-------|--------|-------|
| No plaintext secrets in config files | PASS | No secrets in `.json`, `.yaml`, `.toml`, `.env`, `.md` source files |
| No secrets in git history | PASS | Git history clean; deleted files (`siem_reporter.py`, `agent_os.py`, etc.) contained no credentials |
| Encrypted keystore implemented | PASS | Keys derived via Argon2id or loaded from restricted keyfiles (`0o600`) |
| Non-predictable config paths | ADVISORY | Uses `~/.memory_vault/` which is predictable but standard for user-space apps |
| `.gitignore` covers sensitive paths | PASS | Covers `*.db`, `*.key`, `signing_key`, `.env`, `.env.local` |

**Finding T1-01 (Low): Example file contains mock API key pattern**
- **File:** `examples/langchain_memory.py:90`
- **Detail:** Contains `b"API key: sk-example-12345"` as example content stored in a memory. While this is clearly example data and is encrypted before storage, the pattern `sk-*` in example code could normalize the practice of storing raw API keys in memory objects.
- **Recommendation:** Change the example to use a non-secret pattern (e.g., `b"User preference: dark mode enabled"`) or add a comment warning that real API keys should use a dedicated secrets manager.

**Finding T1-02 (Low): Database directory created without explicit permissions**
- **File:** `db.py:8`
- **Detail:** `os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)` creates `~/.memory_vault/` with default umask permissions (typically `0o755`). Keyfiles within are correctly set to `0o600`, but the directory itself may be world-readable, allowing enumeration of vault presence and file names.
- **Recommendation:** Set directory permissions to `0o700`:
  ```python
  os.makedirs(os.path.dirname(DB_PATH), mode=0o700, exist_ok=True)
  ```

**Finding T1-03 (Medium): SQLite database file has no explicit file permissions**
- **File:** `db.py:35`
- **Detail:** `sqlite3.connect(path)` creates the database file with default umask permissions. The vault database contains encrypted ciphertext, nonces, salts, classification levels, and audit logs. While ciphertext is encrypted, metadata (memory IDs, timestamps, classification levels, access patterns) is in plaintext within the database.
- **Recommendation:** Set database file permissions to `0o600` after creation:
  ```python
  conn = sqlite3.connect(path)
  os.chmod(path, 0o600)
  ```

### 1.2 Default-Deny Permissions / Least Privilege

| Check | Status | Notes |
|-------|--------|-------|
| No default root/admin execution | PASS | No elevated privilege requirements |
| Capabilities declared per-module | PASS | Each module has clear scope (crypto, db, boundary, etc.) |
| Filesystem access scoped to declared directories | PASS | All file I/O confined to `~/.memory_vault/` |
| Network access scoped to declared endpoints | PASS | Only boundary daemon Unix socket; no outbound network |
| Destructive operations gated behind explicit approval | PASS | Tombstoning, lockdown, key rotation all require confirmation |

**No findings.** The permission model is well-designed. The classification system (Level 0-5) with escalating approval requirements is a strong implementation of least privilege.

### 1.3 Cryptographic Agent Identity

| Check | Status | Notes |
|-------|--------|-------|
| Agent keypair generation on initialization | PASS | Ed25519 keypair generated on first run (`crypto.py:330-350`) |
| All agent actions cryptographically signed | PARTIAL | Merkle roots are signed; individual operations are not |
| Identity anchored to NatLangChain | N/A | NatLangChain integration schema exists (`chain_anchors` table) but module was extracted |
| No self-asserted authority claims without crypto backing | PASS | Signing key backs audit trail integrity |
| Session binding tied to authenticated identity | N/A | Single-owner model; no multi-session identity binding needed |

**No actionable findings.** The Ed25519 signing key implementation is correct. The signing key file is properly permissioned (`0o600`). TPM-sealed signing is available as an optional upgrade path.

---

## TIER 2: Core Enforcement Layer

### 2.1 Input Classification Gate (Data vs. Instructions)

| Check | Status | Notes |
|-------|--------|-------|
| All external input classified before reaching LLM | N/A | Memory Vault is a storage layer, not an LLM interface |
| Instruction-like content in data streams flagged | N/A | Stores opaque encrypted blobs; does not interpret content |
| Structured input boundaries | PASS | CLI uses argparse with typed arguments; no raw eval/exec |
| No raw HTML/markdown from external sources passed to reasoning engine | N/A | Not applicable to storage layer |

**No findings.** Memory Vault correctly treats all stored content as opaque data. It never interprets, executes, or processes the plaintext content of memories.

### 2.2 Memory Integrity and Provenance

| Check | Status | Notes |
|-------|--------|-------|
| Every memory entry tagged with metadata | PASS | `created_at`, `created_by`, `classification`, `content_hash`, `encryption_profile` |
| Untrusted memory entries stored separately | N/A | Single-owner model; all entries are owner-created |
| Memory content hashed at write; modifications trigger alerts | PARTIAL | Content hashed at write (`SHA256`); no modification alerting |
| Periodic memory audits for injection patterns | MISSING | No automated audit scanning |
| IntentLog integration for tracing memory-influenced decisions | PASS | `intentlog.py` provides bidirectional linking |
| Memory expiration policy for external-sourced data | PASS | Level 0 ephemeral auto-purge (`purge_ephemeral()`) |

**Finding T2-01 (Medium): No content integrity verification on recall**
- **File:** `vault.py:260-426`
- **Detail:** When a memory is recalled, the decrypted content is not verified against the stored `content_hash`. While XSalsa20-Poly1305 provides authenticated encryption (which verifies ciphertext integrity), an explicit hash check after decryption would provide defense-in-depth against implementation bugs or future cipher changes.
- **Recommendation:** Add post-decryption hash verification:
  ```python
  plaintext = decrypt_memory(key, ciphertext, nonce)
  actual_hash = hashlib.sha256(plaintext).hexdigest()
  if actual_hash != row_dict["content_hash"]:
      raise DecryptionError("Content hash mismatch - possible tampering")
  ```

**Finding T2-02 (Medium): No MemoryAuditor for injection pattern detection**
- **Detail:** The Moltbook incident demonstrated that persistent memory can be used for time-delayed prompt injection. While Memory Vault encrypts content (preventing inspection without decryption), there is no mechanism to scan recalled content for injection patterns before it reaches an LLM consumer.
- **Recommendation:** Consider adding an optional `MemoryAuditor` hook that can be registered to scan decrypted content during recall, looking for known injection patterns, credential fragments, or anomalous content.

### 2.3 Outbound Secret Scanning

| Check | Status | Notes |
|-------|--------|-------|
| All outbound messages scanned for secrets | N/A | No outbound messaging capability |
| Constitutional rule: agents never transmit credentials | N/A | Storage-only system |
| Outbound content logging for audit | N/A | No outbound capability |
| Alerts on detection; block send and notify human principal | N/A | No outbound capability |

**No findings.** Memory Vault is a storage system with no outbound communication beyond the boundary daemon Unix socket (which transmits only JSON control messages, never memory content).

**Finding T2-03 (Low): Backup files may contain metadata in plaintext**
- **File:** `vault.py:579-604`
- **Detail:** Backup files are fully encrypted, but the backup container structure (`version`, `salt`, `nonce`, `ciphertext`) is plaintext JSON. This is standard and expected. However, the backup file extension and structure could identify the file as a Memory Vault backup. This is informational only.

### 2.4 Skill/Module Signing and Sandboxing

| Check | Status | Notes |
|-------|--------|-------|
| All skills/modules cryptographically signed | MISSING | No module signing |
| Manifest required | MISSING | No `permissions.manifest` file |
| Skills run in sandbox | N/A | Memory Vault is a library, not a skill loader |
| Update diff review before acceptance | N/A | Standard dependency management via pip |
| No silent network calls | PASS | Verified: no `requests`, `urllib`, `http.client`, or `fetch` calls in codebase |
| Skill provenance tracking | N/A | Not a skill execution platform |

**Finding T2-04 (High): No dependency pinning to specific hashes**
- **File:** `pyproject.toml:39-41`, `requirements.txt`
- **Detail:** Dependencies use version ranges (`pynacl>=1.5.0`) rather than pinned hashes. A supply chain attack on PyNaCl (the sole required dependency providing all cryptographic operations) would compromise the entire system.
- **Recommendation:** Pin dependencies to specific versions with hashes in a lock file:
  ```
  pynacl==1.5.0 --hash=sha256:...
  ```
  Add `pip-audit` to CI pipeline (already in dev dependencies) and run regularly.

**Finding T2-05 (High): HMAC challenge-response authentication is security theater**
- **File:** `physical_token.py:129-180`
- **Detail:** The `_hmac_challenge_response()` function returns `True` if a 32-byte secret file exists at `~/.memory_vault/token_challenge`, without actually communicating with any hardware token. This means Level 5 (Black) classification memories can be accessed by anyone with filesystem access to the secret file, completely bypassing the intended hardware token requirement.
- **Impact:** If FIDO2 is unavailable (common - requires physical USB device) and HMAC secret exists, Level 5 authentication is reduced to a file-existence check. The TOTP fallback is more secure (requires knowing a time-based code).
- **Current Mitigation:** The code does emit a `UserWarning` and log a warning, but does not prevent authentication from succeeding.
- **Recommendation:** Change `_hmac_challenge_response()` to return `False` by default with a clear error message. Only return `True` when actual YubiKey HID communication is implemented. The current behavior should be opt-in via an explicit `MEMORY_VAULT_ALLOW_HMAC_FILE_ONLY=1` environment variable with prominent warnings.

### Quick Scan Results (Tier 2)

| Scan | Result |
|------|--------|
| Plaintext secrets (`sk-*`, `AKIA*`, passwords) | 1 match: example file only (non-production) |
| Hardcoded URLs / fetch-and-execute | 0 matches |
| Shell execution (`subprocess`, `os.system`, `exec`, `eval`) | 0 matches |
| Unsafe deserialization (`pickle`, `yaml.load`) | 0 matches in code; 1 reference in old audit report (already fixed) |
| Never-commit files (`.pem`, `.key`, `.env`, `.p12`, `id_rsa`) | Properly covered by `.gitignore` |

---

## TIER 3: Protocol-Level Maturity

### 3.1 Constitutional Audit Trail

| Check | Status | Notes |
|-------|--------|-------|
| Every agent decision logged with reasoning chain | PASS | `recall_log` captures `request_id`, `memory_id`, `requester`, `timestamp`, `approved`, `justification` |
| Logs append-only and tamper-evident | PASS | Merkle tree with Ed25519 signed roots; hash chain prevents retroactive modification |
| Human-readable audit format | PASS | FTS5 search on justifications; CLI `search-justifications` command |
| Constitutional violations logged separately | PARTIAL | Denied recalls are logged with reason, but no separate violation log |
| Retention policy defined | PARTIAL | Ephemeral (Level 0) has auto-purge; no retention policy for audit logs |

**Finding T3-01 (Medium): Audit logs have no retention or archival policy**
- **Detail:** The `recall_log` and `merkle_leaves` tables grow unboundedly. For long-running vaults, this could become a performance issue and complicate compliance. There is no mechanism to archive or rotate audit logs while preserving the Merkle tree integrity.
- **Recommendation:** Implement log archival that exports signed Merkle root snapshots before pruning old leaves. The signed roots serve as non-repudiation checkpoints.

**Finding T3-02 (Medium): Merkle tree is rebuilt from scratch on every recall**
- **File:** `vault.py:446-466`
- **Detail:** Every `_log_recall()` call executes `SELECT leaf_hash FROM merkle_leaves ORDER BY leaf_id` and rebuilds the entire Merkle tree. For a vault with N recall events, this is O(N) per recall. At scale, this becomes a performance bottleneck.
- **Recommendation:** Maintain an incremental Merkle tree that appends leaves without full reconstruction. Store intermediate nodes or use a persistent tree structure.

### 3.2 Mutual Agent Authentication

| Check | Status | Notes |
|-------|--------|-------|
| Challenge-response authentication before inter-agent data exchange | N/A | Single-owner, single-agent system |
| Trust levels for peer agents | N/A | No peer agent interaction |
| Communication channel integrity | PASS | Boundary daemon uses Unix socket (local-only, kernel-enforced ACL) |
| No fetch-and-execute from peer agents | PASS | No remote code execution capability |
| Human principal visibility of all agent-to-agent comms | N/A | No agent-to-agent communication |

**No findings.** Memory Vault is a single-owner storage system that does not participate in inter-agent communication. The boundary daemon protocol is local-only and uses JSON control messages.

### 3.3 Anti-C2 Pattern Enforcement

| Check | Status | Notes |
|-------|--------|-------|
| No periodic fetch-and-execute patterns | PASS | No scheduled tasks, no remote content fetching |
| Remote content treated as data only | PASS | No remote content ingestion |
| Dependency pinning to specific versions/hashes | FAIL | See Finding T2-04 |
| Update mechanism requires human approval | PASS | Standard pip update; no auto-update |
| Anomaly detection on outbound patterns | N/A | No outbound network activity |

**No additional findings.** Memory Vault has zero network surface area beyond the local Unix socket to the boundary daemon.

### 3.4 Vibe-Code Security Review Gate

| Check | Status | Notes |
|-------|--------|-------|
| Security-focused review on AI-generated code | ADVISORY | Prior audit report (`AUDIT_REPORT.md`) exists; this audit extends it |
| Automated scanning in CI | PARTIAL | `ruff` with `flake8-bandit` rules configured; `pip-audit` in dev deps; no CI pipeline file found |
| Default-secure configurations | PASS | Fail-closed design; boundary daemon denial is the default |
| Database access controls verified | PARTIAL | See findings T1-02, T1-03 |
| Attack surface checklist pre-deployment | PASS | `SECURITY.md` and `docs/PRODUCTION_READINESS.md` exist |

**Finding T3-03 (Low): No CI pipeline configuration found**
- **Detail:** While `ruff`, `pytest`, `pip-audit`, and `pre-commit` are listed as dev dependencies, no CI configuration file (`.github/workflows/*.yml`, `.gitlab-ci.yml`, etc.) was found. Security scanning tools are available but may not be enforced.
- **Recommendation:** Add a CI pipeline that runs:
  1. `ruff check` (includes bandit security rules)
  2. `pytest` with coverage
  3. `pip-audit` for dependency vulnerabilities
  4. Secret scanning (e.g., `trufflehog` or `detect-secrets`)

**Finding T3-04 (High): Signing key file has TOCTOU race in permission setting**
- **File:** `crypto.py:343-348`
- **Detail:**
  ```python
  with open(SIGNING_KEY_PATH, "wb") as f:
      os.chmod(SIGNING_KEY_PATH, 0o600)  # File already exists with default perms
      f.write(sk.encode())
  ```
  The file is created with default permissions, then `chmod` is called. Between file creation and `chmod`, the private key material is world-readable. Compare with the keyfile generation (`crypto.py:76-78`) which correctly uses `os.fchmod(f.fileno(), 0o600)` before writing.
- **Recommendation:** Use the same pattern as `generate_keyfile()`:
  ```python
  with open(SIGNING_KEY_PATH, "wb") as f:
      os.fchmod(f.fileno(), 0o600)
      f.write(sk.encode())
  ```

### 3.5 Agent Coordination Boundaries

| Check | Status | Notes |
|-------|--------|-------|
| All inter-agent coordination visible to human principal | N/A | Single-agent system |
| Rate limiting on agent-to-agent interactions | N/A | No agent-to-agent interaction |
| Collective action requires human approval | N/A | Not applicable |
| Constitutional transparency rule | PASS | All operations logged in audit trail |
| No autonomous hierarchy formation | N/A | Single-owner model |

**No findings.** Memory Vault's single-owner architecture inherently prevents the coordination boundary issues seen in Moltbook.

---

## Additional Security Findings (Beyond Checklist)

### A-01 (Low): Cooldown bypass via system clock manipulation
- **File:** `vault.py:356-366`
- **Detail:** Cooldown enforcement uses `datetime.now(timezone.utc)` which relies on the system clock. An attacker with system access could bypass cooldowns by advancing the system clock.
- **Mitigation:** This requires local system access, which also implies access to the database file. The threat model assumes the local system is trusted. For hardened deployments, consider using monotonic timestamps.

### A-02 (Low): Public key file for signing key has no permission restriction
- **File:** `crypto.py:347-348`
- **Detail:** The `.pub` file is written without permission restrictions. This is acceptable since it's a public key, but for consistency and to prevent confusion, it could be set to `0o644`.

### A-03 (Low): exit_lockdown passphrase verification is ineffective
- **File:** `vault.py:1006-1019`
- **Detail:** The `exit_lockdown()` method derives a key from the provided passphrase but doesn't verify it against anything meaningful. It just calls `derive_key_from_passphrase(passphrase)` which always succeeds (Argon2id will derive a key from any input). The passphrase is not verified against any stored profile key.
- **Recommendation:** Verify the passphrase against a known profile by attempting to decrypt a known value, or store a passphrase verification hash during lockdown.

---

## Audit Completion Matrix

| Repo | Date Audited | Tier 1 | Tier 2 | Tier 3 | Notes |
|------|--------------|--------|--------|--------|-------|
| memory-vault | 2026-02-20 | MOSTLY PASS | PARTIAL | PARTIAL | 15 findings total; 0 critical |

---

## Findings Summary

| ID | Severity | Title | File(s) | Status |
|----|----------|-------|---------|--------|
| T1-01 | Low | Example file contains mock API key pattern | `examples/langchain_memory.py:90` | Open |
| T1-02 | Low | Database directory created without explicit permissions | `db.py:8` | Open |
| T1-03 | Medium | SQLite database file has no explicit file permissions | `db.py:35` | Open |
| T2-01 | Medium | No content integrity verification on recall | `vault.py:260-426` | Open |
| T2-02 | Medium | No MemoryAuditor for injection pattern detection | N/A | Open |
| T2-03 | Low | Backup files may contain metadata in plaintext | `vault.py:579-604` | Informational |
| T2-04 | High | No dependency pinning to specific hashes | `pyproject.toml:39-41` | Open |
| T2-05 | High | HMAC challenge-response is security theater | `physical_token.py:129-180` | Open (known, documented) |
| T3-01 | Medium | Audit logs have no retention or archival policy | `vault.py`, `db.py` | Open |
| T3-02 | Medium | Merkle tree rebuilt from scratch on every recall | `vault.py:446-466` | Open |
| T3-03 | Low | No CI pipeline configuration found | N/A | Open |
| T3-04 | High | Signing key file has TOCTOU race in permission setting | `crypto.py:343-348` | Open |
| A-01 | Low | Cooldown bypass via system clock manipulation | `vault.py:356-366` | Accepted Risk |
| A-02 | Low | Public key file has no permission restriction | `crypto.py:347-348` | Informational |
| A-03 | Low | exit_lockdown passphrase verification is ineffective | `vault.py:1006-1019` | Open |

---

## Positive Security Observations

The following security practices are commendable and should be preserved:

1. **Cryptographic primitives are correct.** XSalsa20-Poly1305 via libsodium/PyNaCl provides authenticated encryption with constant-time operations. Argon2id with `OPSLIMIT_SENSITIVE` and `MEMLIMIT_SENSITIVE` (1GB) is the strongest available KDF configuration.

2. **No unsafe deserialization.** The previous audit identified `pickle` usage for TPM blobs; this has been fixed. All serialization now uses JSON with base64 encoding (`crypto.py:206-211`).

3. **No shell execution.** Zero instances of `subprocess`, `os.system()`, `exec()`, or `eval()` in the codebase. No command injection surface.

4. **No network surface.** The only external I/O is a local Unix domain socket to the boundary daemon. No HTTP clients, no outbound network calls, no remote content fetching. This eliminates entire categories of vulnerabilities (SSRF, C2, data exfiltration via network).

5. **Fail-closed design.** The boundary daemon client defaults to deny when the daemon is unreachable (`boundary.py:246-251`). Lockdown mode blocks all recalls. Classification gates require escalating approval.

6. **Profile ID validation prevents path traversal.** `validate_profile_id()` enforces `^[a-zA-Z0-9][a-zA-Z0-9_-]*$` pattern, preventing `../../etc/passwd` style attacks on keyfile paths.

7. **Keyfile permissions are correct.** `generate_keyfile()` uses `os.fchmod(f.fileno(), 0o600)` before writing, eliminating the TOCTOU window.

8. **Ed25519 signed Merkle roots.** Every audit trail root is cryptographically signed, providing non-repudiation and tamper evidence.

9. **No plaintext persistence.** Decrypted content exists only in memory. The `MemoryObject.content_plaintext` field is documented as "in-memory only, never stored."

10. **Tombstone system preserves audit trail.** Memories can be made inaccessible without destroying audit evidence.

---

## Recommendations by Priority

### Immediate (Before Next Release)

1. **Fix TOCTOU race in signing key creation** (T3-04) - Use `os.fchmod()` instead of `os.chmod()` in `crypto.py:343-348`
2. **Disable HMAC file-only authentication** (T2-05) - Default to `False` unless explicitly opted in
3. **Set database file permissions** (T1-03) - `os.chmod(path, 0o600)` after `sqlite3.connect()`
4. **Set database directory permissions** (T1-02) - `mode=0o700` in `os.makedirs()`

### Short-Term (Next 2-3 Releases)

5. **Add post-decryption hash verification** (T2-01) - Defense-in-depth integrity check
6. **Fix exit_lockdown passphrase verification** (A-03) - Actually verify against stored profile
7. **Pin dependencies with hashes** (T2-04) - Supply chain protection
8. **Add CI pipeline** (T3-03) - Enforce automated security scanning

### Long-Term

9. **Implement incremental Merkle tree** (T3-02) - Performance at scale
10. **Add audit log archival** (T3-01) - Compliance and performance
11. **Implement MemoryAuditor hook** (T2-02) - Injection pattern detection
12. **Full FIDO2 credential lifecycle** - Replace device-presence-only check
13. **Full HMAC YubiKey HID integration** - Replace file-existence check

---

## Methodology Notes

This audit was conducted by reviewing all source files in the repository against the Agent-OS Post-Moltbook Hardening Guide v1.0 checklist. The following automated scans were performed:

- **Plaintext secret scan:** Regex search for API key patterns (`sk-*`, `AKIA*`), passwords, tokens across all file types
- **Shell execution scan:** Search for `subprocess`, `os.system()`, `exec()`, `eval()`, `__import__` in Python files
- **Unsafe deserialization scan:** Search for `pickle.load`, `pickle.loads`, `yaml.load()`, `yaml.unsafe`
- **Network activity scan:** Search for `requests.get`, `urllib.request`, `urlopen`, `fetch()`, `http.client`
- **Sensitive file scan:** Verify `.gitignore` coverage for `.pem`, `.key`, `.env`, `.p12`, `id_rsa`
- **File permission audit:** Review all `chmod`, `fchmod`, `umask` usage for correctness
- **Git history review:** Check deleted files and commit history for leaked credentials

All findings are based on static code analysis. Dynamic testing (fuzzing, penetration testing, hardware validation) was not performed and is recommended as a follow-up.

---

*End of Security Audit Report*
