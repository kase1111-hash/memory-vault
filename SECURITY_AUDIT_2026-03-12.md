# Agentic Security Audit v3.0 - Memory Vault

```
AUDIT METADATA
  Project:       memory-vault
  Date:          2026-03-12
  Auditor:       claude-opus-4-6
  Commit:        0bba244f5ecdbdace68eded28d94a5e88c1f0ac5
  Strictness:    STANDARD
  Context:       PROTOTYPE

PROVENANCE ASSESSMENT
  Vibe-Code Confidence:   75%
  Human Review Evidence:  MINIMAL

LAYER VERDICTS
  L1 Provenance:       WARN
  L2 Credentials:      WARN
  L3 Agent Boundaries: WARN
  L4 Supply Chain:     WARN
  L5 Infrastructure:   WARN
```

---

## L1: PROVENANCE & TRUST ORIGIN

### 1.1 Vibe-Code Detection

| Indicator | Status | Evidence |
|-----------|--------|----------|
| No tests | PARTIAL | Tests exist (`tests/`) but are shallow mocks; no integration tests exercise real encrypt/decrypt round-trips |
| No security config | PASS | `.env` in `.gitignore`, file permissions set (0o600/0o700), pre-commit hooks configured |
| AI boilerplate | DETECTED | Uniform formatting across all files, tutorial-style comments, commit messages like "Complete Memory Vault implementation with all missing features" |
| Rapid commit history | DETECTED | 106 commits spanning Dec 2025 - Feb 2026; massive initial commit (`81cdc29 Complete Memory Vault implementation with all missing features`); 36 PRs all from `claude/` branches |
| Polished README, hollow codebase | PARTIAL | Extensive documentation (SPECIFICATION.md, RECOVERY.md, INTEGRATIONS.md, etc.) but several modules are experimental stubs |
| Bloated deps | PASS | Minimal dependencies (pynacl core, optional fido2/pyotp/tpm2-pytss) |

**Assessment:** Strong vibe-code indicators. Every PR branch is prefixed `claude/`, meaning an AI agent authored essentially the entire codebase. There is minimal evidence of human security review beyond the AI-generated audit documents. However, the project handles no PII/payments and is clearly labeled alpha, so severity is **WARN** rather than CRITICAL.

### 1.2 Human Review Evidence

- [x] Security-focused commits exist (`Fix all 15 security audit findings`, `Fix FIDO2 silent authentication bypass`)
- [x] Security tooling in CI/CD: ruff with bandit rules, pip-audit, detect-secrets, bandit scan
- [x] `.gitignore` excludes `.env`, `*.key`, `signing_key`, `*.db`
- [ ] No threat model document found
- [ ] No evidence of human-authored security commits (all from `claude/` branches)

### 1.3 The "Tech Preview" Trap

- [ ] No production traffic or real users (alpha status appropriate)
- [x] Real credentials would be handled (passphrases, signing keys) if deployed
- [x] Alpha label is honest and consistent with maturity

**L1 Verdict: WARN** — AI-generated codebase with security tooling but no evidence of human security review.

---

## L2: CREDENTIAL & SECRET HYGIENE

### 2.1 Secret Storage

| Check | Status | Details |
|-------|--------|---------|
| Plaintext creds in files | PASS | Passphrases are never stored; keys derived via Argon2id |
| API keys in client-side code | N/A | No web frontend |
| Deleted creds in git history | PASS | No secrets found in git log for `*.env`, `*.key`, `*secret*` files |
| `.env` committed | PASS | `.env` is in `.gitignore` |
| Secrets in git history | NOT TESTED | `gitleaks` not run; recommend running |

### 2.2 Credential Scoping & Lifecycle

| Check | Status | Details |
|-------|--------|---------|
| Minimum permissions | WARN | Key files use 0o600, directories 0o700 — good. But `profile_keys` dict caches derived keys **in-memory indefinitely** (`vault.py:84,192`) with no expiry or secure wipe |
| Rotation mechanism | PASS | `rotate_profile_key` exists in vault |
| Per-user isolation | PASS | Each profile has its own key material |
| Credential delegation chain | WARN | Passphrase flows: `getpass` -> `derive_key_from_passphrase` -> `profile_keys` dict. No zeroization of passphrase string or derived key from memory |

### 2.3 Machine Credential Exposure

| Check | Status | Details |
|-------|--------|---------|
| Signing key protection | WARN | Ed25519 signing key stored as raw bytes in `~/.memory_vault/signing_key` with 0o600 permissions. Adequate for prototype, insufficient for production (should use OS keyring or HSM) |
| Key revocation | FAIL | No mechanism to revoke a compromised signing key. All signed Merkle roots become untrustworthy if key leaks |
| Billing attack surface | N/A | No paid APIs |

**L2 Verdict: WARN** — Good filesystem permissions and no plaintext storage, but in-memory key caching without expiry and no key revocation mechanism.

---

## L3: AGENT BOUNDARY ENFORCEMENT

### 3.1 Agent Permission Model

| Check | Status | Details |
|-------|--------|---------|
| Default permissions | PASS | Deny-by-default for high-classification memories (Level 3+ requires human approval, Level 5 requires physical token) |
| Privilege escalation | WARN | `skip_boundary_check=True` parameter on `recall_memory` (`vault.py:275`) bypasses boundary daemon. Any caller with code access can skip this check |
| File system boundaries | WARN | No sandbox. `db.py:7-8` creates `~/.memory_vault/` at **import time** unconditionally |
| Least-privilege | PASS | Classification levels (0-5) with escalating requirements |
| Human-in-the-loop | PASS | Level 3+ requires interactive approval; Level 5 requires physical token |

### 3.2 Prompt Injection Defense

| Check | Status | Details |
|-------|--------|---------|
| Input sanitization | PARTIAL | `validate_profile_id` prevents path traversal. But `memory_id` (UUIDs) and `justification` strings are not sanitized before SQL insertion (parameterized queries protect against SQLi, but FTS MATCH queries at `intentlog.py:133,217` use LIKE with `%{query}%` pattern) |
| Output validation | N/A | No LLM outputs processed |
| System/user separation | N/A | CLI tool, not an agent-facing API |

### 3.3 Memory Poisoning

| Check | Status | Details |
|-------|--------|---------|
| Long-term memory | YES | This IS a long-term memory system |
| Source tracking | PARTIAL | `created_by` field exists but is a free-text string ("agent" or "human") with no verification |
| Audit/purge capability | PASS | Tombstoning, ephemeral purge, and Merkle audit trail exist |
| Untrusted source isolation | FAIL | No isolation between memories from different sources. An agent writing `created_by="human"` is indistinguishable from actual human input |

### 3.4 Agent-to-Agent Trust

| Check | Status | Details |
|-------|--------|---------|
| Agent identity verification | FAIL | No authentication for callers. Any process that can import the module can store/recall |
| Capability delegation | N/A | Single-user system |

**L3 Verdict: WARN** — Good classification-gated access model, but `skip_boundary_check` bypass, no caller authentication, and no source verification for `created_by` field.

---

## L4: SUPPLY CHAIN & DEPENDENCY TRUST

### 4.1 Plugin/Skill Supply Chain

N/A — No plugin system.

### 4.2 MCP Server Trust

N/A — No MCP servers.

### 4.3 Dependency Audit

| Check | Status | Details |
|-------|--------|---------|
| Audit tool configured | PASS | `pip-audit` in CI, `pip-audit` in dev dependencies |
| Stale dependencies | PASS | `requirements-lock.txt` dated 2026-02-20 (3 weeks old) |
| Version pinning | PARTIAL | `requirements-lock.txt` pins `pynacl==1.6.2` with hash, but only covers 1 of 4 dependencies. `requirements.txt` uses `>=` ranges |
| Transitive dependencies | WARN | Only direct dependency `pynacl` is hash-pinned. Optional deps (`fido2`, `pyotp`, `tpm2-pytss`) have no lock file entries |
| Pre-commit hook versions | WARN | `pre-commit-config.yaml` pins `ruff-pre-commit` to `v0.1.9` but `pyproject.toml` requires `ruff>=0.1.0` — version drift possible |

**L4 Verdict: WARN** — Good CI auditing, but incomplete lock file (only 1 of 4+ deps hash-pinned).

---

## L5: INFRASTRUCTURE & RUNTIME

### 5.1 Database Security

| Check | Status | Details |
|-------|--------|---------|
| Access control | PARTIAL | SQLite file has 0o600 permissions. No Row Level Security (SQLite doesn't support it). Any process running as the file owner has full access |
| Public accessibility | PASS | Local file only, no network exposure |
| Connection string in client | N/A | Local SQLite |
| Read/write separation | FAIL | Single connection used for all operations. No read-only mode for queries |

### 5.2 Network & Hosting

| Check | Status | Details |
|-------|--------|---------|
| HTTPS | N/A | Offline-first, no network service |
| CORS | N/A | No web server |
| Rate limiting | PASS | Cooldown mechanism serves as rate limiting for recalls |
| Error message leakage | WARN | Several `except Exception as e` blocks print full error messages including internal details (`vault.py:414`, `deadman.py:66`) |
| Security logging | PASS | Recall audit log with Merkle tree tamper evidence |

### 5.3 Deployment Pipeline

| Check | Status | Details |
|-------|--------|---------|
| Pinned CI actions | PASS | `actions/checkout@v4`, `actions/setup-python@v5` — major version pins (acceptable) |
| Secrets in artifacts | PASS | No secrets baked into builds |
| Environment isolation | N/A | Single-user local tool |
| Rollback capability | N/A | No deployment pipeline |

**L5 Verdict: WARN** — Appropriate for offline-first prototype. SQLite permissions are good. Error messages leak internals.

---

## FINDINGS

### [HIGH] — In-Memory Key Cache Never Expires or Wipes
```
Layer:     L2
Location:  vault.py:84,162,192,236,408
Evidence:  self.profile_keys[profile_id] = key — derived keys stored in a plain
           dict with no TTL, no secure wipe, and no maximum cache size.
           Keys persist for the lifetime of the MemoryVault object.
Risk:      Memory dump, core dump, or swap file could expose all cached keys.
           Long-running processes accumulate keys indefinitely.
Fix:       1. Add TTL-based expiry (e.g., 5 minutes)
           2. Use a SecureString/mlock wrapper to prevent swapping
           3. Wipe keys on vault.close() — currently close() only closes
              the DB connection, not the key cache
```

### [HIGH] — No Signing Key Revocation Mechanism
```
Layer:     L2
Location:  crypto.py:315-351, merkle.py, vault.py (Merkle signing)
Evidence:  Ed25519 signing key is generated once and stored forever.
           No rotation, revocation, or key versioning for Merkle root signatures.
Risk:      If signing key is compromised, all existing Merkle proofs become
           untrustworthy. Attacker can forge audit trail entries.
Fix:       1. Add signing key rotation with epoch/version tracking
           2. Store key version in merkle_roots table
           3. Implement key revocation list
```

### [HIGH] — `skip_boundary_check` Parameter Bypasses Security
```
Layer:     L3
Location:  vault.py:275,340
Evidence:  recall_memory(skip_boundary_check=True) skips the boundary daemon
           permission check entirely. Documented "for testing" but available
           in production API.
Risk:      Any caller can bypass boundary enforcement by passing this flag.
           Defeats the purpose of the boundary daemon security layer.
Fix:       1. Remove the parameter from the public API
           2. If needed for testing, use dependency injection or mock
           3. Or gate behind an environment variable (MEMORY_VAULT_TESTING=1)
```

### [MEDIUM] — `created_by` Field Is Unauthenticated
```
Layer:     L3
Location:  models.py:9, vault.py:251
Evidence:  created_by defaults to "agent" and is a free-text string with no
           verification. Any caller can set created_by="human" or any value.
Risk:      Memory provenance cannot be trusted. An agent can masquerade as
           a human for memories that may later be treated with different
           trust levels.
Fix:       Validate created_by against an enum. For stronger guarantees,
           sign the memory record including created_by with the vault's
           signing key at storage time.
```

### [MEDIUM] — LIKE-Based SQL Pattern in IntentLog Allows Wildcard Injection
```
Layer:     L3
Location:  intentlog.py:133,217
Evidence:  WHERE intent_ref LIKE ? with f'%{intent_id}%' allows callers to
           inject SQL LIKE wildcards (%, _) through intent_id values.
Risk:      Not SQL injection (parameterized), but allows unintended broad
           matching. An intent_id of "%" matches all records.
Fix:       Escape LIKE special characters in user input before interpolation,
           or use JSON functions (json_each) for exact matching.
```

### [MEDIUM] — Database Initialization at Import Time
```
Layer:     L5
Location:  db.py:357-358
Evidence:  _conn = init_db() runs unconditionally when db.py is imported.
           Creates directories and database files as a side effect of import.
Risk:      Importing the module for testing, type checking, or documentation
           creates real filesystem artifacts. Breaks principle of least surprise.
Fix:       Use lazy initialization. Only create the database on first actual use.
```

### [MEDIUM] — Error Messages Leak Internal Details
```
Layer:     L5
Location:  vault.py:414, deadman.py:66-67, crypto.py:149-150
Evidence:  Exceptions include full error messages: f"Key access failed: {e}",
           f"TPM primary creation failed: {e}", f"Invalid public key: {e}"
Risk:      Stack traces and internal error details could aid attacker
           reconnaissance if exposed through a future API layer.
Fix:       Log detailed errors internally; return generic error messages to callers.
```

### [MEDIUM] — Incomplete Lock File
```
Layer:     L4
Location:  requirements-lock.txt
Evidence:  Only pynacl==1.6.2 is hash-pinned. Optional dependencies (fido2,
           pyotp, tpm2-pytss) and their transitive dependencies are unpinned.
Risk:      Supply chain attack via compromised optional dependency update.
Fix:       Generate complete lock file with hashes for all dependencies:
           pip-compile --generate-hashes requirements.txt > requirements-lock.txt
```

### [LOW] — SealedBox Validation in deadman.py Is Incorrect
```
Layer:     L3
Location:  deadman.py:64-65
Evidence:  SealedBox(pubkey_bytes) — SealedBox() takes a PublicKey object,
           not raw bytes. This line would raise TypeError at runtime when
           adding an heir.
Risk:      Dead-man switch heir registration silently fails with unhelpful error.
Fix:       Use SealedBox(PublicKey(pubkey_bytes)) for proper validation.
```

### [LOW] — `is_deadman_triggered` Uses Naive Datetime Comparison
```
Layer:     L5
Location:  deadman.py:158-159
Evidence:  deadline = datetime.fromisoformat(row[1].rstrip("Z")) creates a
           naive datetime, then compares with datetime.now(timezone.utc) which
           is timezone-aware. This raises TypeError in Python 3.12+.
Risk:      Dead-man switch may never trigger (comparison fails silently depending
           on Python version).
Fix:       Parse as aware datetime:
           deadline = datetime.fromisoformat(row[1].rstrip("Z")).replace(tzinfo=timezone.utc)
```

### [LOW] — Signing Key Generated on Every MemoryVault Instantiation
```
Layer:     L2
Location:  vault.py:85
Evidence:  self.signing_key = load_or_create_signing_key() is called in __init__.
           If TPM is unavailable and no key file exists, this generates a new
           key and writes to disk on every instantiation (until the first run
           creates the file).
Risk:      Minor — only affects first run. But prints to stdout during import,
           which is surprising for library consumers.
Fix:       Use lazy initialization for the signing key.
```

### [LOW] — `vault.close()` Does Not Clear Key Cache
```
Layer:     L2
Location:  vault.py:94-98
Evidence:  close() only closes the DB connection. self.profile_keys dict
           retains all cached keys even after close.
Risk:      Keys accessible after vault is "closed". Code that calls
           vault.close() expects cleanup.
Fix:       Add self.profile_keys.clear() in close().
```

---

## SUMMARY

Memory Vault is a well-structured prototype with strong cryptographic foundations (XSalsa20-Poly1305, Argon2id, Ed25519) and a thoughtful classification-gated access model. The project is honest about its alpha status and the experimental nature of several modules (zkproofs, escrow, deadman, physical_token).

**Strengths:**
- Solid encryption primitives (pynacl/libsodium)
- Classification-based access control (Levels 0-5) with escalating security
- Merkle tree audit trail with signed roots
- Profile ID validation prevents path traversal
- File permissions properly restricted (0o600/0o700)
- CI pipeline includes linting, bandit, pip-audit, detect-secrets
- Pre-commit hooks with security checks

**Key Risks:**
- Entire codebase is AI-generated with no evidence of human security review
- In-memory key cache has no expiry or secure wipe
- No signing key revocation mechanism
- `skip_boundary_check` parameter undermines boundary enforcement
- Incomplete dependency lock file
- Several datetime/type bugs in experimental modules

**Recommendation:** Suitable as an alpha prototype for local, single-user use. Before any multi-user or production deployment: (1) conduct a human-led security review, (2) fix HIGH findings, (3) complete the dependency lock file, and (4) add integration tests that exercise real encrypt/decrypt/recall flows.
