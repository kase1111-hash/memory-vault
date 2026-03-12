# Fix Plan: All 12 Security Audit Findings

## HIGH Priority (Fix First)

### H1: In-Memory Key Cache Never Expires or Wipes
**Files:** `vault.py`
**Changes:**
- Replace `self.profile_keys = {}` with a TTL-based cache (5-minute expiry)
- Add `_clear_key_cache()` method that zeros out bytes before deleting
- Call `_clear_key_cache()` in `close()` and `shutdown()`
- Add `__del__` fallback to wipe keys on garbage collection

### H2: No Signing Key Revocation Mechanism
**Files:** `crypto.py`, `db.py`, `vault.py`
**Changes:**
- Add `key_epoch` column to `merkle_roots` table (migration in `db.py`)
- Add `rotate_signing_key()` to `crypto.py` that archives old public key and generates new one
- Store key epoch in signed Merkle roots so verifiers know which key version to use
- Add `revoked_signing_keys` table to track revoked keys with revocation timestamps

### H3: `skip_boundary_check` Bypasses Security
**Files:** `vault.py`
**Changes:**
- Remove `skip_boundary_check` parameter from `recall_memory()` public API
- Gate the bypass behind `MEMORY_VAULT_TESTING=1` environment variable check instead
- Document that this env var must never be set in production

---

## MEDIUM Priority (Fix Second)

### M1: `created_by` Field Is Unauthenticated
**Files:** `models.py`, `vault.py`
**Changes:**
- Define `VALID_CREATORS = {"agent", "human", "system"}` enum/set in `models.py`
- Validate `created_by` against the allowed set in `store_memory()`
- Raise `ValueError` for invalid values

### M2: LIKE-Based SQL in IntentLog Allows Wildcard Injection
**Files:** `intentlog.py`
**Changes:**
- Add a `_escape_like()` helper that escapes `%`, `_`, and `\` characters
- Apply it in `get_memories_for_intent()` (line 133) and `search_by_intent()` (line 217)
- Use `ESCAPE '\'` clause in the LIKE queries

### M3: Database Initialization at Import Time
**Files:** `db.py`
**Changes:**
- Remove the module-level `_conn = init_db(); _conn.close()` (lines 357-358)
- Add a `_initialized = False` flag and `ensure_initialized()` function
- Call `ensure_initialized()` lazily from `get_connection()` and `init_db()` when first needed

### M4: Error Messages Leak Internal Details
**Files:** `vault.py`, `deadman.py`, `crypto.py`
**Changes:**
- In `recall_memory()`: log detailed error with `logger.error()`, raise with generic message
- In `deadman.py:add_heir()`: log `f"Invalid public key: {e}"`, print generic "Invalid public key format"
- In `crypto.py` TPM functions: log details, raise with `"TPM operation failed"` only
- Apply same pattern to all `except Exception as e` blocks that expose `{e}` to callers

### M5: Incomplete Lock File
**Files:** `requirements-lock.txt`
**Changes:**
- Generate complete lock file covering all optional dependencies with hashes
- Pin `fido2`, `pyotp`, and their transitive deps
- Add a comment documenting how to regenerate

---

## LOW Priority (Fix Last)

### L1: SealedBox Validation in deadman.py Is Incorrect
**Files:** `deadman.py`
**Changes:**
- Line 65: Change `SealedBox(pubkey_bytes)` to `SealedBox(PublicKey(pubkey_bytes))`
- Add `from nacl.public import PublicKey` import (already has `SealedBox`)

### L2: `is_deadman_triggered` Naive Datetime Comparison
**Files:** `deadman.py`
**Changes:**
- Line 158: Change `datetime.fromisoformat(row[1].rstrip("Z"))` to
  `datetime.fromisoformat(row[1].rstrip("Z")).replace(tzinfo=timezone.utc)`
- Ensures aware-to-aware comparison works on Python 3.12+

### L3: Signing Key Generated Eagerly
**Files:** `vault.py`
**Changes:**
- Change `self.signing_key = load_or_create_signing_key()` to a `@property` with lazy init
- Only load/create when first Merkle operation needs it

### L4: `vault.close()` Doesn't Clear Key Cache
**Files:** `vault.py`
**Changes:**
- Add `self.profile_keys.clear()` to `close()` method
- (This is partially addressed by H1, but the `.clear()` call is the minimal fix)

---

## Implementation Order

1. **L4** + **L1** + **L2** — trivial one-line fixes, do first
2. **M1** + **M2** + **M3** + **M4** — medium complexity, independent of each other
3. **H3** — remove `skip_boundary_check` parameter
4. **H1** — TTL key cache (most code change)
5. **H2** — signing key revocation (schema change + new functions)
6. **M5** — lock file regeneration (last, since it's a generated artifact)
7. **L3** — lazy signing key (depends on H2 design)

## Testing Strategy

- Run existing test suite after each group of fixes to ensure no regressions
- Add specific tests for:
  - Key cache expiry behavior (H1)
  - Signing key rotation (H2)
  - `created_by` validation rejection (M1)
  - LIKE escape correctness (M2)
  - Lazy DB init (M3)
  - Datetime-aware comparison in deadman (L2)
