# Memory Vault Security and Correctness Audit Report

**Audit Date:** January 28, 2026
**Auditor:** Automated Code Audit
**Version:** v0.1.0-alpha
**Repository:** memory-vault

---

## Executive Summary

Memory Vault is a sophisticated cryptographic storage system for AI agent ecosystems. The audit identified **3 critical issues**, **5 high-severity issues**, and **12 medium/low issues** across correctness, security, and code quality. The core cryptographic primitives are sound, but several implementation issues require attention before production use.

**Overall Assessment:** The software is well-designed and functional for its intended purpose as an alpha release, but several correctness and security issues must be addressed before production deployment.

---

## Critical Issues

### C-1: Test-API Contract Mismatch in Merkle Module

**File:** `merkle.py:9`, `tests/test_merkle.py`
**Severity:** Critical
**Type:** Correctness

The `hash_leaf()` function expects a `str` parameter but tests pass `bytes`:

```python
# merkle.py line 9
def hash_leaf(data: str) -> str:
    h = hashlib.sha256(data.encode()).digest()  # Calls .encode() on str
```

```python
# tests/test_merkle.py line 18
data = b"test data for hashing"  # bytes, not str
hash1 = hash_leaf(data)  # AttributeError: 'bytes' object has no attribute 'encode'
```

**Impact:** 11 of 40 tests fail (27.5% failure rate). This indicates either:
1. The API was changed without updating tests, or
2. The tests document intended behavior that was incorrectly implemented

**Recommendation:** Determine the correct contract and fix either the function or tests. If the function should accept bytes, change to:
```python
def hash_leaf(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    h = hashlib.sha256(data).digest()
```

---

### C-2: HMAC Challenge-Response Not Implemented (Security Bypass)

**File:** `physical_token.py:150-172`
**Severity:** Critical
**Type:** Security

The HMAC challenge-response mechanism for Level 5 security does NOT actually verify hardware token response. It only checks if a secret file exists:

```python
def _hmac_challenge_response() -> bool:
    # ... loads secret, computes expected HMAC ...

    # SECURITY WARNING: HMAC challenge-response is NOT fully implemented.
    # This currently only verifies that a secret file exists, not that an
    # actual hardware token responded.
    warnings.warn(...)
    return True  # Always returns True if file exists!
```

**Impact:** Level 5 memories (highest security) can be accessed by anyone who has access to the secret file, without requiring actual hardware token authentication. This completely bypasses the intended security control.

**Recommendation:** Either:
1. Fully implement YubiKey HID communication
2. Remove HMAC from the authentication chain until properly implemented
3. Make the warning more prominent (error instead of warning)

---

### C-3: Deadman Switch PublicKey Type Error

**File:** `deadman.py:59`
**Severity:** Critical
**Type:** Correctness

```python
def add_heir(name: str, public_key_b64: str) -> None:
    try:
        pubkey_bytes = base64.b64decode(public_key_b64)
        SealedBox(pubkey_bytes)  # ERROR: SealedBox expects PublicKey, not bytes
```

**Impact:** Adding heirs to the dead-man switch will fail at runtime with a type error. This breaks the succession planning feature.

**Recommendation:** Fix to:
```python
from nacl.public import PublicKey, SealedBox
pubkey = PublicKey(pubkey_bytes)
SealedBox(pubkey)
```

---

## High-Severity Issues

### H-1: Test Expects None for Empty Tree, Implementation Returns Hash

**File:** `merkle.py:23`, `tests/test_merkle.py:114-116`
**Severity:** High
**Type:** Correctness

```python
# merkle.py
def build_tree(leaves: List[str]) -> Tuple[str, List[List[str]]]:
    if not leaves:
        return hash_leaf(""), []  # Returns hash of empty string

# test expects:
def test_build_tree_empty(self):
    root, proofs = build_tree([])
    assert root is None  # FAILS: actual is hash string
    assert proofs == {}  # FAILS: actual is []
```

**Impact:** API contract is unclear - callers may not handle empty tree case correctly.

---

### H-2: Model Defaults Mismatch

**File:** `models.py`, `tests/test_models.py:42`
**Severity:** High
**Type:** Correctness

```python
# test expects:
assert memory.value_metadata is None

# actual: models.py defaults to {} not None
value_metadata: dict = field(default_factory=dict)
```

**Impact:** Code relying on `None` checks for unset metadata will behave incorrectly.

---

### H-3: File Naming Convention Violation

**File:** `boundry.py`
**Severity:** High
**Type:** Code Quality/Maintainability

The file is named `boundry.py` (misspelled) instead of `boundary.py`. This is imported throughout the codebase as `from .boundry import ...`.

**Impact:**
- Makes codebase harder to search/navigate
- May cause confusion for contributors
- IDE autocomplete may not work as expected

**Recommendation:** Rename to `boundary.py` and update all imports.

---

### H-4: pickle Used for TPM Blob Serialization

**File:** `crypto.py:208-228`
**Severity:** High
**Type:** Security

```python
def tpm_generate_sealed_key() -> bytes:
    # ...
    sealed_blob = {"private": private.marshal(), "public": public.marshal()}
    import pickle
    return pickle.dumps(sealed_blob)

def tpm_unseal_key(sealed_blob: bytes) -> bytes:
    import pickle
    blob_data = pickle.loads(sealed_blob)  # Arbitrary code execution risk
```

**Impact:** If an attacker can modify the sealed_blob stored in the database, they could execute arbitrary code when the blob is unsealed.

**Recommendation:** Use JSON or a safer serialization format for structured data.

---

### H-5: Silent Exception Swallowing in crypto.py

**File:** `crypto.py:116-117`
**Severity:** High
**Type:** Security

```python
def tpm_create_and_persist_primary() -> None:
    try:
        with ESAPI() as esys:
            try:
                esys.ReadPublic(TPM_PRIMARY_HANDLE)
                return
            except:
                pass  # Swallows ALL exceptions silently
```

**Impact:** Legitimate TPM errors (permission issues, hardware failures) are silently ignored, potentially leading to security failures that go unnoticed.

---

## Medium-Severity Issues

### M-1: Database Connection Management

**Files:** `vault.py`, `db.py`
**Severity:** Medium
**Type:** Resource Management

Many database operations create new connections with `sqlite3.connect()` and close them in finally blocks, but the pattern is inconsistent. Some methods use `self.conn` while others create new connections.

Example in `vault.py:255-277`:
```python
conn = sqlite3.connect(self.db_path)  # New connection
try:
    # ... operations ...
finally:
    conn.close()
```

But `recall_memory` uses `self._conn` (line 442) and also creates new connection.

**Recommendation:** Use consistent connection management with context managers.

---

### M-2: Bare Exception Handlers

**File:** `crypto.py:371`, `zkproofs.py:341`
**Severity:** Medium
**Type:** Code Quality

```python
def verify_signature(...) -> bool:
    try:
        # ...
    except:  # Catches everything including KeyboardInterrupt, SystemExit
        return False
```

**Recommendation:** Catch specific exceptions.

---

### M-3: Time-Based Security Without Monotonic Clock

**File:** `vault.py:515`
**Severity:** Medium
**Type:** Security

Cooldown enforcement uses `datetime.utcnow()` which can be affected by system clock changes:

```python
if last_time and (datetime.utcnow() - last_time) < timedelta(seconds=cooldown):
```

**Impact:** Attacker with system access could bypass cooldowns by changing system time.

**Recommendation:** Use `time.monotonic()` for timing-sensitive security checks, or persist monotonic timestamps.

---

### M-4: Missing Input Validation for memory_id

**File:** `vault.py:397-404`
**Severity:** Medium
**Type:** Input Validation

While `profile_id` is validated against path traversal, `memory_id` is not validated. It's used in SQL queries (parameterized, so safe from injection) but could contain unexpected characters.

---

### M-5: FIDO2 Authentication Bypass

**File:** `physical_token.py:106-115`
**Severity:** Medium
**Type:** Security

```python
try:
    options = {"challenge": challenge, ...}
    client.get_assertion(options)
    return True
except Exception:
    # If no credential, just verify device presence
    return True  # Returns True even on failure!
```

**Impact:** If FIDO2 assertion fails for any reason, authentication still succeeds.

---

### M-6: Race Condition in Global Client Initialization

**File:** `boundry.py:415-424`
**Severity:** Medium
**Type:** Concurrency

```python
def get_client(siem_reporter=None) -> BoundaryClient:
    global _global_client
    if _global_client is None:  # Check-then-act pattern
        with _client_lock:
            if _global_client is None:  # Double-checked locking (correct)
```

The double-checked locking is correct, but the first check is outside the lock. This is acceptable for Python due to the GIL but the `siem_reporter` parameter is ignored on subsequent calls.

---

## Low-Severity Issues

### L-1: Print Statements for User Communication

Multiple files use `print()` for user communication instead of a proper logging/messaging framework:

- `vault.py`: ~30+ print statements
- `escrow.py`: ~15 print statements
- `deadman.py`: ~10 print statements

**Recommendation:** Use logging module with configurable output destinations.

---

### L-2: Hardcoded Socket Path

**File:** `boundry.py:29`

```python
SOCKET_PATH = os.path.expanduser("~/.agent-os/api/boundary.sock")
```

**Recommendation:** Make configurable via environment variable.

---

### L-3: Unicode Handling Not Specified

**File:** `crypto.py:47`

```python
password=passphrase.encode('utf-8')
```

Explicit UTF-8 encoding is good, but should document that passphrases must be valid UTF-8.

---

### L-4: Missing Type Hints

**Files:** Various

Some newer Python 3.10+ type hints (e.g., `list[dict]`, `tuple[bool, str]`) are used, limiting compatibility. Consider using `typing` module for broader compatibility.

---

### L-5: Inconsistent Import Style

The codebase uses both relative and absolute imports, sometimes with fallback patterns:

```python
try:
    from .crypto import ...
except ImportError:
    from crypto import ...
```

This is fragile and can mask real import errors.

---

### L-6: No Explicit Database Schema Versioning

**File:** `db.py`

Migrations are handled via "column exists" checks but there's no version number. If schema changes require data migration, this will be problematic.

---

## Test Coverage Analysis

| Test File | Tests | Passed | Failed |
|-----------|-------|--------|--------|
| test_merkle.py | 11 | 0 | 11 |
| test_models.py | 12 | 11 | 1 |
| test_smoke.py | 17 | 17 | 0 |
| **Total** | **40** | **28** | **12** |

**Pass Rate:** 70%

Key findings:
- All merkle tests fail due to type mismatch (C-1)
- Smoke tests pass - core vault functionality works
- Models test has one default value mismatch (H-2)

---

## Fitness for Purpose Assessment

### Intended Purpose
Memory Vault is designed as a "sovereign AI memory storage system" for storing encrypted memories with:
- 6-level classification system
- Owner-controlled encryption
- Tamper-evident audit trails
- Hardware security integration (optional)
- Succession planning features

### Fitness Rating: **7/10 for Alpha Release**

**Strengths:**
1. Core encryption/decryption using NaCl/libsodium is correctly implemented
2. Classification system and access control logic is well-designed
3. Merkle tree audit trail provides strong tamper evidence
4. SIEM integration for security monitoring is comprehensive
5. Fail-closed security model is correctly implemented
6. Backup/restore functionality works correctly

**Weaknesses Affecting Fitness:**
1. Physical token authentication is partially implemented (reduces L5 security)
2. Test failures indicate API instability
3. TPM integration uses unsafe serialization
4. Dead-man switch has type errors preventing use
5. Some security controls can be bypassed

### Production Readiness: **NOT READY**

The following must be addressed before production:
1. Fix all critical issues (C-1, C-2, C-3)
2. Fix high-severity security issues (H-4, H-5)
3. Achieve >95% test pass rate
4. Complete TPM hardware testing
5. Security penetration testing

---

## Recommendations

### Immediate (Before Next Release)

1. **Fix test-API contract mismatches** - Decide on correct behavior and fix
2. **Disable or properly implement HMAC authentication** - Current state is security theater
3. **Fix deadman.py PublicKey type error** - Succession planning is broken
4. **Replace pickle with JSON** in TPM blob serialization

### Short-Term (Next 2-3 Releases)

1. Rename `boundry.py` to `boundary.py`
2. Implement proper connection pooling or consistent connection management
3. Add database schema versioning
4. Replace bare `except:` clauses with specific exception handling
5. Add input validation for memory_id
6. Use monotonic clock for timing-sensitive security

### Long-Term

1. Add comprehensive integration tests
2. Security audit by external party
3. TPM hardware testing
4. FIDO2 full credential lifecycle implementation
5. Consider formal verification of cryptographic protocols

---

## Appendix: Files Reviewed

| File | Lines | Purpose |
|------|-------|---------|
| vault.py | 1,920 | Main MemoryVault class |
| crypto.py | 372 | Cryptographic operations |
| db.py | 439 | Database schema and operations |
| merkle.py | 75 | Merkle tree implementation |
| errors.py | 415 | Exception hierarchy |
| boundry.py | 444 | Boundary daemon client |
| physical_token.py | 327 | Hardware token authentication |
| deadman.py | 252 | Dead-man switch |
| escrow.py | 474 | Shamir secret sharing |
| zkproofs.py | 342 | Zero-knowledge proofs |
| tests/*.py | ~500 | Test suite |

**Total Lines Reviewed:** ~5,560

---

*End of Audit Report*
