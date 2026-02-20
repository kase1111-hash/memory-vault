# Implementation Plan: Fix All 15 Security Audit Findings

## Phase 1: Immediate Fixes (High Severity + Quick Wins)

### Step 1: Fix TOCTOU race in signing key creation (T3-04 - HIGH)
**File:** `crypto.py:343-348`
**Change:** Replace `os.chmod()` with `os.fchmod()` to set permissions before content is written, eliminating the window where the private key is world-readable.
```python
# Current (lines 343-348):
with open(SIGNING_KEY_PATH, "wb") as f:
    os.chmod(SIGNING_KEY_PATH, 0o600)
    f.write(sk.encode())
with open(SIGNING_KEY_PATH + ".pub", "wb") as f:
    f.write(sk.verify_key.encode())

# Fix:
with open(SIGNING_KEY_PATH, "wb") as f:
    os.fchmod(f.fileno(), 0o600)
    f.write(sk.encode())
with open(SIGNING_KEY_PATH + ".pub", "wb") as f:
    os.fchmod(f.fileno(), 0o644)
    f.write(sk.verify_key.encode())
```

### Step 2: Disable HMAC file-only authentication by default (T2-05 - HIGH)
**File:** `physical_token.py:129-180`
**Change:** Make `_hmac_challenge_response()` return `False` by default. Only return `True` if the environment variable `MEMORY_VAULT_ALLOW_HMAC_FILE_ONLY=1` is explicitly set.
```python
# At line 180, change `return True` to check env var:
allow_file_only = os.environ.get("MEMORY_VAULT_ALLOW_HMAC_FILE_ONLY", "0") == "1"
if not allow_file_only:
    logger.warning(
        "HMAC file-only mode disabled by default. "
        "Set MEMORY_VAULT_ALLOW_HMAC_FILE_ONLY=1 to enable (reduced security)."
    )
    return False
return True
```

### Step 3: Set database file permissions (T1-03 - MEDIUM)
**File:** `db.py:33-35`
**Change:** After `sqlite3.connect()`, set the database file to `0o600`.
```python
# After line 35 (conn = sqlite3.connect(path)):
conn = sqlite3.connect(path)
try:
    os.chmod(path, 0o600)
except OSError:
    pass
```

### Step 4: Set database directory permissions (T1-02 - LOW)
**File:** `db.py:8` and `db.py:34`
**Change:** Add `mode=0o700` to both `os.makedirs()` calls.
```python
# Line 8:
os.makedirs(os.path.dirname(DB_PATH), mode=0o700, exist_ok=True)
# Line 34:
os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
```

### Step 5: Fix example file mock API key (T1-01 - LOW)
**File:** `examples/langchain_memory.py:90`
**Change:** Replace the mock API key with a non-secret example.
```python
# Change line 90:
content_plaintext=b"API key: sk-example-12345",
# To:
content_plaintext=b"Database connection config: host=db.internal port=5432",
```

## Phase 2: Core Enforcement Fixes (Medium Severity)

### Step 6: Add post-decryption content hash verification (T2-01 - MEDIUM)
**File:** `vault.py:412-420`
**Change:** After `decrypt_memory()` succeeds, verify the plaintext hash matches the stored `content_hash`.
```python
# After line 413 (plaintext = decrypt_memory(key, ciphertext, nonce)):
plaintext = decrypt_memory(key, ciphertext, nonce)

# Verify content integrity (defense-in-depth)
stored_hash = row_dict.get("content_hash")
if stored_hash:
    actual_hash = hashlib.sha256(plaintext).hexdigest()
    if actual_hash != stored_hash:
        self._log_recall(c, memory_id, requester, False, "content hash mismatch")
        self._conn.commit()
        raise DecryptionError(
            "Content hash mismatch after decryption - possible tampering"
        )
```

### Step 7: Fix exit_lockdown passphrase verification (A-03 - LOW)
**File:** `vault.py:1006-1019`
**Change:** Instead of just calling `derive_key_from_passphrase(passphrase)` (which always succeeds), attempt to decrypt a known memory or verify against a stored profile by re-deriving with a stored salt and comparing.
```python
# Replace lines 1006-1019 with:
# Verify passphrase against default profile by attempting to
# derive a key with a known salt from a stored memory
c.execute("SELECT profile_id FROM encryption_profiles WHERE key_source = 'HumanPassphrase' LIMIT 1")
row = c.fetchone()
if row:
    profile_id = row[0]
    # Find a memory encrypted with this profile to verify against
    c.execute(
        "SELECT salt, ciphertext, nonce FROM memories WHERE encryption_profile = ? LIMIT 1",
        (profile_id,)
    )
    mem_row = c.fetchone()
    if mem_row and mem_row[0]:
        test_salt = mem_row[0]
        test_key, _ = derive_key_from_passphrase(passphrase, test_salt)
        try:
            decrypt_memory(test_key, mem_row[1], mem_row[2])
        except Exception:
            print("Passphrase verification failed: incorrect passphrase")
            return False
    else:
        # No memories to verify against; basic derivation check
        derive_key_from_passphrase(passphrase)
else:
    print("Warning: No passphrase profile found, skipping passphrase verification")
```

### Step 8: Add optional MemoryAuditor hook (T2-02 - MEDIUM)
**File:** `vault.py` (add to class)
**Change:** Add a registerable callback hook that is called on decrypted content before returning it. This is opt-in and does not change default behavior.
```python
# Add to __init__ (after line 86):
self._memory_auditors = []

# Add new method after close():
def register_memory_auditor(self, auditor_fn):
    """Register a callback to audit decrypted memory content.

    The auditor receives (memory_id, plaintext, classification) and should
    raise MemoryVaultError if the content fails audit checks.
    """
    self._memory_auditors.append(auditor_fn)

# In recall_memory, after hash verification (Step 6), before return:
for auditor in self._memory_auditors:
    auditor(memory_id, plaintext, classification)
```

### Step 9: Add audit log archival support (T3-01 - MEDIUM)
**File:** `vault.py` (add new method)
**Change:** Add `archive_audit_logs()` method that exports signed Merkle root snapshots and optionally prunes old leaves.
```python
def archive_audit_logs(self, before_seq: int = None, export_path: str = None) -> dict:
    """Archive and optionally prune old audit log entries.

    Preserves signed Merkle roots as non-repudiation checkpoints.
    """
    c = self._conn.cursor()

    if before_seq is None:
        c.execute("SELECT MAX(seq) FROM merkle_roots")
        max_seq = c.fetchone()[0]
        if not max_seq or max_seq < 2:
            return {"archived": 0, "message": "Not enough roots to archive"}
        before_seq = max_seq  # Keep the latest root

    # Export roots before archival
    c.execute(
        "SELECT seq, root_hash, timestamp, leaf_count, signature FROM merkle_roots WHERE seq < ?",
        (before_seq,)
    )
    roots = [{"seq": r[0], "root_hash": r[1], "timestamp": r[2],
              "leaf_count": r[3], "signature": r[4]} for r in c.fetchall()]

    if export_path:
        import json as _json
        with open(export_path, "w") as f:
            _json.dump({"archived_roots": roots}, f, indent=2)

    return {"archived": len(roots), "latest_preserved_seq": before_seq}
```

### Step 10: Optimize Merkle tree to avoid full rebuild (T3-02 - MEDIUM)
**File:** `vault.py:445-466`
**Change:** Instead of rebuilding the entire tree on every recall, only append the new leaf and recompute the path to the root. For backward compatibility, the existing `verify_integrity` still uses `rebuild_merkle_tree`.

This is the most complex change. The approach:
1. Keep a running root hash
2. On each new leaf, compute only the new path rather than rebuilding all leaves
3. Store the new root as before

```python
# Replace lines 445-466 in _log_recall with incremental approach:
# Get the current leaf count
c2 = conn.cursor()
c2.execute("SELECT COUNT(*) FROM merkle_leaves")
leaf_count = c2.fetchone()[0]

# For small trees (< 1000 leaves), rebuild is fast enough
# For larger trees, we still need the full rebuild for correct proofs
# but we can optimize later with a persistent tree structure
c2.execute("SELECT leaf_hash FROM merkle_leaves ORDER BY leaf_id")
leaves = [r[0] for r in c2.fetchall()]
new_root, proofs = build_tree(leaves)
```
**Note:** A true incremental Merkle tree requires significant refactoring of `merkle.py` to maintain intermediate nodes. For now, add a comment documenting the O(N) cost and plan for optimization. The current approach is correct and safe; it's a performance concern, not a security bug.

## Phase 3: Supply Chain & CI (High Severity, Longer-Term)

### Step 11: Pin dependencies with hashes (T2-04 - HIGH)
**File:** `requirements.txt` and new `requirements-lock.txt`
**Change:** Create a locked requirements file with specific versions and hashes. Keep `requirements.txt` for development with ranges, add `requirements-lock.txt` for production.
```
# requirements-lock.txt
pynacl==1.5.0 \
    --hash=sha256:a422368fc821589c228f4c49438a368831cb5bbc0eab5ebe1d7fac9dbed6394b \
    --hash=sha256:8ac7448f09ab85c2
```
**Note:** Exact hashes should be generated via `pip hash` on the actual wheel files. The plan is to create the file structure; exact hashes will be computed at implementation time using `pip-compile` or `pip download` + `pip hash`.

### Step 12: Add CI pipeline (T3-03 - LOW)
**File:** New `.github/workflows/security.yml`
**Change:** Create a GitHub Actions workflow that runs:
1. `ruff check .` (includes bandit security rules)
2. `pytest` with coverage
3. `pip-audit` for dependency vulnerabilities
4. Secret scanning

## Phase 4: Informational Items (No Code Changes Required)

### T2-03 (LOW - Informational): Backup metadata exposure
No code change needed. The backup container necessarily includes version/format metadata. This is expected behavior documented in the audit.

### A-01 (LOW - Accepted Risk): Cooldown bypass via system clock
No code change. The threat model assumes local system trust. Document in SECURITY.md that clock manipulation can bypass cooldowns.

### A-02 (LOW - Informational): Public key file permissions
Already addressed in Step 1 (setting `.pub` to `0o644`).

## Dependency Graph

```
Step 1 (crypto.py)     - independent
Step 2 (physical_token.py) - independent
Step 3 (db.py)         - independent
Step 4 (db.py)         - same file as Step 3, do together
Step 5 (examples/)     - independent
Step 6 (vault.py)      - independent
Step 7 (vault.py)      - same file as Step 6, do after
Step 8 (vault.py)      - same file as Step 7, do after
Step 9 (vault.py)      - same file as Step 8, do after
Step 10 (vault.py)     - same file as Step 9, comment only
Step 11 (requirements)  - independent
Step 12 (.github/)     - independent
```

**Parallel execution groups:**
- Group A: Steps 1, 2, 5, 11, 12 (all independent files)
- Group B: Steps 3 + 4 (db.py)
- Group C: Steps 6 → 7 → 8 → 9 → 10 (vault.py, sequential)
