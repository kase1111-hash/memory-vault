# Memory Vault Specification

**Version:** 1.1
**Last Updated:** December 19, 2025
**Status:** Active Development

---

## 1. Purpose

The Memory Vault is the secure, offline-capable, owner-sovereign storage subsystem for a learning co-worker/assistant. Its role is to store high-value cognitive artifacts (memories, intent logs, failed paths, IP, heuristics) with guarantees of confidentiality, integrity, provenance, and controlled recall.

**The Vault treats memory as capital, not cache.**

---

## 2. Design Principles

- **Owner Sovereignty** – The human owner is the final authority.
- **Least Recall** – Memories are not recalled unless explicitly permitted.
- **Classification First** – Security policy is bound at write-time.
- **Offline-First** – No network dependency for safety.
- **Composable Security** – Encryption, air-gaps, and contracts stack.
- **Auditability Without Exposure** – Proof without plaintext.

---

## 3. Memory Classification Model

Every memory object MUST declare a classification at creation.

### 3.1 Classification Levels

| Level | Name | Description | Status |
|-------|------|-------------|--------|
| 0 | Ephemeral | Session-only, auto-purged | Partial (no auto-purge) |
| 1 | Working | Short-term, low sensitivity | Implemented |
| 2 | Private | Owner-only recall | Implemented |
| 3 | Sealed | Encrypted, delayed access | Implemented |
| 4 | Vaulted | Hardware-bound, air-gapped | Implemented |
| 5 | Black | Exists but unretrievable without owner key + ritual | Partial (token.py missing) |

**Classification is immutable once written.**

---

## 4. Core Data Schemas

### 4.1 Memory Object Schema

```json
{
  "memory_id": "uuid",
  "created_at": "timestamp",
  "created_by": "agent|human",
  "classification": 0-5,
  "encryption_profile": "profile_id",
  "content_hash": "sha256",
  "content_ciphertext": "bytes",
  "intent_ref": "intentlog_id",
  "value_metadata": {
    "time_cost": "seconds",
    "novelty_score": "0-1",
    "failure_density": "0-1"
  },
  "access_policy": {
    "recall_conditions": ["human_approval", "offline_only"],
    "cooldown_seconds": 0
  },
  "audit_proof": "merkle_ref"
}
```

### 4.2 Encryption Profile Schema

```json
{
  "profile_id": "string",
  "cipher": "AES-256-GCM",
  "key_source": "TPM|File|HumanPassphrase",
  "rotation_policy": "manual|time|event",
  "exportable": false
}
```

### 4.3 Recall Request Schema

```json
{
  "request_id": "uuid",
  "memory_id": "uuid",
  "requester": "agent|human",
  "environment": {
    "network": "offline|online",
    "boundary_mode": "trusted|restricted|airgap"
  },
  "justification": "natural_language",
  "approved": false
}
```

---

## 5. Recall Flow (High Level)

1. Recall request submitted
2. Boundary daemon validates environment
3. Classification gate checked
4. Owner approval if required
5. Cooldown enforced
6. Decrypt in secure enclave
7. Deliver minimal necessary context
8. Log recall event

**No plaintext is ever written back to disk.**

---

## 6. Threat Model

### 6.1 Assets to Protect

- Proprietary ideas
- Failed paths (negative IP)
- Intent history
- Learning heuristics
- Economic value metadata

### 6.2 Adversaries

| Adversary | Capability |
|-----------|------------|
| External attacker | Network access |
| Malware | Local user-level access |
| Rogue agent | API-level misuse |
| Curious model | Over-recall |
| Owner future self | Unsafe hindsight |

### 6.3 Threats & Mitigations

| Threat | Mitigation | Status |
|--------|------------|--------|
| Memory exfiltration | Encryption + air-gap | Implemented |
| Over-recall | Least recall + contracts | Implemented |
| Model leakage | No plaintext training reuse | By design |
| Key theft | Hardware-bound keys | TPM stubs only |
| Coercive recall | Cooldowns + rituals | Implemented |
| Silent corruption | Hashing + Merkle audits | Implemented |

---

## 7. Air-Gap & Boundary Integration

The Vault refuses recall if:
- Network is active and classification >= 3
- Boundary daemon reports unsafe state
- External model access is enabled

**Boundary state is a hard dependency, not advisory.**

---

## 8. Audit & Proof Without Disclosure

| Feature | Status |
|---------|--------|
| Merkle trees over encrypted blobs | Implemented |
| Zero-knowledge proofs of existence | Not implemented |
| Recall logs hashed and chained | Implemented |

Allows proof of creation without revealing content.

---

## 9. Failure & Emergency Modes

### 9.1 Lockdown

- Triggered by owner or anomaly
- All recall disabled
- **Status:** Not implemented

### 9.2 Memory Tombstones

- Memories marked inaccessible but retained
- **Status:** Not implemented

### 9.3 Owner Death / Transfer

| Feature | Status |
|---------|--------|
| Escrowed keys | Not implemented |
| Dead-man switches | Implemented |
| Encrypted release to designated heirs | Implemented |

---

## 10. Non-Goals

- Cloud sync
- Automatic sharing
- Model self-training on vaulted memories

---

## 11. Implementation Notes

- Default to filesystem + SQLite + libsodium
- No background indexing of sealed content
- Human approval via explicit UX, not CLI flags

---

## 12. Philosophical Constraint

> A system that remembers everything becomes dangerous. A system that forgets nothing must learn restraint.

**The Memory Vault exists to enforce that restraint.**

---

## 13. Implementation Status Summary

### 13.1 Fully Implemented

| Feature | File(s) |
|---------|---------|
| Core MemoryVault class (store/recall) | vault.py |
| Classification enforcement (levels 1-4) | vault.py |
| Encryption profiles (Passphrase, KeyFile) | vault.py, crypto.py |
| AES-256-GCM encryption | crypto.py |
| Argon2id key derivation | crypto.py |
| Cooldown enforcement | vault.py |
| Full-text search (FTS5) | db.py |
| Merkle tree audit trail | merkle.py, vault.py |
| Ed25519 signed roots | crypto.py, vault.py |
| Dead-man switch | deadman.py |
| Heir management | deadman.py |
| CLI interface | cli.py |
| Boundary daemon client | boundry.py |

### 13.2 Partially Implemented

| Feature | State | Missing |
|---------|-------|---------|
| TPM memory sealing | Stubs exist | Actual TPM API calls |
| TPM-sealed signing key | Code exists | Testing/validation |
| Level 5 physical token | Referenced | token.py file |
| Backup/restore | Schema + CLI | Execution logic |
| verify-integrity | CLI args | Execution logic |

### 13.3 Not Implemented

| Feature | Priority |
|---------|----------|
| token.py (physical token) | HIGH |
| verify-integrity execution | HIGH |
| Backup/restore logic | HIGH |
| Level 0 auto-purge | MEDIUM |
| Lockdown mode | MEDIUM |
| Key rotation logic | MEDIUM |
| Memory tombstones | LOW |
| Zero-knowledge proofs | LOW |
| IntentLog adapter | LOW |
| MP-02 Proof-of-Effort | FUTURE |

---

## 14. Implementation Plans

### 14.1 HIGH PRIORITY

#### 14.1.1 token.py - Physical Token Integration

**Problem:** deadman.py imports `require_physical_token` from non-existent token.py, causing import errors.

**Plan:**
1. Create token.py with `require_physical_token()` function
2. Support FIDO2 via `fido2` library (optional)
3. Support HMAC challenge-response for YubiKey
4. Support TOTP fallback via `pyotp` (optional)
5. Graceful fallback when no token libraries installed
6. Integrate into vault.py for Level 5 recall gate

**Files:** Create token.py, modify vault.py

**Structure:**
```python
def require_physical_token(justification: str = "") -> bool:
    # Try FIDO2 -> HMAC -> TOTP -> fail
    # Return True only if token validates
```

---

#### 14.1.2 verify-integrity Command

**Problem:** CLI parses args but has no execution logic.

**Plan:**
1. Add `verify_integrity()` method to MemoryVault:
   - Rebuild Merkle tree from all leaves
   - Compare against latest stored root
   - Verify all root signatures
   - If memory_id given, verify its specific proof
2. Return detailed result dict
3. Add execution in cli.py

**Files:** vault.py, cli.py

---

#### 14.1.3 Backup/Restore Logic

**Problem:** Schema and CLI exist but no implementation.

**Plan:**
1. Add `create_backup()` method:
   - Query memories (all or since last backup)
   - Build JSON structure
   - Encrypt with passphrase-derived key
   - Record in backups table
2. Add `restore_backup()` method:
   - Decrypt and validate
   - Insert/update memories
   - Skip non-exportable profiles
3. Handle incremental chains via parent_backup_id

**Files:** vault.py, cli.py

---

### 14.2 MEDIUM PRIORITY

#### 14.2.1 Level 0 Ephemeral Auto-Purge

**Plan:**
1. Add `purge_ephemeral(max_age_hours)` to vault.py
2. Call on vault initialization or via CLI command
3. Delete level 0 memories older than threshold

---

#### 14.2.2 Lockdown Mode

**Plan:**
1. Add vault_state table with lockdown flag
2. Add `enter_lockdown()` / `exit_lockdown()` methods
3. Check lockdown state at start of recall_memory()
4. Require physical token for lockdown changes

---

#### 14.2.3 Key Rotation

**Plan:**
1. Add last_rotation column to encryption_profiles
2. Add `rotate_profile_key()` method
3. Re-encrypt all memories using the profile
4. Add `rotate-key` CLI command

---

#### 14.2.4 Complete TPM Implementation

**Plan:**
1. Implement `tpm_generate_sealed_key()` with actual TPM calls
2. Implement `tpm_unseal_key()` with PCR validation
3. Test with TPM 2.0 hardware or swtpm simulator

**Dependencies:** tpm2-pytss, TPM hardware

---

### 14.3 LOW PRIORITY

#### 14.3.1 Memory Tombstones

**Plan:**
1. Add `tombstoned` column to memories
2. Add `tombstone_memory()` method
3. Check tombstone in recall_memory()

---

#### 14.3.2 IntentLog Adapter

**Plan:**
1. Create intentlog.py with helper functions
2. Add search-by-intent CLI command

---

#### 14.3.3 Zero-Knowledge Proofs

**Plan:**
1. Research ZK libraries (py_ecc, etc.)
2. Implement proof of existence without content disclosure
3. Add generate/verify commands

---

### 14.4 FUTURE

| Feature | Dependencies |
|---------|--------------|
| Remote TPM Attestation | TPM implementation |
| Web Audit Viewer | verify-integrity |
| MP-02 Integration | Separate protocol |
| Multi-Device Sync | Key exchange protocol |

---

## 15. File Inventory

| File | Purpose | Status |
|------|---------|--------|
| vault.py | Core MemoryVault class | Production |
| db.py | SQLite schema, FTS | Production |
| crypto.py | Encryption, signing | TPM stubs |
| merkle.py | Merkle tree | Production |
| boundry.py | Boundary client | Production (typo in name) |
| deadman.py | Dead-man switch | Needs token.py |
| models.py | Dataclasses | Production |
| cli.py | CLI interface | Incomplete commands |
| token.py | Physical tokens | Missing |

---

## 16. Known Issues

1. **Filename typo:** `boundry.py` should be `boundary.py`
2. **Import error:** deadman.py imports non-existent token.py
3. **Incomplete CLI:** backup, restore, verify-integrity don't execute
4. **TPM untested:** TPM code not validated on hardware
