# Memory Vault Specification

**Version:** 1.2
**Last Updated:** December 19, 2025
**Status:** Production (Core Features Complete)

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
| 3 | Sealed | Encrypted, delayed access, human approval | Implemented |
| 4 | Vaulted | Hardware-bound, air-gapped, boundary check | Implemented |
| 5 | Black | Physical token + all Level 4 requirements | Implemented |

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
| Memory exfiltration | Encryption + air-gap + boundary daemon | Implemented |
| Over-recall | Least recall + cooldowns + human approval | Implemented |
| Model leakage | No plaintext training reuse | By design |
| Key theft | Hardware-bound keys (TPM sealing) | Code complete, untested |
| Coercive recall | Cooldowns + physical tokens | Implemented |
| Silent corruption | Merkle tree + Ed25519 signatures | Implemented |
| Owner incapacitation | Dead-man switch + heir release | Implemented |

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
| Merkle trees over recall events | Implemented |
| Ed25519 signed Merkle roots | Implemented |
| Full integrity verification CLI | Implemented |
| Recall logs hashed and chained | Implemented |
| Zero-knowledge proofs of existence | Not implemented |

Allows proof of audit trail integrity without revealing memory content.

---

## 9. Failure & Emergency Modes

### 9.1 Lockdown

- Triggered by owner or anomaly
- All recall disabled
- **Status:** Not implemented (see Section 14.1.2 for plan)

### 9.2 Memory Tombstones

- Memories marked inaccessible but retained for audit
- **Status:** Not implemented (see Section 14.2.1 for plan)

### 9.3 Owner Death / Transfer

| Feature | Status |
|---------|--------|
| Dead-man switches | Implemented |
| Encrypted release to designated heirs | Implemented |
| Physical token required for arming | Implemented |
| Escrowed keys (Shamir's Secret Sharing) | Not implemented |

### 9.4 Backup & Recovery

| Feature | Status |
|---------|--------|
| Full encrypted backups | Implemented |
| Incremental backups with chain tracking | Implemented |
| Passphrase-protected backup files | Implemented |
| Restore with merge logic | Implemented |
| Non-exportable profile handling | Implemented (excluded from backup) |

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
| Classification enforcement (levels 0-5) | vault.py |
| Encryption profiles (Passphrase, KeyFile) | vault.py, crypto.py |
| AES-256-GCM encryption | crypto.py |
| Argon2id key derivation | crypto.py |
| Cooldown enforcement | vault.py |
| Full-text search (FTS5) | db.py |
| Merkle tree audit trail | merkle.py, vault.py |
| Ed25519 signed roots | crypto.py, vault.py |
| Dead-man switch | deadman.py |
| Heir management + encrypted payloads | deadman.py |
| CLI interface | cli.py |
| Boundary daemon client | boundry.py |
| Physical token authentication (Level 5) | token.py |
| FIDO2/U2F token support | token.py |
| HMAC challenge-response tokens | token.py |
| TOTP/HOTP fallback tokens | token.py |
| Backup (full + incremental) | vault.py, cli.py |
| Restore from backup | vault.py, cli.py |
| Integrity verification (Merkle + signatures) | vault.py, cli.py |

### 13.2 Partially Implemented

| Feature | State | Missing |
|---------|-------|---------|
| TPM memory sealing | Full code exists | Hardware testing/validation |
| TPM-sealed signing key | Full code exists | Hardware testing/validation |
| Level 0 ephemeral | Storage works | Auto-purge on session end |

### 13.3 Not Implemented

| Feature | Priority | Description |
|---------|----------|-------------|
| Level 0 auto-purge | MEDIUM | Auto-delete ephemeral memories after session |
| Lockdown mode | MEDIUM | Emergency all-recall-disabled mode |
| Key rotation logic | MEDIUM | Re-encrypt memories with new profile key |
| Memory tombstones | LOW | Mark memories inaccessible but retained |
| Zero-knowledge proofs | LOW | Prove existence without content disclosure |
| IntentLog adapter | LOW | Bidirectional linking with IntentLog system |
| Escrowed keys | LOW | Third-party key escrow (vs dead-man switch) |
| MP-02 Proof-of-Effort | FUTURE | NatLangChain effort receipt integration |

---

## 14. Implementation Plans

### 14.1 MEDIUM PRIORITY

#### 14.1.1 Level 0 Ephemeral Auto-Purge

**Status:** Not Implemented

**Problem:** Level 0 memories are stored but never automatically purged, contradicting the "ephemeral" designation.

**Plan:**
1. Add `purge_ephemeral(max_age_hours: int = 24)` method to vault.py
2. Delete all level 0 memories older than threshold
3. Call automatically on vault initialization
4. Add `purge-ephemeral` CLI command for manual triggering
5. Optionally configure auto-purge interval in config

**Files:** vault.py, cli.py

**Code Outline:**
```python
def purge_ephemeral(self, max_age_hours: int = 24) -> int:
    cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
    c.execute("DELETE FROM memories WHERE classification = 0 AND created_at < ?", (cutoff.isoformat(),))
    return c.rowcount
```

---

#### 14.1.2 Lockdown Mode

**Status:** Not Implemented

**Problem:** No emergency mechanism to disable all recall operations.

**Plan:**
1. Add `vault_state` table with columns: `lockdown` (bool), `lockdown_since` (timestamp), `lockdown_reason` (text)
2. Add `enter_lockdown(reason: str)` method - requires physical token
3. Add `exit_lockdown()` method - requires physical token + passphrase
4. Check lockdown state at start of `recall_memory()` - fail immediately if locked
5. Add `lockdown` / `unlock` CLI commands
6. Log all lockdown events to audit trail

**Files:** vault.py, db.py, cli.py

**Security:** Lockdown exit requires both physical token AND passphrase to prevent accidental/malicious unlock.

---

#### 14.1.3 Key Rotation

**Status:** Not Implemented

**Problem:** No way to rotate encryption keys for a profile without losing access to memories.

**Plan:**
1. Add `last_rotation` and `rotation_count` columns to encryption_profiles
2. Add `rotate_profile_key(profile_id: str)` method:
   - Prompt for current passphrase
   - Prompt for new passphrase
   - Decrypt all memories using old key
   - Re-encrypt with new key
   - Update salt for each memory
   - Record rotation event
3. Add `rotate-key` CLI command
4. Optionally enforce rotation policy (time-based or event-based)

**Files:** vault.py, db.py, cli.py

**Warning:** KeyFile profiles require secure destruction of old keyfile after rotation.

---

#### 14.1.4 TPM Hardware Validation

**Status:** Code Complete, Untested

**Problem:** TPM code exists but hasn't been validated on real hardware.

**Plan:**
1. Set up test environment with TPM 2.0 (hardware or swtpm simulator)
2. Test `tpm_create_and_persist_primary()` - verify primary key creation
3. Test `tpm_generate_sealed_key()` - verify key sealing to PCRs 0-7
4. Test `tpm_unseal_key()` - verify unsealing works and fails on PCR mismatch
5. Test `tpm_seal_signing_key()` - verify signing key sealing
6. Document PCR binding behavior and recovery procedures
7. Add integration tests

**Dependencies:** tpm2-pytss, TPM 2.0 hardware or swtpm

---

### 14.2 LOW PRIORITY

#### 14.2.1 Memory Tombstones

**Status:** Not Implemented

**Problem:** No way to mark a memory as inaccessible while retaining it for audit purposes.

**Plan:**
1. Add `tombstoned` (bool) and `tombstoned_at` (timestamp) columns to memories table
2. Add `tombstone_memory(memory_id: str, reason: str)` method
3. Tombstoning requires human approval + physical token for Level 3+
4. Tombstoned memories cannot be recalled but appear in searches
5. Add `tombstone` CLI command
6. Log tombstone event to audit trail

**Files:** vault.py, db.py, cli.py

---

#### 14.2.2 IntentLog Adapter

**Status:** Not Implemented

**Problem:** No built-in integration with external IntentLog systems.

**Plan:**
1. Create `intentlog.py` with adapter interface
2. Implement `link_intent(memory_id: str, intent_id: str)` - bidirectional linking
3. Implement `get_memories_for_intent(intent_id: str)` - query by intent
4. Implement `get_intents_for_memory(memory_id: str)` - reverse lookup
5. Add FTS index on intent_ref column
6. Add `search-by-intent` CLI command

**Files:** Create intentlog.py, modify db.py, cli.py

**Integration Point:** Uses existing `intent_ref` field in MemoryObject schema.

---

#### 14.2.3 Zero-Knowledge Proofs

**Status:** Not Implemented

**Problem:** Cannot prove memory existence without revealing content.

**Plan:**
1. Research ZK libraries: py_ecc, libsnark Python bindings, or zkSNARKs
2. Design proof structure:
   - Prover: owner with decryption key
   - Verifier: third party without key access
   - Statement: "Memory with hash H exists and was created before time T"
3. Implement `generate_existence_proof(memory_id: str)` method
4. Implement `verify_existence_proof(proof: bytes, commitment: bytes)` method
5. Add `zk-prove` / `zk-verify` CLI commands

**Files:** Create zkproofs.py, modify cli.py

**Note:** This is a complex feature requiring careful cryptographic design.

---

#### 14.2.4 Escrowed Keys

**Status:** Not Implemented (Dead-man switch provides similar functionality)

**Problem:** No third-party key escrow mechanism (distinct from dead-man switch).

**Plan:**
1. Design escrow protocol with split keys (Shamir's Secret Sharing)
2. Add escrow_shards table with encrypted key shares
3. Implement `create_escrow(threshold: int, total_shares: int)` method
4. Implement `recover_from_escrow(shards: list[bytes])` method
5. Escrow recovery requires quorum of shares

**Files:** Create escrow.py, modify db.py, cli.py

**Note:** Consider using existing dead-man switch for most succession use cases.

---

### 14.3 FUTURE / MP-02 INTEGRATION

#### 14.3.1 MP-02 Proof-of-Effort Receipt Protocol

**Status:** Specification Only (see MP-02-spec.md)

**Problem:** Memory Vault stores cognitive artifacts but doesn't prove the effort that created them.

**Background:** MP-02 (NatLangChain Effort Verification) defines how human intellectual effort is observed, validated, and recorded as cryptographically verifiable receipts. This integration allows Memory Vault memories to be linked to effort proofs.

**Integration Plan:**

**Phase 1: Receipt Schema Integration**
1. Add `effort_receipt_id` column to memories table
2. Add `receipts` table to store effort receipt metadata:
   ```sql
   CREATE TABLE effort_receipts (
       receipt_id TEXT PRIMARY KEY,
       memory_id TEXT REFERENCES memories(memory_id),
       time_bounds_start TEXT,
       time_bounds_end TEXT,
       signal_hashes TEXT,          -- JSON array of signal hashes
       effort_summary TEXT,         -- Deterministic summary
       validator_id TEXT,           -- LLM model identifier
       validator_version TEXT,      -- Model version
       observer_id TEXT,            -- Observer system identifier
       anchored_at TEXT,            -- Ledger anchor timestamp
       ledger_proof TEXT            -- Inclusion proof
   );
   ```

**Phase 2: Observer Integration**
1. Create `observer.py` for signal capture
2. Implement signal types: text edits, command history, tool interactions
3. Time-stamp and hash all signals
4. Segment signals by activity boundaries or explicit markers

**Phase 3: Validator Integration**
1. Create `validator.py` for effort assessment
2. Integrate with LLM for coherence/progression analysis
3. Produce deterministic summaries
4. Preserve uncertainty and dissent
5. Record model identity and version

**Phase 4: Receipt Construction**
1. Create `receipt.py` for MP-02 receipt building
2. Generate receipt ID, time bounds, signal hashes
3. Include validation metadata
4. Sign receipt with vault's Ed25519 key

**Phase 5: Ledger Anchoring**
1. Design append-only ledger format (local SQLite or external)
2. Hash receipt contents and append to ledger
3. Generate inclusion proofs
4. Support external ledger systems (blockchain optional)

**Files:** Create observer.py, validator.py, receipt.py, ledger.py; modify db.py, vault.py, cli.py

**CLI Commands:**
- `effort-observe start/stop` - Control signal observation
- `effort-segment` - Mark activity boundary
- `effort-validate <segment_id>` - Generate effort assessment
- `effort-receipt <memory_id>` - Create and anchor receipt
- `effort-verify <receipt_id>` - Verify receipt against ledger

**Compatibility:** MP-02 receipts will be compatible with MP-01 Negotiation & Ratification protocol for future licensing/delegation.

---

#### 14.3.2 Remote TPM Attestation

**Status:** Future

**Dependencies:** TPM hardware validation complete

**Plan:**
1. Implement remote attestation protocol
2. Generate TPM quotes for platform state
3. Allow third-party verification of vault integrity
4. Integrate with enterprise key management

---

#### 14.3.3 Web Audit Viewer

**Status:** Future

**Dependencies:** verify-integrity complete

**Plan:**
1. Create read-only web interface for audit trail visualization
2. Display Merkle tree structure graphically
3. Show recall history with approval/denial status
4. Export audit reports in standard formats

---

#### 14.3.4 Multi-Device Sync

**Status:** Future

**Dependencies:** Key exchange protocol design

**Plan:**
1. Design secure key exchange between trusted devices
2. Implement conflict resolution for concurrent modifications
3. Support selective sync (by classification level)
4. End-to-end encryption for sync transport

**Note:** This partially conflicts with "offline-first" principle - requires careful design.

---

## 15. File Inventory

| File | Purpose | Status |
|------|---------|--------|
| vault.py | Core MemoryVault class (store, recall, backup, restore, verify) | Production |
| db.py | SQLite schema, FTS5, migrations | Production |
| crypto.py | AES-256-GCM encryption, Argon2id KDF, Ed25519 signing, TPM | Production (TPM untested) |
| merkle.py | Merkle tree construction, verification, rebuild | Production |
| boundry.py | Boundary daemon Unix socket client | Production (typo in name) |
| deadman.py | Dead-man switch, heir management, encrypted payloads | Production |
| models.py | MemoryObject and related dataclasses | Production |
| cli.py | Complete command-line interface | Production |
| token.py | Physical token authentication (FIDO2, HMAC, TOTP) | Production |

---

## 16. Known Issues

1. **Filename typo:** `boundry.py` should be `boundary.py` - kept for backwards compatibility
2. **TPM untested:** TPM sealing/unsealing code has not been validated on hardware
3. **FIDO2 credential registration:** token.py verifies device presence but doesn't implement full credential management

---

## 17. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Dec 2025 | Initial specification |
| 1.1 | Dec 19, 2025 | Added implementation status, plans, MP-02 integration |
| 1.2 | Dec 19, 2025 | Updated status: token.py, backup/restore, verify-integrity now fully implemented |
