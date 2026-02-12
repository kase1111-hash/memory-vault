# Memory Vault Specification

**Version:** 1.7
**Last Updated:** January 1, 2026
**Status:** Production (Feature Complete)

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
| 0 | Ephemeral | Session-only, auto-purged | Implemented |
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
  "cipher": "XSalsa20-Poly1305",
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
| Zero-knowledge existence proofs | Implemented |

Allows proof of audit trail integrity without revealing memory content.

---

## 9. Failure & Emergency Modes

### 9.1 Lockdown

- Triggered by owner or anomaly
- All recall disabled
- **Status:** Implemented

### 9.2 Memory Tombstones

- Memories marked inaccessible but retained for audit
- **Status:** Implemented

### 9.3 Owner Death / Transfer

| Feature | Status |
|---------|--------|
| Dead-man switches | Implemented |
| Encrypted release to designated heirs | Implemented |
| Physical token required for arming | Implemented |
| Escrowed keys (Shamir's Secret Sharing) | Implemented |

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
| XSalsa20-Poly1305 encryption | crypto.py |
| Argon2id key derivation | crypto.py |
| Cooldown enforcement | vault.py |
| Full-text search (FTS5) | db.py |
| Merkle tree audit trail | merkle.py, vault.py |
| Ed25519 signed roots | crypto.py, vault.py |
| Dead-man switch | deadman.py |
| Heir management + encrypted payloads | deadman.py |
| CLI interface | cli.py |
| Boundary daemon client | boundry.py |
| Physical token authentication (Level 5) | physical_token.py |
| FIDO2/U2F token support | physical_token.py |
| HMAC challenge-response tokens | physical_token.py |
| TOTP/HOTP fallback tokens | physical_token.py |
| Backup (full + incremental) | vault.py, cli.py |
| Restore from backup | vault.py, cli.py |
| Integrity verification (Merkle + signatures) | vault.py, cli.py |
| Level 0 ephemeral auto-purge | vault.py, cli.py |
| Lockdown mode | vault.py, db.py, cli.py |
| Key rotation | vault.py, db.py, cli.py |
| Memory tombstones | vault.py, db.py, cli.py |
| IntentLog adapter | intentlog.py, cli.py |
| Zero-knowledge proofs | zkproofs.py, cli.py |
| Escrowed keys (Shamir) | escrow.py, db.py, cli.py |

### 13.2 Partially Implemented

| Feature | State | Missing |
|---------|-------|---------|
| TPM memory sealing | Full code exists | Hardware testing/validation |
| TPM-sealed signing key | Full code exists | Hardware testing/validation |

### 13.3 All Core Features Implemented

All core features including MP-02 Proof-of-Effort receipts are now implemented. See `docs/INTEGRATIONS.md` for integration details.

---

## 14. Implementation Status

### 14.1 Pending: TPM Hardware Validation

**Status:** Code Complete, Untested

TPM sealing/unsealing code exists but hasn't been validated on real hardware.

**Requirements:**
- TPM 2.0 hardware or swtpm simulator
- tpm2-pytss package

**To validate:**
1. Test `tpm_create_and_persist_primary()` - primary key creation
2. Test `tpm_generate_sealed_key()` - key sealing to PCRs 0-7
3. Test `tpm_unseal_key()` - unsealing and PCR mismatch behavior
4. Test `tpm_seal_signing_key()` - signing key sealing

---

### 14.2 Future Work

| Feature | Description |
|---------|-------------|
| Remote TPM Attestation | Generate TPM quotes for third-party verification |
| Web Audit Viewer | Read-only web interface for audit trail visualization |
| Multi-Device Sync | Secure sync with E2E encryption (conflicts with offline-first principle) |

---

## 15. File Inventory

| File | Purpose | Status |
|------|---------|--------|
| vault.py | Core MemoryVault class (store, recall, backup, restore, verify) | Production |
| db.py | SQLite schema, FTS5, migrations | Production |
| crypto.py | XSalsa20-Poly1305 encryption, Argon2id KDF, Ed25519 signing, TPM | Production (TPM untested) |
| merkle.py | Merkle tree construction, verification, rebuild | Production |
| boundry.py | Boundary daemon Unix socket client | Production (typo in name) |
| deadman.py | Dead-man switch, heir management, encrypted payloads | Production |
| models.py | MemoryObject and related dataclasses | Production |
| cli.py | Complete command-line interface (~40 subcommands) | Production |
| physical_token.py | Physical token authentication (FIDO2, HMAC, TOTP) | Production |
| intentlog.py | IntentLog bidirectional linking adapter | Production |
| zkproofs.py | Zero-knowledge existence proofs | Production |
| escrow.py | Shamir's Secret Sharing key escrow | Production |
| natlangchain.py | NatLangChain blockchain anchoring | Production |
| agent_os.py | Agent-OS governance integration | Production |
| effort.py | MP-02 Proof-of-Effort receipt protocol | Production |

---

## 16. Known Issues

1. **Filename typo:** `boundry.py` should be `boundary.py` - kept for backwards compatibility
2. **TPM untested:** TPM sealing/unsealing code has not been validated on hardware
3. **FIDO2 credential registration:** physical_token.py verifies device presence but doesn't implement full credential management

---

## 17. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | Dec 2025 | Initial specification |
| 1.1 | Dec 19, 2025 | Added implementation status, plans, MP-02 integration |
| 1.2 | Dec 19, 2025 | Updated status: token.py, backup/restore, verify-integrity now fully implemented |
| 1.3 | Dec 22, 2025 | Fixed file references (token.py → physical_token.py), fixed import bug, consolidated documentation |
| 1.4 | Dec 22, 2025 | Implemented Level 0 auto-purge, lockdown mode, key rotation; added vault_state table |
| 1.5 | Dec 22, 2025 | Implemented tombstones, IntentLog adapter, ZK proofs, escrowed keys (Shamir SSS) |
| 1.6 | Dec 31, 2025 | Documentation cleanup: consolidated MP-02 spec, removed outdated implementation plans |
| 1.7 | Jan 1, 2026 | Full documentation update: added all modules to file inventory, updated implementation status |

---

## 18. Dependencies

### Required
- `pynacl>=1.5.0` — Core cryptography (XSalsa20-Poly1305, Argon2id, Ed25519)
- Python 3.7+ (sqlite3, json, hashlib, uuid, datetime, base64 standard library)

### Optional
- `tpm2-pytss>=2.1.0` — TPM 2.0 support (Linux only)
- `fido2>=1.1.0` — FIDO2/U2F hardware tokens
- `pyotp>=2.8.0` — TOTP/HOTP software tokens

---

## 19. Integration Points

### 19.1 Boundary Daemon
- **Purpose:** Environmental security enforcement via Unix socket
- **Socket Path:** `~/.agent-os/api/boundary.sock`
- **Protocol:** JSON over Unix socket
- **Behavior:** Fail-closed (all recalls denied if daemon unavailable)
- **See:** `docs/INTEGRATIONS.md` Section 1

### 19.2 IntentLog
- **Purpose:** Bidirectional linking with intent tracking system
- **Integration:** Via `intent_ref` field in MemoryObject schema
- **Status:** ✓ Full adapter implemented (intentlog.py)
- **See:** `docs/INTEGRATIONS.md` Section 2

### 19.3 Physical Tokens
- **Purpose:** Level 5 physical presence requirement
- **Supported:** FIDO2/U2F (YubiKey, Nitrokey, OnlyKey), HMAC challenge-response, TOTP/HOTP
- **See:** `docs/INTEGRATIONS.md` Section 3

### 19.4 Dead-Man Switch / Heir Release
- **Purpose:** Secure succession and owner-incapacitation handling
- **Encryption:** SealedBox (X25519) for per-recipient payloads
- **Key Format:** age/X25519 public keys
- **See:** `docs/INTEGRATIONS.md` Section 4

---

## 20. Related Documentation

| Document | Purpose |
|----------|---------|
| README.md | Installation, quick start, CLI usage |
| RECOVERY.md | Emergency data recovery using only PyNaCl |
| docs/INTEGRATIONS.md | Detailed integration guides for all external systems |

---

## Appendix A: MP-02 Proof-of-Effort Receipt Protocol

### A.1 Purpose

MP-02 defines the protocol by which human intellectual effort is observed, validated, and recorded as cryptographically verifiable receipts.

The protocol establishes a primitive that is:
- Verifiable without trusting the issuer
- Human-readable over long time horizons
- Composable with negotiation, licensing, and settlement protocols

MP-02 does not assert value, ownership, or compensation. It asserts that effort occurred, with traceable provenance.

### A.2 Design Principles

- **Process Over Artifact** — Effort is validated as a process unfolding over time, not a single output
- **Continuity Matters** — Temporal progression is a primary signal of genuine work
- **Receipts, Not Claims** — The protocol records evidence, not conclusions about value
- **Model Skepticism** — LLM assessments are advisory and must be reproducible
- **Partial Observability** — Uncertainty is preserved, not collapsed

### A.3 Definitions

| Term | Definition |
|------|------------|
| **Effort** | A temporally continuous sequence of human cognitive activity directed toward an intelligible goal |
| **Signal** | A raw observable trace of effort (voice transcripts, text edits, command history, tool interaction) |
| **Effort Segment** | A bounded time slice of signals treated as a unit of analysis |
| **Receipt** | A cryptographic record attesting that a specific effort segment occurred |

### A.4 Actors

| Actor | Role |
|-------|------|
| Human Worker | The individual whose effort is being recorded |
| Observer | System component responsible for capturing raw signals |
| Validator | LLM-assisted process that analyzes effort segments for coherence and progression |
| Ledger | Append-only system that anchors receipts and their hashes |

### A.5 Protocol Requirements

**Observers MUST:**
- Time-stamp all signals
- Preserve ordering
- Disclose capture modality

**Observers MUST NOT:**
- Alter raw signals
- Infer intent beyond observed data

**Validators MUST:**
- Produce deterministic summaries
- Disclose model identity and version
- Preserve dissent and uncertainty

**Validators MUST NOT:**
- Declare effort as valuable
- Assert originality or ownership
- Collapse ambiguous signals into certainty

### A.6 Receipt Construction

Each Effort Receipt MUST include:
- Receipt ID
- Time bounds
- Hashes of referenced signals
- Deterministic effort summary
- Validation metadata
- Observer and Validator identifiers

### A.7 Anchoring and Verification

Receipts are anchored by hashing receipt contents and appending to a ledger. The ledger MUST be append-only, time-ordered, and publicly verifiable.

A third party MUST be able to recompute receipt hashes, inspect validation metadata, and confirm ledger inclusion. Trust in the Observer or Validator is not required.

### A.8 Non-Goals

MP-02 does NOT:
- Measure productivity
- Enforce labor conditions
- Replace authorship law
- Rank humans by output

### A.9 Canonical Rule

> If effort cannot be independently verified as having occurred over time, it must not be capitalized.

*MP-02 is compatible with MP-01 Negotiation & Ratification protocol.*
