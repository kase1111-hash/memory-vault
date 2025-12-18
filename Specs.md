Memory Vault Specification
1. Purpose

The Memory Vault is the secure, offline‑capable, owner‑sovereign storage subsystem for a learning co‑worker/assistant. Its role is to store high‑value cognitive artifacts (memories, intent logs, failed paths, IP, heuristics) with guarantees of confidentiality, integrity, provenance, and controlled recall.

The Vault treats memory as capital, not cache.

2. Design Principles

Owner Sovereignty – The human owner is the final authority.

Least Recall – Memories are not recalled unless explicitly permitted.

Classification First – Security policy is bound at write‑time.

Offline‑First – No network dependency for safety.

Composable Security – Encryption, air‑gaps, and contracts stack.

Auditability Without Exposure – Proof without plaintext.

3. Memory Classification Model

Every memory object MUST declare a classification at creation.

3.1 Classification Levels
Level	Name	Description
0	Ephemeral	Session‑only, auto‑purged
1	Working	Short‑term, low sensitivity
2	Private	Owner‑only recall
3	Sealed	Encrypted, delayed access
4	Vaulted	Hardware‑bound, air‑gapped
5	Black	Exists but unretrievable without owner key + ritual

Classification is immutable once written.

4. Core Data Schemas
4.1 Memory Object Schema
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
4.2 Encryption Profile Schema
{
  "profile_id": "string",
  "cipher": "AES-256-GCM",
  "key_source": "TPM|File|HumanPassphrase",
  "rotation_policy": "manual|time|event",
  "exportable": false
}
4.3 Recall Request Schema
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
5. Recall Flow (High Level)

Recall request submitted

Boundary daemon validates environment

Classification gate checked

Owner approval if required

Cooldown enforced

Decrypt in secure enclave

Deliver minimal necessary context

Log recall event

No plaintext is ever written back to disk.

6. Threat Model
6.1 Assets to Protect

Proprietary ideas

Failed paths (negative IP)

Intent history

Learning heuristics

Economic value metadata

6.2 Adversaries
Adversary	Capability
External attacker	Network access
Malware	Local user‑level access
Rogue agent	API‑level misuse
Curious model	Over‑recall
Owner future self	Unsafe hindsight
6.3 Threats & Mitigations
Threat	Mitigation
Memory exfiltration	Encryption + air‑gap
Over‑recall	Least recall + contracts
Model leakage	No plaintext training reuse
Key theft	Hardware‑bound keys
Coercive recall	Cooldowns + rituals
Silent corruption	Hashing + Merkle audits
7. Air‑Gap & Boundary Integration

The Vault refuses recall if:

Network is active and classification ≥ 3

Boundary daemon reports unsafe state

External model access is enabled

Boundary state is a hard dependency, not advisory.

8. Audit & Proof Without Disclosure

Merkle trees over encrypted blobs

Zero‑knowledge proofs of existence

Recall logs hashed and chained

Allows proof of creation without revealing content.

9. Failure & Emergency Modes
9.1 Lockdown

Triggered by owner or anomaly

All recall disabled

9.2 Memory Tombstones

Memories marked inaccessible but retained

9.3 Owner Death / Transfer (Optional)

Escrowed keys

Dead‑man switches

10. Non‑Goals

Cloud sync

Automatic sharing

Model self‑training on vaulted memories

11. Implementation Notes

Default to filesystem + SQLite + libsodium

No background indexing of sealed content

Human approval via explicit UX, not CLI flags

12. Philosophical Constraint

A system that remembers everything becomes dangerous. A system that forgets nothing must learn restraint.

The Memory Vault exists to enforce that restraint.
