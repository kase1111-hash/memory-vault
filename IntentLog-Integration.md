Memory Vault + IntentLog Integration Guide
Date: December 17, 2025
Status: Ready for integration
The Memory Vault is now fully capable of serving as the secure, auditable, classification-bound persistence layer for IntentLog — ensuring that high-value intent references, failed paths, heuristics, and root secrets are stored with the appropriate sovereignty guarantees.
Why Integrate?

IntentLog tracks agent intent, outcomes, and lessons learned
Many entries are low-value (transient) → fine in plain synth-mind memory
High-value entries (e.g., root keys, recovery seeds, critical heuristics, long-term goals) must be protected by Memory Vault's gates
Vault provides: classification, human approval, cooldowns, tamper-proof audit, hardware binding

Integration Strategy

Dual Persistence Model
Low-value intent log entries → synth-mind's existing memory.db
High-value entries → Memory Vault via intent_ref linkage

intent_ref Field
Every MemoryObject has an optional intent_ref: str
This is a UUID or identifier from your IntentLog system
Enables bidirectional linking: IntentLog → Vault memory ID


Code Integration Example
Python# In your IntentLog persistence logic

from memory_vault.vault import MemoryVault
from memory_vault.models import MemoryObject
from uuid import uuid4

vault = MemoryVault()

def store_critical_intent(
    content: bytes,
    classification: int,
    intent_id: str,
    metadata: dict,
    cooldown_seconds: int = 0
):
    """
    Store a high-value intent artifact in the Memory Vault.
    Returns vault memory_id for linking.
    """
    obj = MemoryObject(
        memory_id=str(uuid4()),
        content_plaintext=content,
        classification=classification,
        encryption_profile="default-passphrase",  # or TPM profile
        intent_ref=intent_id,                     # ← Link back to IntentLog
        access_policy={"cooldown_seconds": cooldown_seconds},
        value_metadata=metadata | {"source": "IntentLog", "intent_id": intent_id}
    )
    vault.store_memory(obj)
    print(f"Critical intent {intent_id} secured in Vault as {obj.memory_id}")
    return obj.memory_id


def recall_critical_intent(memory_id: str, justification: str) -> bytes:
    """
    Recall with full Vault gates (boundary, human approval, cooldown, audit).
    """
    return vault.recall_memory(memory_id, justification=justification)
Recommended Classification Mapping















































IntentLog TypeRecommended Vault LevelJustification RequirementCooldownTransient goal/outcomeNone (synth-mind only)NoNoLearned heuristic1–2NoNoFailed path lesson2NoNoLong-term goal / principle3YesOptionalRecovery seed / root key5Yes + strong justification30+ daysMaster encryption key5 (TPM profile)Yes + boundary check90+ days
Audit & Forensics
All recalls of IntentLog-linked memories are:

Logged in tamper-evident Merkle tree
Signed with hardware-bound key (if TPM enabled)
Searchable via search-justifications "IntentLog recovery"

Bash# Find all IntentLog-related recalls
memory-vault search-justifications "IntentLog"

# Verify entire audit trail
memory-vault verify-integrity
Backup Strategy

Full + incremental backups include IntentLog-linked memories
Non-exportable (TPM) memories are skipped with warning
Restore re-establishes links (memory_id preserved)

Next Steps for Integration

Add intent_ref to your IntentLog schema
Route high-value entries through store_critical_intent()
On agent reflection/goal recall:
Check if intent has a vault memory_id
If yes → use recall_critical_intent() with justification

Use Vault search for powerful reflection:Pythonfrom memory_vault.db import search_memories_metadata
results = search_memories_metadata("IntentLog recovery OR seed")

Result
Your agent now has:

Fast, ephemeral memory for daily operation (synth-mind)
Sovereign, protected memory for anything that matters long-term (Memory Vault)
Full audit trail of when and why critical intents were recalled
Human-in-the-loop for existential decisions

The loop is closed: Intent → Action → Outcome → Secure Reflection → Evolution
The agent can now learn, remember, and protect its most sacred knowledge — without ever compromising sovereignty.
Integration complete.
