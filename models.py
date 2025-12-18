from dataclasses import dataclass, field
from datetime import datetime
import uuid

@dataclass
class MemoryObject:
    memory_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = "agent"  # or "human"
    classification: int = 1  # 0-5
    encryption_profile: str = "default-passphrase"
    content_plaintext: bytes = b""  # Only in-memory, never stored
    content_hash: str = ""
    intent_ref: str = None
    value_metadata: dict = field(default_factory=dict)
    access_policy: dict = field(default_factory=lambda: {"recall_conditions": [], "cooldown_seconds": 0})
    audit_proof: str = None  # Future Merkle ref

@dataclass
class EncryptionProfile:
    profile_id: str
    cipher: str = "AES-256-GCM"
    key_source: str = "HumanPassphrase"  # or "File", "TPM"
    rotation_policy: str = "manual"
    exportable: bool = False

@dataclass
class RecallRequest:
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    memory_id: str
    requester: str
    justification: str
    approved: bool = False
