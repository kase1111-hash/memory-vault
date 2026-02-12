from dataclasses import dataclass, field
from datetime import datetime, timezone
import uuid

@dataclass
class MemoryObject:
    memory_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "agent"  # or "human"
    classification: int = 1  # 0-5
    encryption_profile: str = "default-passphrase"
    content_plaintext: bytes = b""  # Only in-memory, never stored
    content_hash: str = ""
    intent_ref: str = None
    value_metadata: dict = None
    access_policy: dict = None
    audit_proof: str = None  # Future Merkle ref

@dataclass
class EncryptionProfile:
    profile_id: str
    cipher: str = "XSalsa20-Poly1305"
    key_source: str = "HumanPassphrase"  # or "File", "TPM"
    rotation_policy: str = "manual"
    exportable: bool = False

@dataclass
class RecallRequest:
    memory_id: str
    requester: str
    justification: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    approved: bool = False
