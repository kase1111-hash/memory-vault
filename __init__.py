"""Memory Vault - Encrypted, classification-gated storage for AI agent memories."""

__version__ = "0.1.0-alpha"
__author__ = "kase1111-hash"

# Support both package import (pip install) and direct module import
try:
    from .vault import MemoryVault
    from .models import MemoryObject, EncryptionProfile, RecallRequest
    from .db import init_db
    from .errors import (
        MemoryVaultError,
        Severity,
        CryptoError,
        DecryptionError,
        AccessError,
        CooldownError,
        ApprovalRequiredError,
        LockdownError,
        TombstoneError,
        BoundaryError,
        BoundaryConnectionError,
        BoundaryDeniedError,
        BoundaryTimeoutError,
        DatabaseError,
        MemoryNotFoundError,
        ProfileError,
        ProfileKeyMissingError,
        HardwareSecurityError,
        PhysicalTokenError,
    )
except ImportError:
    from vault import MemoryVault
    from models import MemoryObject, EncryptionProfile, RecallRequest
    from db import init_db
    from errors import (
        MemoryVaultError,
        Severity,
        CryptoError,
        DecryptionError,
        AccessError,
        CooldownError,
        ApprovalRequiredError,
        LockdownError,
        TombstoneError,
        BoundaryError,
        BoundaryConnectionError,
        BoundaryDeniedError,
        BoundaryTimeoutError,
        DatabaseError,
        MemoryNotFoundError,
        ProfileError,
        ProfileKeyMissingError,
        HardwareSecurityError,
        PhysicalTokenError,
    )

__all__ = [
    # Core
    "MemoryVault",
    "MemoryObject",
    "EncryptionProfile",
    "RecallRequest",
    "init_db",
    # Errors
    "MemoryVaultError",
    "Severity",
    "CryptoError",
    "DecryptionError",
    "AccessError",
    "CooldownError",
    "ApprovalRequiredError",
    "LockdownError",
    "TombstoneError",
    "BoundaryError",
    "BoundaryConnectionError",
    "BoundaryDeniedError",
    "BoundaryTimeoutError",
    "DatabaseError",
    "MemoryNotFoundError",
    "ProfileError",
    "ProfileKeyMissingError",
    "HardwareSecurityError",
    "PhysicalTokenError",
]
