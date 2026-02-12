# memory_vault/__init__.py
"""
Memory Vault - Secure, owner-sovereign, offline-first storage for high-value cognitive artifacts.

This package provides classification-bound access control, tamper-evident auditing,
hardware-bound secrets, and human-in-the-loop controls for AI agent memory systems.
"""

__version__ = "0.1.0-alpha"
__author__ = "kase1111-hash"

# Support both package import (pip install) and direct module import
try:
    from .vault import MemoryVault
    from .models import MemoryObject, EncryptionProfile, RecallRequest
    from .db import init_db, search_memories_metadata, search_recall_justifications
except ImportError:
    from vault import MemoryVault
    from models import MemoryObject, EncryptionProfile, RecallRequest
    from db import init_db, search_memories_metadata, search_recall_justifications

# Error handling framework
try:
    from .errors import (
        MemoryVaultError,
        Severity,
        CryptoError,
        DecryptionError,
        EncryptionError,
        KeyDerivationError,
        SignatureError,
        AccessError,
        ClassificationError,
        CooldownError,
        ApprovalRequiredError,
        LockdownError,
        TombstoneError,
        BoundaryError,
        BoundaryConnectionError,
        BoundaryDeniedError,
        BoundaryTimeoutError,
        DatabaseError,
        DatabaseConnectionError,
        DatabaseIntegrityError,
        MemoryNotFoundError,
        ProfileNotFoundError,
        ProfileError,
        ProfileExistsError,
        ProfileKeyMissingError,
        IntegrityError,
        MerkleVerificationError,
        AuditTrailError,
        BackupError,
        RestoreError,
        HardwareSecurityError,
        TPMError,
        FIDO2Error,
        PhysicalTokenError,
        ConfigurationError,
        PolicyViolationError,
    )
    ERRORS_AVAILABLE = True
except ImportError:
    try:
        from errors import (
            MemoryVaultError,
            Severity,
            CryptoError,
            DecryptionError,
            EncryptionError,
            KeyDerivationError,
            SignatureError,
            AccessError,
            ClassificationError,
            CooldownError,
            ApprovalRequiredError,
            LockdownError,
            TombstoneError,
            BoundaryError,
            BoundaryConnectionError,
            BoundaryDeniedError,
            BoundaryTimeoutError,
            DatabaseError,
            DatabaseConnectionError,
            DatabaseIntegrityError,
            MemoryNotFoundError,
            ProfileNotFoundError,
            ProfileError,
            ProfileExistsError,
            ProfileKeyMissingError,
            IntegrityError,
            MerkleVerificationError,
            AuditTrailError,
            BackupError,
            RestoreError,
            HardwareSecurityError,
            TPMError,
            FIDO2Error,
            PhysicalTokenError,
            ConfigurationError,
            PolicyViolationError,
        )
        ERRORS_AVAILABLE = True
    except ImportError:
        ERRORS_AVAILABLE = False

# Boundary daemon client
try:
    from .boundary import (
        BoundaryClient,
        BoundaryStatus,
        OperationalMode,
        check_recall,
        get_client as get_boundary_client,
    )
    BOUNDARY_AVAILABLE = True
except ImportError:
    try:
        from boundary import (
            BoundaryClient,
            BoundaryStatus,
            OperationalMode,
            check_recall,
            get_client as get_boundary_client,
        )
        BOUNDARY_AVAILABLE = True
    except ImportError:
        BOUNDARY_AVAILABLE = False




__all__ = [
    # Core
    "MemoryVault",
    "MemoryObject",
    "EncryptionProfile",
    "RecallRequest",
    "init_db",
    "search_memories_metadata",
    "search_recall_justifications",
    # Availability flags
    "ERRORS_AVAILABLE",
    "BOUNDARY_AVAILABLE",



]

# Add error classes to __all__ if available
if ERRORS_AVAILABLE:
    __all__.extend([
        "MemoryVaultError",
        "Severity",
        "CryptoError",
        "DecryptionError",
        "EncryptionError",
        "KeyDerivationError",
        "SignatureError",
        "AccessError",
        "ClassificationError",
        "CooldownError",
        "ApprovalRequiredError",
        "LockdownError",
        "TombstoneError",
        "BoundaryError",
        "BoundaryConnectionError",
        "BoundaryDeniedError",
        "BoundaryTimeoutError",
        "DatabaseError",
        "DatabaseConnectionError",
        "DatabaseIntegrityError",
        "MemoryNotFoundError",
        "ProfileNotFoundError",
        "ProfileError",
        "ProfileExistsError",
        "ProfileKeyMissingError",
        "IntegrityError",
        "MerkleVerificationError",
        "AuditTrailError",
        "BackupError",
        "RestoreError",
        "HardwareSecurityError",
        "TPMError",
        "FIDO2Error",
        "PhysicalTokenError",
        "ConfigurationError",
        "PolicyViolationError",
    ])

# Add Boundary exports if available
if BOUNDARY_AVAILABLE:
    __all__.extend([
        "BoundaryClient",
        "BoundaryStatus",
        "OperationalMode",
        "check_recall",
        "get_boundary_client",
    ])



