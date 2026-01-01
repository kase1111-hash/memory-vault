# memory_vault/__init__.py
"""
Memory Vault - Secure, owner-sovereign, offline-first storage for high-value cognitive artifacts.

This package provides classification-bound access control, tamper-evident auditing,
hardware-bound secrets, and human-in-the-loop controls for AI agent memory systems.

Integrations:
- NatLangChain: Blockchain anchoring for immutable audit trails
- Agent-OS: Governance and boundary enforcement
- MP-02: Proof-of-Effort Receipt Protocol for verifying human effort
- Boundary-SIEM: Security event reporting and monitoring
- boundary-daemon: Connection protection and operational mode enforcement
"""

__version__ = "1.2.0"
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
        SIEMError,
        SIEMConnectionError,
        SIEMReportingError,
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
            SIEMError,
            SIEMConnectionError,
            SIEMReportingError,
        )
        ERRORS_AVAILABLE = True
    except ImportError:
        ERRORS_AVAILABLE = False

# SIEM reporting
try:
    from .siem_reporter import (
        SIEMReporter,
        SIEMConfig,
        Protocol as SIEMProtocol,
        get_reporter,
        report_event,
        report_exception,
        configure_siem,
        shutdown_siem,
    )
    SIEM_AVAILABLE = True
except ImportError:
    try:
        from siem_reporter import (
            SIEMReporter,
            SIEMConfig,
            Protocol as SIEMProtocol,
            get_reporter,
            report_event,
            report_exception,
            configure_siem,
            shutdown_siem,
        )
        SIEM_AVAILABLE = True
    except ImportError:
        SIEM_AVAILABLE = False

# Boundary daemon client
try:
    from .boundry import (
        BoundaryClient,
        BoundaryStatus,
        OperationalMode,
        check_recall,
        get_client as get_boundary_client,
    )
    BOUNDARY_AVAILABLE = True
except ImportError:
    try:
        from boundry import (
            BoundaryClient,
            BoundaryStatus,
            OperationalMode,
            check_recall,
            get_client as get_boundary_client,
        )
        BOUNDARY_AVAILABLE = True
    except ImportError:
        BOUNDARY_AVAILABLE = False

# NatLangChain integration
try:
    try:
        from .natlangchain import (
            NatLangChainClient,
            NatLangEntry,
            ChainProof,
            anchor_memory_to_chain,
            anchor_effort_receipt,
            verify_memory_anchor,
            get_memory_chain_history,
        )
    except ImportError:
        from natlangchain import (
            NatLangChainClient,
            NatLangEntry,
            ChainProof,
            anchor_memory_to_chain,
            anchor_effort_receipt,
            verify_memory_anchor,
            get_memory_chain_history,
        )
    NATLANGCHAIN_AVAILABLE = True
except ImportError:
    NATLANGCHAIN_AVAILABLE = False

# MP-02 Effort tracking
try:
    try:
        from .effort import (
            EffortObserver,
            EffortValidator,
            EffortReceipt,
            EffortSegment,
            Signal,
            SignalType,
            generate_receipt,
            get_receipt,
            get_receipts_for_memory,
            link_receipt_to_memory,
            list_pending_segments,
        )
    except ImportError:
        from effort import (
            EffortObserver,
            EffortValidator,
            EffortReceipt,
            EffortSegment,
            Signal,
            SignalType,
            generate_receipt,
            get_receipt,
            get_receipts_for_memory,
            link_receipt_to_memory,
            list_pending_segments,
        )
    EFFORT_AVAILABLE = True
except ImportError:
    EFFORT_AVAILABLE = False

# Agent-OS governance
try:
    try:
        from .agent_os import (
            BoundaryDaemon,
            ConstitutionManager,
            GovernanceLogger,
            AgentIdentity,
            AgentRole,
            OperationalMode,
            check_agent_permission,
            require_human_authority,
            get_governance_summary,
            verify_vault_constitution,
            register_memory_vault_agent,
        )
    except ImportError:
        from agent_os import (
            BoundaryDaemon,
            ConstitutionManager,
            GovernanceLogger,
            AgentIdentity,
            AgentRole,
            OperationalMode,
            check_agent_permission,
            require_human_authority,
            get_governance_summary,
            verify_vault_constitution,
            register_memory_vault_agent,
        )
    AGENT_OS_AVAILABLE = True
except ImportError:
    AGENT_OS_AVAILABLE = False

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
    "SIEM_AVAILABLE",
    "BOUNDARY_AVAILABLE",
    "NATLANGCHAIN_AVAILABLE",
    "EFFORT_AVAILABLE",
    "AGENT_OS_AVAILABLE",
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
        "SIEMError",
        "SIEMConnectionError",
        "SIEMReportingError",
    ])

# Add SIEM exports if available
if SIEM_AVAILABLE:
    __all__.extend([
        "SIEMReporter",
        "SIEMConfig",
        "SIEMProtocol",
        "get_reporter",
        "report_event",
        "report_exception",
        "configure_siem",
        "shutdown_siem",
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

# Conditionally add NatLangChain exports
if NATLANGCHAIN_AVAILABLE:
    __all__.extend([
        "NatLangChainClient",
        "NatLangEntry",
        "ChainProof",
        "anchor_memory_to_chain",
        "anchor_effort_receipt",
        "verify_memory_anchor",
        "get_memory_chain_history",
    ])

# Conditionally add effort tracking exports
if EFFORT_AVAILABLE:
    __all__.extend([
        "EffortObserver",
        "EffortValidator",
        "EffortReceipt",
        "EffortSegment",
        "Signal",
        "SignalType",
        "generate_receipt",
        "get_receipt",
        "get_receipts_for_memory",
        "link_receipt_to_memory",
        "list_pending_segments",
    ])

# Conditionally add Agent-OS exports
if AGENT_OS_AVAILABLE:
    __all__.extend([
        "BoundaryDaemon",
        "ConstitutionManager",
        "GovernanceLogger",
        "AgentIdentity",
        "AgentRole",
        "OperationalMode",
        "check_agent_permission",
        "require_human_authority",
        "get_governance_summary",
        "verify_vault_constitution",
        "register_memory_vault_agent",
    ])
