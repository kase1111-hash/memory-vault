# memory_vault/__init__.py
"""
Memory Vault - Secure, owner-sovereign, offline-first storage for high-value cognitive artifacts.

This package provides classification-bound access control, tamper-evident auditing,
hardware-bound secrets, and human-in-the-loop controls for AI agent memory systems.

Integrations:
- NatLangChain: Blockchain anchoring for immutable audit trails
- Agent-OS: Governance and boundary enforcement
- MP-02: Proof-of-Effort Receipt Protocol for verifying human effort
"""

__version__ = "1.1.0"
__author__ = "kase1111-hash"

from .vault import MemoryVault
from .models import MemoryObject, EncryptionProfile, RecallRequest
from .db import init_db, search_memories_metadata, search_recall_justifications

# NatLangChain integration
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
    NATLANGCHAIN_AVAILABLE = True
except ImportError:
    NATLANGCHAIN_AVAILABLE = False

# MP-02 Effort tracking
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
    EFFORT_AVAILABLE = True
except ImportError:
    EFFORT_AVAILABLE = False

# Agent-OS governance
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
    "NATLANGCHAIN_AVAILABLE",
    "EFFORT_AVAILABLE",
    "AGENT_OS_AVAILABLE",
]

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
