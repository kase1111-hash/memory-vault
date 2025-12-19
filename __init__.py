# memory_vault/__init__.py
"""
Memory Vault - Secure, owner-sovereign, offline-first storage for high-value cognitive artifacts.

This package provides classification-bound access control, tamper-evident auditing,
hardware-bound secrets, and human-in-the-loop controls for AI agent memory systems.
"""

__version__ = "1.0.0"
__author__ = "kase1111-hash"

from .vault import MemoryVault
from .models import MemoryObject, EncryptionProfile, RecallRequest
from .db import init_db, search_memories_metadata, search_recall_justifications

__all__ = [
    "MemoryVault",
    "MemoryObject",
    "EncryptionProfile",
    "RecallRequest",
    "init_db",
    "search_memories_metadata",
    "search_recall_justifications",
]
