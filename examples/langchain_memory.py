"""
Example: Using Memory Vault as a LangChain-compatible memory backend.

Memory Vault provides encrypted, classification-gated storage for AI agent
memories. This example shows how to use it as a drop-in memory store for
LangChain or any agent framework.

Requirements:
    pip install memory-vault
"""

import sys
import os

# For running from the examples directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vault import MemoryVault
from models import MemoryObject


def basic_usage():
    """Store and recall a memory in 3 lines."""
    vault = MemoryVault()
    vault.create_profile("default", passphrase="my-secret")

    # Store a memory
    obj = MemoryObject(
        content_plaintext=b"The user prefers dark mode",
        classification=1,
    )
    vault.store_memory(obj, passphrase="my-secret")

    # Recall it
    content = vault.recall_memory(
        obj.memory_id,
        justification="personalizing UI",
        passphrase="my-secret",
        skip_boundary_check=True,
    )
    print(f"Recalled: {content.decode()}")
    return content


def classified_memories():
    """Demonstrate classification levels for different memory types."""
    vault = MemoryVault()
    vault.create_profile("agent-profile", passphrase="agent-secret-key")

    # Level 0: Ephemeral - auto-recall, auto-purge
    ephemeral = MemoryObject(
        content_plaintext=b"Current weather: 72F sunny",
        classification=0,
    )
    vault.store_memory(ephemeral, passphrase="agent-secret-key")

    # Level 1: Working - auto-recall
    working = MemoryObject(
        content_plaintext=b"User asked about Python decorators yesterday",
        classification=1,
    )
    vault.store_memory(working, passphrase="agent-secret-key")

    # Level 2: Private - auto-recall, encrypted at rest
    private = MemoryObject(
        content_plaintext=b"User's project deadline is March 15",
        classification=2,
    )
    vault.store_memory(private, passphrase="agent-secret-key")

    # Level 3+: Requires human approval (not shown here - interactive)

    # Recall working memory
    content = vault.recall_memory(
        working.memory_id,
        justification="answering follow-up question about decorators",
        passphrase="agent-secret-key",
        skip_boundary_check=True,
    )
    print(f"Working memory: {content.decode()}")


def memory_with_cooldown():
    """Store a memory with access throttling."""
    vault = MemoryVault()
    vault.create_profile("throttled", passphrase="throttle-key")

    # Store with 60-second cooldown between accesses
    obj = MemoryObject(
        content_plaintext=b"API key: sk-example-12345",
        classification=2,
        access_policy={"cooldown_seconds": 60},
    )
    vault.store_memory(obj, passphrase="throttle-key")

    # First recall succeeds
    content = vault.recall_memory(
        obj.memory_id,
        justification="making API call",
        passphrase="throttle-key",
        skip_boundary_check=True,
    )
    print(f"First recall: {content.decode()}")

    # Second recall within 60s would raise CooldownError
    # from errors import CooldownError
    # try:
    #     vault.recall_memory(obj.memory_id, ...)
    # except CooldownError as e:
    #     print(f"Throttled: {e}")


def langchain_adapter():
    """Sketch of a LangChain memory adapter using Memory Vault.

    This shows the pattern for wrapping Memory Vault as a
    LangChain-compatible memory backend. The actual LangChain
    integration would subclass langchain.memory.BaseMemory.
    """

    class VaultMemory:
        """Simple adapter that wraps Memory Vault for agent use."""

        def __init__(self, passphrase: str, profile: str = "default"):
            self.vault = MemoryVault()
            self.passphrase = passphrase
            self.profile = profile
            try:
                self.vault.create_profile(profile, passphrase=passphrase)
            except Exception:
                pass  # Profile already exists

        def save(self, content: str, classification: int = 1) -> str:
            """Store a memory, return its ID."""
            obj = MemoryObject(
                content_plaintext=content.encode("utf-8"),
                classification=classification,
            )
            self.vault.store_memory(obj, passphrase=self.passphrase)
            return obj.memory_id

        def load(self, memory_id: str, justification: str = "agent recall") -> str:
            """Recall a memory by ID."""
            content = self.vault.recall_memory(
                memory_id,
                justification=justification,
                passphrase=self.passphrase,
                skip_boundary_check=True,
            )
            return content.decode("utf-8")

    # Usage
    memory = VaultMemory(passphrase="my-agent-key")

    # Store
    mid = memory.save("The user's favorite color is blue")
    print(f"Stored memory: {mid}")

    # Recall
    content = memory.load(mid, justification="personalizing response")
    print(f"Recalled: {content}")


if __name__ == "__main__":
    print("=== Basic Usage ===")
    basic_usage()
    print()

    print("=== Classified Memories ===")
    classified_memories()
    print()

    print("=== LangChain Adapter Pattern ===")
    langchain_adapter()
