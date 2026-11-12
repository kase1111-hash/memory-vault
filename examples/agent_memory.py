"""
Example: Memory Vault as long-term memory for an AI agent.

Two ways to use it are shown:

1. ``library_usage`` - the core API: encrypt, store and recall directly.
2. ``agent_tools`` - ``VaultToolkit``, the same operations the MCP server exposes
   (remember / search / recall / forget), as plain functions you can hand to any
   tool-calling loop.

Most people do not need to write code at all: run ``memory-vault-mcp`` and point
an MCP client (Claude Code, Claude Desktop, Cursor, ...) at it. See the README.

Run:
    pip install memory-vault
    python examples/agent_memory.py

The demo keeps its database in a temporary directory, so it never touches your
real vault. (The agent profile's key file is created under ~/.memory_vault/keys/.)
"""

import os
import sys
import tempfile

# Allow running from a source checkout without installing
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp_server import VaultToolError, VaultToolkit
from models import MemoryObject
from vault import MemoryVault


def library_usage(db_path: str) -> None:
    """Store and recall with a passphrase-protected profile."""
    vault = MemoryVault(db_path, interactive=False)  # never prompt on the terminal

    obj = MemoryObject(
        content_plaintext=b"The user prefers dark mode",
        classification=1,
        value_metadata={"summary": "UI preferences"},  # stored unencrypted, searchable
    )
    # The first use of a passphrase runs Argon2id (about 1 GB of RAM and a few
    # seconds, by design). The derived key is then cached for five minutes.
    vault.store_memory(obj, passphrase="my-secret")

    content = vault.recall_memory(obj.memory_id, justification="personalizing UI", passphrase="my-secret")
    print(f"Recalled: {content.decode()}")

    # Every recall is in the signed audit log.
    print(f"Audit log intact: {vault.verify_integrity()}")
    vault.close()


def agent_tools(db_path: str) -> None:
    """The operations an agent calls. These are exactly the MCP server's tools."""
    memory = VaultToolkit(db_path=db_path, profile="example-agent")  # keyfile profile, no passphrase

    saved = memory.remember(
        content="Deploys go out on Tuesdays; never on Fridays. Staging is staging.example.internal.",
        summary="Deployment schedule and staging host",
        tags=["deploy", "ops"],
        classification=2,
    )
    print(f"Remembered {saved['memory_id']}")

    # Later (or in another session): find it by topic, then read it.
    hits = memory.search_memories("when can I deploy?")["memories"]
    print(f"Search found: {[h['summary'] for h in hits]}")

    recalled = memory.recall(hits[0]["memory_id"], justification="user asked to schedule a release")
    print(f"Content: {recalled['content']}")

    # Sensitive memories need the human: without approval the recall is refused (and logged).
    sealed = memory.remember("sk-live-123", "Billing API key", classification=3)
    try:
        memory.recall(sealed["memory_id"], justification="charging a customer")
    except VaultToolError as e:
        print(f"Level 3 recall refused: {e}")

    memory.forget(saved["memory_id"], reason="schedule changed")
    print(f"After forgetting: {memory.search_memories('deploy')['memories']}")


if __name__ == "__main__":
    # The demo has no boundary daemon; this skips that check. Never set it in production.
    os.environ["MEMORY_VAULT_TESTING"] = "1"

    with tempfile.TemporaryDirectory() as tmp:
        print("=== Library usage ===")
        library_usage(os.path.join(tmp, "library.db"))
        print()
        print("=== Agent tools ===")
        agent_tools(os.path.join(tmp, "agent.db"))
