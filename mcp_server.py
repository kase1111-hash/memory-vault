"""
Model Context Protocol (MCP) server for Memory Vault.

Exposes the vault to any MCP-capable AI client (Claude Code, Claude Desktop,
Cursor, agent SDKs, ...) as a small set of tools, so an assistant gets durable
memory that is encrypted at rest, stays on the owner's machine, and leaves a
signed audit trail of every recall.

Run it with ``memory-vault-mcp`` (or ``python -m memory_vault.mcp_server``).
Requires the optional dependency: ``pip install "memory-vault[mcp]"``.

Configuration is by environment variable:

    MEMORY_VAULT_DB               Path to the vault database (default ~/.memory_vault/vault.db)
    MEMORY_VAULT_PROFILE          Encryption profile to use
    MEMORY_VAULT_PASSPHRASE       Passphrase for a passphrase profile
    MEMORY_VAULT_PASSPHRASE_FILE  File containing that passphrase (preferred over the variable)

With no passphrase configured the server uses a keyfile profile named
``mcp-agent`` and generates its key under ``~/.memory_vault/keys/`` on first run.

The tool logic lives in :class:`VaultToolkit`, which has no MCP dependency and
can be wired into any other tool-calling framework.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys

try:
    from .vault import MemoryVault
    from .models import MemoryObject
    from .errors import ApprovalRequiredError, MemoryVaultError
    from .crypto import validate_profile_id
    from .boundary import check_recall
except ImportError:  # direct (flat) import
    from boundary import check_recall
    from vault import MemoryVault
    from models import MemoryObject
    from errors import ApprovalRequiredError, MemoryVaultError
    from crypto import validate_profile_id

try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import Context
    from mcp.server.mcpserver import MCPServer as _Server
    from mcp.server.mcpserver.exceptions import ToolError as _ToolError
except ImportError:
    try:  # MCP Python SDK 1.x
        from mcp.server.fastmcp import Context
        from mcp.server.fastmcp import FastMCP as _Server
        from mcp.server.fastmcp.exceptions import ToolError as _ToolError
    except ImportError:
        Context = None
        _Server = None
        _ToolError = None

DEFAULT_KEYFILE_PROFILE = "mcp-agent"
DEFAULT_PASSPHRASE_PROFILE = "default-passphrase"  # noqa: S105 - a profile name, not a secret
MAX_CONTENT_BYTES = 1_000_000
MAX_AUTO_RECALL_LEVEL = 2  # Levels 0-2 are auto-recall; 3-4 need a human; 5 needs a token.
MAX_APPROVABLE_LEVEL = 4

INSTRUCTIONS = """\
Memory Vault is the user's private long-term memory: encrypted at rest, stored only on \
their machine, and every recall is written to a signed audit log.

- Use `remember` to save durable facts, preferences, decisions and context worth keeping \
across sessions. Do not save trivia or anything the user asked you not to keep.
- Use `search_memories` (or `list_memories`) to find what is already known before asking \
the user to repeat themselves, then `recall` to read a memory's content.
- `summary` and `tags` are stored UNENCRYPTED as the search index. Describe the topic \
there ("API key for the staging billing service") but never put the secret itself in them.
- Pick a classification: 0 ephemeral (purged after a day), 1 working, 2 private, \
3-4 sensitive (the user must approve each recall, and the vault's boundary daemon must be \
running), 5 secrets needing a physical token (cannot be recalled through this server). \
Use 1 or 2 unless the user asks for more protection.
- Give an honest, specific `justification` when recalling: the user can read the audit log.
- Use `forget` when a memory is wrong, outdated, or the user asks you to forget it.
"""


class VaultToolError(Exception):
    """A tool call failed for a reason the caller (model or user) can act on."""


class VaultToolkit:
    """Agent-facing operations on a :class:`MemoryVault`.

    Framework-neutral: every method takes and returns plain JSON-serialisable
    values, so it can back MCP tools, native tool-use loops, or tests.
    """

    def __init__(
        self,
        db_path: str | None = None,
        profile: str | None = None,
        passphrase: str | None = None,
    ):
        self._passphrase = passphrase or None
        self._human_approved = False
        self.profile = profile or (DEFAULT_PASSPHRASE_PROFILE if self._passphrase else DEFAULT_KEYFILE_PROFILE)
        validate_profile_id(self.profile)
        # Never touch the terminal: stdin/stdout belong to the protocol.
        self.vault = MemoryVault(db_path=db_path, interactive=False, approver=self._approver)
        self.key_source = self._ensure_profile()

    @classmethod
    def from_env(cls, env=None) -> VaultToolkit:
        """Build a toolkit from MEMORY_VAULT_* environment variables."""
        env = os.environ if env is None else env
        passphrase = env.get("MEMORY_VAULT_PASSPHRASE") or None
        passphrase_file = env.get("MEMORY_VAULT_PASSPHRASE_FILE")
        if passphrase_file:
            try:
                with open(os.path.expanduser(passphrase_file), encoding="utf-8") as f:
                    passphrase = f.read().strip("\r\n")
            except OSError as e:
                raise VaultToolError(f"Cannot read MEMORY_VAULT_PASSPHRASE_FILE: {e}") from e
            if not passphrase:
                raise VaultToolError("MEMORY_VAULT_PASSPHRASE_FILE is empty")
        return cls(
            db_path=env.get("MEMORY_VAULT_DB") or None,
            profile=env.get("MEMORY_VAULT_PROFILE") or None,
            passphrase=passphrase,
        )

    # ---- setup -----------------------------------------------------------

    def _approver(self, memory_id, classification, requester, justification) -> bool:
        return self._human_approved

    def _ensure_profile(self) -> str:
        profiles = {p["profile_id"]: p["key_source"] for p in self.vault.list_profiles()}
        key_source = profiles.get(self.profile)

        if key_source is None:
            if self._passphrase:
                self.vault.create_profile(self.profile, key_source="HumanPassphrase", passphrase=self._passphrase)
                return "HumanPassphrase"
            # Reuse an existing key rather than replacing it: another database may depend on it.
            self.vault.create_profile(
                self.profile, key_source="KeyFile", generate_keyfile=not os.path.exists(self._keyfile_path())
            )
            return "KeyFile"

        if key_source == "HumanPassphrase" and not self._passphrase:
            raise VaultToolError(
                f"Profile '{self.profile}' is passphrase-protected. Set MEMORY_VAULT_PASSPHRASE_FILE "
                "(or MEMORY_VAULT_PASSPHRASE), or choose a keyfile profile with MEMORY_VAULT_PROFILE."
            )
        if key_source == "KeyFile" and not os.path.exists(self._keyfile_path()):
            raise VaultToolError(
                f"Keyfile for profile '{self.profile}' is missing ({self._keyfile_path()}). "
                "Restore it from your backup: memories stored with it cannot be read without it."
            )
        if key_source not in ("HumanPassphrase", "KeyFile"):
            raise VaultToolError(
                f"Profile '{self.profile}' uses key source '{key_source}', which is not supported here"
            )
        return key_source

    def _keyfile_path(self) -> str:
        return os.path.expanduser(f"~/.memory_vault/keys/{self.profile}.key")

    @staticmethod
    def _envelope(info: dict) -> dict:
        metadata = info.get("metadata") if isinstance(info.get("metadata"), dict) else {}
        tags = metadata.get("tags")
        return {
            "memory_id": info["memory_id"],
            "summary": metadata.get("summary") or "",
            "tags": tags if isinstance(tags, list) else [],
            "classification": info["classification"],
            "created_at": info["created_at"],
        }

    # ---- tools -----------------------------------------------------------

    def remember(self, content: str, summary: str, tags: list[str] | None = None, classification: int = 1) -> dict:
        """Encrypt and store a memory. Returns its envelope (including the new memory_id)."""
        if not isinstance(content, str) or not content.strip():
            raise VaultToolError("content must be a non-empty string")
        if not isinstance(summary, str) or not summary.strip():
            raise VaultToolError("summary must be a non-empty string: it is how the memory is found later")
        if isinstance(classification, bool) or not isinstance(classification, int) or not 0 <= classification <= 5:
            raise VaultToolError("classification must be an integer from 0 to 5")
        data = content.encode("utf-8")
        if len(data) > MAX_CONTENT_BYTES:
            raise VaultToolError(f"content is too large ({len(data)} bytes; limit is {MAX_CONTENT_BYTES})")
        clean_tags = [str(t).strip() for t in (tags or []) if str(t).strip()]

        obj = MemoryObject(
            content_plaintext=data,
            classification=classification,
            encryption_profile=self.profile,
            created_by="agent",
            value_metadata={"summary": summary.strip(), "tags": clean_tags, "source": "mcp"},
        )
        try:
            self.vault.store_memory(obj, passphrase=self._passphrase)
        except MemoryVaultError as e:
            raise VaultToolError(e.message) from e
        return self._envelope(self.vault.get_memory_info(obj.memory_id))

    def search_memories(self, query: str, limit: int = 10) -> dict:
        """Search memory summaries and tags. Content is encrypted and is not searched."""
        limit = max(1, min(int(limit), 50))
        return {"memories": [self._envelope(i) for i in self.vault.search_memories(query or "", limit=limit)]}

    def list_memories(self, limit: int = 20) -> dict:
        """List the most recent memories (envelopes only)."""
        limit = max(1, min(int(limit), 100))
        return {"memories": [self._envelope(i) for i in self.vault.list_memories(limit=limit)]}

    def approval_prompt(self, memory_id: str, justification: str = "") -> str | None:
        """Return the question to put to the human if recalling this memory needs approval.

        Returns None when there is nothing to ask: either no approval is needed, or
        the vault's boundary check would refuse the recall anyway (calling
        :meth:`recall` then records and reports that denial). Raises if the memory
        can never be recalled through this toolkit.
        """
        info = self._info(memory_id)
        level = info["classification"]
        if level > MAX_APPROVABLE_LEVEL:
            raise VaultToolError(
                f"Level {level} memories require a physical token and can only be recalled by the owner "
                "from the command line (memory-vault recall)."
            )
        if level <= MAX_AUTO_RECALL_LEVEL:
            return None
        if os.environ.get("MEMORY_VAULT_TESTING") != "1" and not check_recall(level)[0]:
            return None  # don't bother the human with a recall the boundary will refuse
        summary = self._envelope(info)["summary"] or "(no summary)"
        return (
            f"The assistant wants to recall a Level {level} memory from your Memory Vault.\n"
            f"Memory: {summary}\n"
            f"Stated reason: {justification or '(none given)'}\n"
            "Approve this recall?"
        )

    def recall(self, memory_id: str, justification: str, human_approved: bool = False) -> dict:
        """Decrypt and return a memory. The recall is logged whether or not it succeeds.

        ``human_approved`` must only be True when a human has just approved this
        specific recall (see :meth:`approval_prompt`); it is ignored for Level 0-2.
        """
        if not isinstance(justification, str) or not justification.strip():
            raise VaultToolError("justification is required: every recall is recorded in the audit log")
        info = self._info(memory_id)
        if info["classification"] > MAX_APPROVABLE_LEVEL:
            self.approval_prompt(memory_id)  # raises with the explanation
        self._human_approved = bool(human_approved)
        try:
            plaintext = self.vault.recall_memory(
                memory_id,
                justification=justification.strip(),
                requester="mcp-agent",
                passphrase=self._passphrase,
            )
        except ApprovalRequiredError as e:
            raise VaultToolError(
                f"Level {info['classification']} recall needs the user's approval, which was not given"
            ) from e
        except MemoryVaultError as e:
            raise VaultToolError(e.message) from e
        finally:
            self._human_approved = False
        result = self._envelope(info)
        result["content"] = plaintext.decode("utf-8", errors="replace")
        return result

    def forget(self, memory_id: str, reason: str) -> dict:
        """Tombstone a memory: it can no longer be recalled, but its audit trail is kept."""
        if not isinstance(reason, str) or not reason.strip():
            raise VaultToolError("reason is required")
        info = self._info(memory_id)
        if info["classification"] > MAX_AUTO_RECALL_LEVEL:
            raise VaultToolError(
                f"Level {info['classification']} memories can only be tombstoned by the owner "
                "from the command line (memory-vault tombstone)."
            )
        if info["tombstoned"]:
            return {"memory_id": memory_id, "forgotten": True, "note": "already forgotten"}
        self.vault.tombstone_memory(memory_id, reason.strip(), skip_confirmation=True)
        return {"memory_id": memory_id, "forgotten": True}

    def status(self) -> dict:
        """Summarise the vault: counts per classification, lockdown state, active profile."""
        c = self.vault.conn.cursor()
        c.execute(
            "SELECT classification, COUNT(*) FROM memories WHERE COALESCE(tombstoned, 0) = 0 GROUP BY classification"
        )
        by_level = {str(level): count for level, count in c.fetchall()}
        locked, since, reason = self.vault.is_locked_down()
        return {
            "profile": self.profile,
            "key_source": self.key_source,
            "memory_count": sum(by_level.values()),
            "by_classification": by_level,
            "lockdown": locked,
            "lockdown_since": since,
            "lockdown_reason": reason,
            "database": self.vault.db_path,
        }

    def _info(self, memory_id: str) -> dict:
        if not isinstance(memory_id, str) or not memory_id.strip():
            raise VaultToolError("memory_id is required")
        try:
            return self.vault.get_memory_info(memory_id.strip())
        except MemoryVaultError as e:
            raise VaultToolError(e.message) from e


def build_server(toolkit: VaultToolkit):
    """Create the MCP server exposing ``toolkit``'s operations as tools."""
    if _Server is None:
        raise RuntimeError('The MCP SDK is not installed. Install it with: pip install "memory-vault[mcp]"')

    from mcp.types import ToolAnnotations
    from pydantic import BaseModel, Field

    class RecallApproval(BaseModel):
        approve: bool = Field(description="Allow the assistant to read this memory?")

    server = _Server("memory-vault", instructions=INSTRUCTIONS)

    def run(fn, *args, **kwargs):
        # The vault library prints progress to stdout, which carries the protocol
        # on the stdio transport. Tools run on the event-loop thread with no await
        # inside this block, so the temporary redirect cannot interleave.
        with contextlib.redirect_stdout(sys.stderr):
            try:
                return fn(*args, **kwargs)
            except VaultToolError as e:
                # ToolError's message is shown to the model; anything else is a crash.
                raise _ToolError(str(e)) from e

    @server.tool(annotations=ToolAnnotations(title="Remember", readOnlyHint=False, destructiveHint=False))
    async def remember(content: str, summary: str, tags: list[str] | None = None, classification: int = 1) -> dict:
        """Save a memory in the user's encrypted Memory Vault.

        Args:
            content: The full text to remember. Encrypted at rest.
            summary: One line describing what this memory is about. Stored UNENCRYPTED
                and used for search - describe the topic, never include secrets.
            tags: Optional keywords for search. Also stored unencrypted.
            classification: Sensitivity 0-5. 0 ephemeral (purged after a day), 1 working
                (default), 2 private, 3-4 sensitive (user approves each recall and the
                boundary daemon must be running), 5 secret (physical token; not
                recallable through this server).
        """
        return run(toolkit.remember, content, summary, tags, classification)

    @server.tool(annotations=ToolAnnotations(title="Search memories", readOnlyHint=True))
    async def search_memories(query: str, limit: int = 10) -> dict:
        """Search the Memory Vault by topic. Matches words in memory summaries and tags
        (memory content is encrypted and not searched). Returns memory IDs with their
        summaries, best match first; pass an ID to `recall` to read the content.
        """
        return run(toolkit.search_memories, query, limit)

    @server.tool(annotations=ToolAnnotations(title="List memories", readOnlyHint=True))
    async def list_memories(limit: int = 20) -> dict:
        """List the most recently stored memories (IDs, summaries, tags, classification)."""
        return run(toolkit.list_memories, limit)

    @server.tool(annotations=ToolAnnotations(title="Recall memory", readOnlyHint=False, destructiveHint=False))
    async def recall(memory_id: str, justification: str, ctx: Context) -> dict:
        """Decrypt and return one memory's content.

        Every recall, allowed or denied, is recorded in a signed audit log together
        with your justification. Level 3-4 memories ask the user for approval first.

        Args:
            memory_id: ID from `search_memories`, `list_memories` or `remember`.
            justification: Why this memory is needed right now (shown to the user).
        """
        prompt = run(toolkit.approval_prompt, memory_id, justification)
        approved = False
        if prompt is not None:
            try:
                answer = await ctx.elicit(prompt, RecallApproval)
            except Exception:  # noqa: BLE001 - client cannot ask the user: fall through and fail closed
                answer = None
            data = getattr(answer, "data", None)
            approved = getattr(answer, "action", None) == "accept" and bool(getattr(data, "approve", False))
        return run(toolkit.recall, memory_id, justification, approved)

    @server.tool(annotations=ToolAnnotations(title="Forget memory", readOnlyHint=False, destructiveHint=True))
    async def forget(memory_id: str, reason: str) -> dict:
        """Permanently retire a memory (wrong, outdated, or the user asked to forget it).
        It can no longer be recalled; its audit trail is kept. Cannot be undone.
        """
        return run(toolkit.forget, memory_id, reason)

    @server.tool(annotations=ToolAnnotations(title="Vault status", readOnlyHint=True))
    async def vault_status() -> dict:
        """Show how many memories the vault holds per classification level and whether it is locked down."""
        return run(toolkit.status)

    return server


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="memory-vault-mcp",
        description="Serve Memory Vault to AI clients over the Model Context Protocol (stdio).",
        epilog=__doc__.split("Configuration is by environment variable:")[1].split("The tool logic")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--check", action="store_true", help="validate configuration, print vault status, and exit")
    args = parser.parse_args(argv)

    if _Server is None and not args.check:
        print('The MCP SDK is not installed. Install it with: pip install "memory-vault[mcp]"', file=sys.stderr)
        return 1

    try:
        with contextlib.redirect_stdout(sys.stderr):
            toolkit = VaultToolkit.from_env()
            status = toolkit.status()
    except (VaultToolError, MemoryVaultError, ValueError, OSError) as e:
        print(f"memory-vault-mcp: {e}", file=sys.stderr)
        return 1

    summary = (
        f"memory-vault-mcp: profile '{status['profile']}' ({status['key_source']}), "
        f"{status['memory_count']} memories, database {status['database']}"
    )
    print(summary, file=sys.stderr)
    if args.check:
        return 0

    build_server(toolkit).run("stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
