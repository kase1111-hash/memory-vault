"""
Tests for the MCP server: the framework-neutral VaultToolkit, and a real
client <-> server session over stdio using the MCP SDK.
"""

import asyncio
import builtins
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mcp_server
import vault as vault_module
from mcp_server import VaultToolError, VaultToolkit

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def toolkit(temp_vault_dir, monkeypatch):
    """Toolkit on an isolated vault using the zero-config keyfile profile."""

    def refuse(*args, **kwargs):
        raise AssertionError("toolkit tried to prompt on the terminal")

    monkeypatch.setattr(builtins, "input", refuse)
    monkeypatch.setattr(vault_module.getpass, "getpass", refuse)
    return VaultToolkit(db_path=str(temp_vault_dir / ".memory_vault" / "vault.db"))


class TestToolkit:
    def test_remember_search_recall(self, toolkit):
        saved = toolkit.remember("Prefers dark mode and vim keys", "Editor preferences", tags=["ui"])
        assert saved["summary"] == "Editor preferences" and saved["tags"] == ["ui"]
        assert saved["classification"] == 1

        found = toolkit.search_memories("what editor does the user prefer?")["memories"]
        assert [m["memory_id"] for m in found] == [saved["memory_id"]]
        assert "content" not in found[0]

        recalled = toolkit.recall(saved["memory_id"], "configuring the editor")
        assert recalled["content"] == "Prefers dark mode and vim keys"

    def test_content_is_encrypted_at_rest(self, toolkit):
        toolkit.remember("the launch code is 0000", "Launch code")
        toolkit.vault.close()
        with open(toolkit.vault.db_path, "rb") as f:
            raw = f.read()
        assert b"launch code is 0000" not in raw
        assert b"Launch code" in raw  # the summary is the (documented) plaintext index

    def test_memories_survive_restart(self, toolkit):
        saved = toolkit.remember("persisted", "Persistence check")
        db_path = toolkit.vault.db_path
        toolkit.vault.close()
        again = VaultToolkit(db_path=db_path)
        assert again.recall(saved["memory_id"], "restart check")["content"] == "persisted"

    def test_recall_is_audited_with_justification(self, toolkit):
        saved = toolkit.remember("x", "Audit check")
        toolkit.recall(saved["memory_id"], "testing the audit trail")
        row = toolkit.vault.conn.execute(
            "SELECT requester, approved, justification FROM recall_log WHERE memory_id = ?", (saved["memory_id"],)
        ).fetchone()
        assert row == ("mcp-agent", 1, "testing the audit trail")
        assert toolkit.vault.verify_integrity() is True

    def test_recall_requires_justification(self, toolkit):
        saved = toolkit.remember("x", "y")
        with pytest.raises(VaultToolError, match="justification"):
            toolkit.recall(saved["memory_id"], "  ")

    def test_unknown_memory(self, toolkit):
        with pytest.raises(VaultToolError, match="not found"):
            toolkit.recall("does-not-exist", "why")

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"content": "", "summary": "s"},
            {"content": "c", "summary": " "},
            {"content": "c", "summary": "s", "classification": 6},
            {"content": "c", "summary": "s", "classification": -1},
            {"content": "c", "summary": "s", "classification": True},
            {"content": "x" * (mcp_server.MAX_CONTENT_BYTES + 1), "summary": "s"},
        ],
    )
    def test_remember_validates_input(self, toolkit, kwargs):
        with pytest.raises(VaultToolError):
            toolkit.remember(**kwargs)
        assert toolkit.list_memories()["memories"] == []

    def test_level3_needs_human_approval(self, toolkit):
        saved = toolkit.remember("sk-123", "Billing API key", classification=3)
        prompt = toolkit.approval_prompt(saved["memory_id"], "calling the billing API")
        assert "Billing API key" in prompt and "calling the billing API" in prompt
        assert "sk-123" not in prompt

        with pytest.raises(VaultToolError, match="approval"):
            toolkit.recall(saved["memory_id"], "calling the billing API")
        assert toolkit.recall(saved["memory_id"], "calling the billing API", human_approved=True)["content"] == "sk-123"

    def test_approval_does_not_carry_over_to_the_next_call(self, toolkit):
        saved = toolkit.remember("sk-123", "Billing API key", classification=3)
        toolkit.recall(saved["memory_id"], "first", human_approved=True)
        with pytest.raises(VaultToolError):
            toolkit.recall(saved["memory_id"], "second")

    def test_low_levels_need_no_approval(self, toolkit):
        saved = toolkit.remember("x", "y", classification=2)
        assert toolkit.approval_prompt(saved["memory_id"]) is None

    def test_level3_without_boundary_daemon_fails_closed(self, toolkit, monkeypatch):
        """Outside testing mode Level 3+ also needs the boundary daemon, which is not running."""
        monkeypatch.delenv("MEMORY_VAULT_TESTING")
        monkeypatch.setattr(mcp_server, "check_recall", lambda level: (False, "daemon unreachable"))
        monkeypatch.setattr(vault_module, "check_recall", lambda level: (False, "daemon unreachable"))
        saved = toolkit.remember("sk-123", "Billing API key", classification=3)
        assert toolkit.approval_prompt(saved["memory_id"]) is None  # nothing to ask the human
        with pytest.raises(VaultToolError, match="daemon unreachable"):
            toolkit.recall(saved["memory_id"], "why", human_approved=True)

    def test_level5_is_never_recallable(self, toolkit):
        saved = toolkit.remember("root password", "Root credential", classification=5)
        with pytest.raises(VaultToolError, match="physical token"):
            toolkit.approval_prompt(saved["memory_id"])
        with pytest.raises(VaultToolError, match="physical token"):
            toolkit.recall(saved["memory_id"], "why", human_approved=True)

    def test_forget(self, toolkit):
        saved = toolkit.remember("wrong fact", "Outdated")
        assert toolkit.forget(saved["memory_id"], "user corrected it")["forgotten"] is True
        assert toolkit.search_memories("outdated")["memories"] == []
        with pytest.raises(VaultToolError, match="TOMBSTONED"):
            toolkit.recall(saved["memory_id"], "why")
        assert toolkit.forget(saved["memory_id"], "again")["note"] == "already forgotten"

    def test_agent_cannot_forget_sensitive_memories(self, toolkit):
        saved = toolkit.remember("sk-123", "Billing API key", classification=3)
        with pytest.raises(VaultToolError, match="owner"):
            toolkit.forget(saved["memory_id"], "cleanup")
        assert toolkit.vault.get_memory_info(saved["memory_id"])["tombstoned"] is False

    def test_lockdown_blocks_recall(self, toolkit):
        saved = toolkit.remember("x", "y")
        toolkit.vault.enable_lockdown("incident")
        assert toolkit.status()["lockdown"] is True
        with pytest.raises(VaultToolError, match="LOCKDOWN"):
            toolkit.recall(saved["memory_id"], "why")

    def test_status(self, toolkit):
        toolkit.remember("a", "one")
        toolkit.remember("b", "two", classification=2)
        status = toolkit.status()
        assert status["memory_count"] == 2
        assert status["by_classification"] == {"1": 1, "2": 1}
        assert status["profile"] == "mcp-agent" and status["key_source"] == "KeyFile"


class TestConfiguration:
    def test_existing_keyfile_is_reused_not_replaced(self, temp_vault_dir):
        """A second database must not regenerate (and so destroy) the shared key."""
        first = VaultToolkit(db_path=str(temp_vault_dir / "a.db"))
        saved = first.remember("in the first vault", "First")
        keyfile = temp_vault_dir / ".memory_vault" / "keys" / "mcp-agent.key"
        key = keyfile.read_bytes()

        VaultToolkit(db_path=str(temp_vault_dir / "b.db")).remember("in the second", "Second")
        assert keyfile.read_bytes() == key
        assert first.recall(saved["memory_id"], "still readable")["content"] == "in the first vault"

    def test_missing_keyfile_is_reported_not_regenerated(self, temp_vault_dir):
        db_path = str(temp_vault_dir / "a.db")
        VaultToolkit(db_path=db_path).remember("x", "y")
        (temp_vault_dir / ".memory_vault" / "keys" / "mcp-agent.key").unlink()
        with pytest.raises(VaultToolError, match="missing"):
            VaultToolkit(db_path=db_path)

    def test_passphrase_profile_from_env(self, temp_vault_dir):
        secret = temp_vault_dir / "pass.txt"
        secret.write_text("file passphrase\n")
        env = {"MEMORY_VAULT_DB": str(temp_vault_dir / "a.db"), "MEMORY_VAULT_PASSPHRASE_FILE": str(secret)}

        toolkit = VaultToolkit.from_env(env)
        assert toolkit.profile == "default-passphrase" and toolkit.key_source == "HumanPassphrase"
        saved = toolkit.remember("passphrase protected", "Passphrase check")
        toolkit.vault.close()

        again = VaultToolkit.from_env(env)
        assert again.recall(saved["memory_id"], "check")["content"] == "passphrase protected"

    def test_passphrase_profile_without_passphrase_is_a_clear_error(self, temp_vault_dir):
        env = {"MEMORY_VAULT_DB": str(temp_vault_dir / "a.db"), "MEMORY_VAULT_PROFILE": "default-passphrase"}
        with pytest.raises(VaultToolError, match="MEMORY_VAULT_PASSPHRASE"):
            VaultToolkit.from_env(env)

    def test_check_flag_reports_status_on_stderr_only(self, temp_vault_dir, monkeypatch, capsys):
        monkeypatch.setenv("MEMORY_VAULT_DB", str(temp_vault_dir / "a.db"))
        assert mcp_server.main(["--check"]) == 0
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "profile 'mcp-agent'" in captured.err


# ---------------------------------------------------------------------------
# Real protocol session
# ---------------------------------------------------------------------------


def _text(result):
    return result.content[0].text


def _is_error(result):
    return result.is_error if hasattr(result, "is_error") else result.isError


async def _session_script(home, approve):
    from mcp import ClientSession, StdioServerParameters, stdio_client
    import mcp.types as types

    asked = []

    async def on_elicit(context, params):
        asked.append(params.message)
        return types.ElicitResult(action="accept", content={"approve": approve})

    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), MEMORY_VAULT_TESTING="1")
    for name in ("MEMORY_VAULT_DB", "MEMORY_VAULT_PROFILE", "MEMORY_VAULT_PASSPHRASE", "MEMORY_VAULT_PASSPHRASE_FILE"):
        env.pop(name, None)
    params = StdioServerParameters(command=sys.executable, args=[os.path.join(REPO_ROOT, "mcp_server.py")], env=env)

    out = {}
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write, elicitation_callback=on_elicit) as session:
            init = await session.initialize()
            out["instructions"] = init.instructions
            out["tools"] = {t.name: t for t in (await session.list_tools()).tools}

            saved = await session.call_tool(
                "remember", {"content": "Prefers dark mode", "summary": "UI preferences", "tags": ["ui"]}
            )
            out["saved"] = json.loads(_text(saved))
            found = await session.call_tool("search_memories", {"query": "ui preferences?"})
            out["found"] = json.loads(_text(found))
            recalled = await session.call_tool(
                "recall", {"memory_id": out["saved"]["memory_id"], "justification": "theming"}
            )
            out["recalled"] = json.loads(_text(recalled))

            sealed = await session.call_tool(
                "remember", {"content": "sk-123", "summary": "Billing key", "classification": 3}
            )
            sealed_id = json.loads(_text(sealed))["memory_id"]
            out["sealed"] = await session.call_tool("recall", {"memory_id": sealed_id, "justification": "billing"})

            out["missing"] = await session.call_tool("recall", {"memory_id": "nope", "justification": "x"})
            out["forgot"] = json.loads(
                _text(await session.call_tool("forget", {"memory_id": out["saved"]["memory_id"], "reason": "test"}))
            )
            out["status"] = json.loads(_text(await session.call_tool("vault_status", {})))
    out["asked"] = asked
    return out


@pytest.fixture(scope="module")
def approved(tmp_path_factory):
    """One full client session in which the human approves the Level 3 recall."""
    pytest.importorskip("mcp")
    return asyncio.run(_session_script(tmp_path_factory.mktemp("home"), approve=True))


@pytest.mark.skipif(sys.platform == "win32", reason="stdio session test uses POSIX home-directory isolation")
class TestProtocolSession:
    """Drive the real server process with the MCP SDK's client.

    This is what catches protocol-level breakage, e.g. the vault library printing
    to stdout and corrupting the JSON-RPC stream.
    """

    def test_advertises_tools_and_instructions(self, approved):
        assert set(approved["tools"]) == {
            "remember",
            "search_memories",
            "list_memories",
            "recall",
            "forget",
            "vault_status",
        }
        assert "UNENCRYPTED" in approved["instructions"]
        recall_schema = (
            approved["tools"]["recall"].inputSchema
            if hasattr(approved["tools"]["recall"], "inputSchema")
            else approved["tools"]["recall"].input_schema
        )
        assert set(recall_schema["required"]) == {"memory_id", "justification"}
        assert "ctx" not in recall_schema["properties"]

    def test_remember_search_recall_roundtrip(self, approved):
        assert approved["found"]["memories"][0]["memory_id"] == approved["saved"]["memory_id"]
        assert approved["recalled"]["content"] == "Prefers dark mode"

    def test_level3_recall_asks_the_human(self, approved):
        assert len(approved["asked"]) == 1
        assert "Billing key" in approved["asked"][0] and "sk-123" not in approved["asked"][0]
        assert not _is_error(approved["sealed"])
        assert json.loads(_text(approved["sealed"]))["content"] == "sk-123"

    def test_errors_reach_the_model_with_a_reason(self, approved):
        assert _is_error(approved["missing"])
        assert "not found" in _text(approved["missing"])

    def test_forget_and_status(self, approved):
        assert approved["forgot"]["forgotten"] is True
        assert approved["status"]["memory_count"] == 1

    def test_level3_recall_denied_when_human_declines(self, tmp_path):
        pytest.importorskip("mcp")
        declined = asyncio.run(_session_script(tmp_path, approve=False))
        assert len(declined["asked"]) == 1
        assert _is_error(declined["sealed"])
        assert "sk-123" not in _text(declined["sealed"])
