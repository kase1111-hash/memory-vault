"""
Tests for agent_os.py - Agent-OS governance integration.

Tests data structures, constitution management, governance logging,
and boundary daemon error handling.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from agent_os import (
    OperationalMode,
    AgentRole,
    AgentIdentity,
    GovernanceDecision,
    BoundaryDaemon,
    ConstitutionManager,
    GovernanceLogger,
)


class TestOperationalMode:
    """Test OperationalMode enum."""

    def test_all_modes(self):
        assert OperationalMode.ONLINE.value == "online"
        assert OperationalMode.OFFLINE.value == "offline"
        assert OperationalMode.AIRGAP.value == "airgap"
        assert OperationalMode.COLDROOM.value == "coldroom"
        assert OperationalMode.MAINTENANCE.value == "maintenance"


class TestAgentRole:
    """Test AgentRole enum."""

    def test_all_roles(self):
        assert AgentRole.ORCHESTRATOR.value == "orchestrator"
        assert AgentRole.WORKER.value == "worker"
        assert AgentRole.GUARDIAN.value == "guardian"
        assert AgentRole.AUDITOR.value == "auditor"
        assert AgentRole.SPECIALIST.value == "specialist"
        assert AgentRole.MEMORY_VAULT.value == "memory_vault"


class TestAgentIdentity:
    """Test AgentIdentity dataclass."""

    def test_creation(self):
        identity = AgentIdentity(
            agent_id="agent-001",
            role=AgentRole.MEMORY_VAULT,
            name="Test Vault",
            permissions=["memory:read", "memory:write"],
        )
        assert identity.agent_id == "agent-001"
        assert identity.role == AgentRole.MEMORY_VAULT
        assert len(identity.permissions) == 2

    def test_to_dict(self):
        identity = AgentIdentity(
            agent_id="a1",
            role=AgentRole.WORKER,
            name="Worker",
        )
        d = identity.to_dict()
        assert d["agent_id"] == "a1"
        assert d["role"] == "worker"
        assert d["name"] == "Worker"
        assert d["permissions"] == []

    def test_defaults(self):
        identity = AgentIdentity(
            agent_id="a1", role=AgentRole.AUDITOR, name="Aud"
        )
        assert identity.permissions == []
        assert identity.constitution_hash == ""
        assert identity.created_at == ""
        assert identity.last_seen == ""


class TestGovernanceDecision:
    """Test GovernanceDecision dataclass."""

    def test_creation(self):
        decision = GovernanceDecision(
            decision_id="d-001",
            timestamp="2025-01-15T10:00:00Z",
            agent_id="agent-001",
            action="recall",
            resource="mem-001",
            outcome="approved",
            reason="Classification allows",
        )
        assert decision.outcome == "approved"

    def test_to_dict(self):
        decision = GovernanceDecision(
            decision_id="d1", timestamp="now", agent_id="a1",
            action="store", resource="r1", outcome="denied",
            reason="test", constitution_ref="ref1",
            human_override=True,
        )
        d = decision.to_dict()
        assert d["decision_id"] == "d1"
        assert d["human_override"] is True
        assert d["constitution_ref"] == "ref1"


class TestBoundaryDaemon:
    """Test BoundaryDaemon client without running daemon."""

    def test_default_initialization(self):
        daemon = BoundaryDaemon()
        assert daemon.socket_path  # Should have a default

    def test_custom_socket(self):
        daemon = BoundaryDaemon(socket_path="/tmp/custom.sock")
        assert daemon.socket_path == "/tmp/custom.sock"

    def test_check_recall_no_daemon(self):
        daemon = BoundaryDaemon(socket_path="/tmp/nonexistent_daemon.sock")
        permitted, reason = daemon.check_recall(memory_class=0)
        assert permitted is False
        assert reason  # Should have error message

    def test_get_mode_no_daemon(self):
        daemon = BoundaryDaemon(socket_path="/tmp/nonexistent_daemon.sock")
        mode = daemon.get_mode()
        assert mode == OperationalMode.OFFLINE  # Default fallback

    def test_get_status_no_daemon(self):
        daemon = BoundaryDaemon(socket_path="/tmp/nonexistent_daemon.sock")
        status = daemon.get_status()
        assert "error" in status
        assert status.get("permitted") is False

    def test_request_permission_no_daemon(self):
        daemon = BoundaryDaemon(socket_path="/tmp/nonexistent_daemon.sock")
        permitted, reason = daemon.request_permission(
            agent_id="test", action="recall",
            resource="mem-1", justification="test",
        )
        assert permitted is False

    def test_verify_agent_no_daemon(self):
        daemon = BoundaryDaemon(socket_path="/tmp/nonexistent_daemon.sock")
        valid, identity = daemon.verify_agent("agent-001")
        assert valid is False
        assert identity is None

    def test_is_human_present_no_daemon(self):
        daemon = BoundaryDaemon(socket_path="/tmp/nonexistent_daemon.sock")
        assert daemon.is_human_present() is False

    def test_require_human_approval_no_daemon(self):
        daemon = BoundaryDaemon(socket_path="/tmp/nonexistent_daemon.sock")
        approved, reason = daemon.require_human_approval("test", "details")
        assert approved is False


class TestConstitutionManager:
    """Test ConstitutionManager with temp directory."""

    @pytest.fixture
    def manager(self, tmp_path):
        return ConstitutionManager(constitution_dir=str(tmp_path / "constitutions"))

    def test_list_empty(self, manager):
        assert manager.list_constitutions() == []

    def test_load_nonexistent(self, manager):
        assert manager.load_constitution("nonexistent") is None

    def test_get_hash_nonexistent(self, manager):
        assert manager.get_constitution_hash("nonexistent") is None

    def test_write_and_load(self, manager):
        # Write a constitution file
        const_path = os.path.join(manager.constitution_dir, "test.md")
        with open(const_path, "w") as f:
            f.write("# Test Constitution\nRules go here.")

        content = manager.load_constitution("test")
        assert content is not None
        assert "Test Constitution" in content

    def test_list_constitutions(self, manager):
        for name in ["alpha", "beta"]:
            path = os.path.join(manager.constitution_dir, f"{name}.md")
            with open(path, "w") as f:
                f.write(f"# {name}")

        names = manager.list_constitutions()
        assert set(names) == {"alpha", "beta"}

    def test_get_hash(self, manager):
        path = os.path.join(manager.constitution_dir, "hash_test.md")
        with open(path, "w") as f:
            f.write("content for hashing")

        h = manager.get_constitution_hash("hash_test")
        assert h is not None
        assert len(h) == 64  # SHA256 hex

    def test_verify_constitution(self, manager):
        path = os.path.join(manager.constitution_dir, "verify.md")
        with open(path, "w") as f:
            f.write("verifiable content")

        correct_hash = manager.get_constitution_hash("verify")
        assert manager.verify_constitution("verify", correct_hash) is True
        assert manager.verify_constitution("verify", "wrong_hash") is False

    def test_get_memory_vault_constitution_default(self, manager):
        """When no file exists, returns default constitution."""
        content = manager.get_memory_vault_constitution()
        assert "Memory Vault Constitution" in content
        assert "Owner Sovereignty" in content
        assert "Level 5" in content


class TestGovernanceLogger:
    """Test GovernanceLogger with temp file."""

    @pytest.fixture
    def logger(self, tmp_path):
        return GovernanceLogger(log_path=str(tmp_path / "governance.log"))

    def test_log_decision(self, logger):
        decision = logger.log_decision(
            agent_id="agent-001",
            action="recall",
            resource="mem-001",
            outcome="approved",
            reason="Classification allows",
        )
        assert decision.decision_id
        assert decision.agent_id == "agent-001"
        assert decision.outcome == "approved"

    def test_log_creates_file(self, logger):
        logger.log_decision(
            agent_id="a1", action="store", resource="r1",
            outcome="approved", reason="ok",
        )
        assert os.path.exists(logger.log_path)

    def test_get_decisions(self, logger):
        for i in range(5):
            logger.log_decision(
                agent_id=f"agent-{i}",
                action="recall",
                resource=f"mem-{i}",
                outcome="approved" if i % 2 == 0 else "denied",
                reason=f"reason {i}",
            )

        decisions = logger.get_decisions()
        assert len(decisions) == 5

    def test_get_decisions_filter_agent(self, logger):
        logger.log_decision(
            agent_id="target", action="recall", resource="r1",
            outcome="approved", reason="ok",
        )
        logger.log_decision(
            agent_id="other", action="recall", resource="r2",
            outcome="denied", reason="no",
        )

        decisions = logger.get_decisions(agent_id="target")
        assert len(decisions) == 1
        assert decisions[0].agent_id == "target"

    def test_get_decisions_filter_action(self, logger):
        logger.log_decision(
            agent_id="a1", action="recall", resource="r1",
            outcome="ok", reason="ok",
        )
        logger.log_decision(
            agent_id="a1", action="store", resource="r2",
            outcome="ok", reason="ok",
        )

        decisions = logger.get_decisions(action="store")
        assert len(decisions) == 1
        assert decisions[0].action == "store"

    def test_get_decisions_limit(self, logger):
        for i in range(20):
            logger.log_decision(
                agent_id="a1", action="test", resource=f"r{i}",
                outcome="ok", reason="ok",
            )

        decisions = logger.get_decisions(limit=5)
        assert len(decisions) == 5

    def test_get_decisions_empty(self, logger):
        decisions = logger.get_decisions()
        assert decisions == []

    def test_log_with_constitution_ref(self, logger):
        decision = logger.log_decision(
            agent_id="a1", action="recall", resource="r1",
            outcome="denied", reason="policy",
            constitution_ref="memory_vault:level5",
            human_override=True,
        )
        assert decision.constitution_ref == "memory_vault:level5"
        assert decision.human_override is True
