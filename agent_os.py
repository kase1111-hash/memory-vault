# memory_vault/agent_os.py
"""
Agent-OS Governance Integration

This module provides deep integration with Agent-OS, the natural-language
native operating system for AI agents. It extends the basic boundary daemon
integration to include:

- Constitution-based access control
- Agent role verification
- Governance audit logging
- Permission boundary enforcement
- Human authority validation

Agent-OS Principles:
1. Governance through auditable natural language
2. Role-based agent specialization with clear permission boundaries
3. Ultimate human authority and control
4. Local-first architecture
5. Explicit consent requirements
6. Refusal as a valued system capability
7. Documented, amendable governance processes
"""

import socket
import json
import os
import hashlib
from datetime import datetime, timezone
from typing import Optional, List, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

# Standard Agent-OS paths (configurable via environment variables)
AGENT_OS_BASE = os.environ.get("AGENT_OS_BASE", os.path.expanduser("~/.agent-os"))
BOUNDARY_SOCKET = os.environ.get(
    "MEMORY_VAULT_BOUNDARY_SOCKET",
    os.path.join(AGENT_OS_BASE, "api", "boundary.sock")
)
CONSTITUTION_PATH = os.environ.get(
    "AGENT_OS_CONSTITUTION_PATH",
    os.path.join(AGENT_OS_BASE, "constitutions")
)
AGENT_REGISTRY = os.path.join(AGENT_OS_BASE, "agents.json")
GOVERNANCE_LOG = os.path.join(AGENT_OS_BASE, "governance.log")


class OperationalMode(Enum):
    """Agent-OS operational modes."""
    ONLINE = "online"
    OFFLINE = "offline"
    AIRGAP = "airgap"
    COLDROOM = "coldroom"
    MAINTENANCE = "maintenance"


class AgentRole(Enum):
    """Standard agent roles in Agent-OS."""
    ORCHESTRATOR = "orchestrator"
    WORKER = "worker"
    GUARDIAN = "guardian"
    AUDITOR = "auditor"
    SPECIALIST = "specialist"
    MEMORY_VAULT = "memory_vault"


@dataclass
class AgentIdentity:
    """Identity of an Agent-OS agent."""
    agent_id: str
    role: AgentRole
    name: str
    permissions: List[str] = field(default_factory=list)
    constitution_hash: str = ""
    created_at: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "name": self.name,
            "permissions": self.permissions,
            "constitution_hash": self.constitution_hash,
            "created_at": self.created_at,
            "last_seen": self.last_seen
        }


@dataclass
class GovernanceDecision:
    """Record of a governance decision."""
    decision_id: str
    timestamp: str
    agent_id: str
    action: str
    resource: str
    outcome: str  # "approved", "denied", "referred"
    reason: str
    constitution_ref: str = ""
    human_override: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


# ==================== Boundary Daemon Client (Extended) ====================

class BoundaryDaemon:
    """
    Extended client for the Agent-OS boundary daemon.

    Provides environmental security enforcement and governance queries.
    """

    def __init__(self, socket_path: str = None):
        self.socket_path = socket_path or BOUNDARY_SOCKET
        self._connected = False

    def _send_request(self, request: dict) -> dict:
        """Send request to boundary daemon and receive response."""
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect(self.socket_path)
                s.sendall(json.dumps(request).encode('utf-8') + b'\n')
                response_data = s.recv(8192).decode('utf-8')
                return json.loads(response_data)
        except FileNotFoundError:
            return {"error": "boundary_socket_not_found", "permitted": False}
        except ConnectionRefusedError:
            return {"error": "boundary_daemon_not_running", "permitted": False}
        except socket.timeout:
            return {"error": "boundary_timeout", "permitted": False}
        except Exception as e:
            return {"error": str(e), "permitted": False}

    def check_recall(self, memory_class: int) -> Tuple[bool, str]:
        """Check if memory recall is permitted for given classification."""
        response = self._send_request({
            "command": "check_recall",
            "params": {"memory_class": memory_class}
        })
        permitted = response.get("permitted", False)
        reason = response.get("reason", response.get("error", "Unknown"))
        return permitted, reason

    def get_mode(self) -> OperationalMode:
        """Get current operational mode."""
        response = self._send_request({"command": "get_mode"})
        mode_str = response.get("mode", "offline")
        try:
            return OperationalMode(mode_str.lower())
        except ValueError:
            return OperationalMode.OFFLINE

    def get_status(self) -> dict:
        """Get full boundary daemon status."""
        return self._send_request({"command": "status"})

    def request_permission(
        self,
        agent_id: str,
        action: str,
        resource: str,
        justification: str
    ) -> Tuple[bool, str]:
        """
        Request permission for an action from the boundary daemon.

        Args:
            agent_id: ID of requesting agent
            action: Action to perform
            resource: Resource being accessed
            justification: Reason for the request

        Returns:
            (permitted, reason) tuple
        """
        response = self._send_request({
            "command": "request_permission",
            "params": {
                "agent_id": agent_id,
                "action": action,
                "resource": resource,
                "justification": justification
            }
        })
        permitted = response.get("permitted", False)
        reason = response.get("reason", response.get("error", "Unknown"))
        return permitted, reason

    def verify_agent(self, agent_id: str) -> Tuple[bool, Optional[AgentIdentity]]:
        """
        Verify an agent's identity with the boundary daemon.

        Returns:
            (valid, identity) tuple
        """
        response = self._send_request({
            "command": "verify_agent",
            "params": {"agent_id": agent_id}
        })

        if response.get("valid"):
            identity = AgentIdentity(
                agent_id=agent_id,
                role=AgentRole(response.get("role", "worker")),
                name=response.get("name", "unknown"),
                permissions=response.get("permissions", []),
                constitution_hash=response.get("constitution_hash", ""),
                last_seen=datetime.now(timezone.utc).isoformat() + "Z"
            )
            return True, identity

        return False, None

    def is_human_present(self) -> bool:
        """Check if human operator is present."""
        response = self._send_request({"command": "human_presence"})
        return response.get("present", False)

    def require_human_approval(self, action: str, details: str) -> Tuple[bool, str]:
        """
        Request explicit human approval for an action.

        This blocks until human responds or timeout.
        """
        response = self._send_request({
            "command": "require_human_approval",
            "params": {
                "action": action,
                "details": details
            }
        })
        approved = response.get("approved", False)
        reason = response.get("reason", "No response")
        return approved, reason


# ==================== Constitution Management ====================

class ConstitutionManager:
    """
    Manages Agent-OS constitutions - natural language documents
    that define agent behavior and boundaries.
    """

    def __init__(self, constitution_dir: str = None):
        self.constitution_dir = constitution_dir or CONSTITUTION_PATH
        os.makedirs(self.constitution_dir, exist_ok=True)

    def load_constitution(self, name: str) -> Optional[str]:
        """Load a constitution by name."""
        path = os.path.join(self.constitution_dir, f"{name}.md")
        if os.path.exists(path):
            with open(path) as f:
                return f.read()
        return None

    def get_constitution_hash(self, name: str) -> Optional[str]:
        """Get SHA-256 hash of a constitution."""
        content = self.load_constitution(name)
        if content:
            return hashlib.sha256(content.encode()).hexdigest()
        return None

    def list_constitutions(self) -> List[str]:
        """List available constitutions."""
        if not os.path.exists(self.constitution_dir):
            return []
        return [
            f[:-3] for f in os.listdir(self.constitution_dir)
            if f.endswith(".md")
        ]

    def verify_constitution(self, name: str, expected_hash: str) -> bool:
        """Verify constitution hasn't been tampered with."""
        actual_hash = self.get_constitution_hash(name)
        return actual_hash == expected_hash

    def get_memory_vault_constitution(self) -> str:
        """Get the Memory Vault's governing constitution."""
        constitution = self.load_constitution("memory_vault")
        if constitution:
            return constitution

        # Return default constitution
        return """# Memory Vault Constitution

## Purpose
The Memory Vault serves as the secure, owner-sovereign storage for high-value
cognitive artifacts. Its role is to protect memories with confidentiality,
integrity, provenance, and controlled recall guarantees.

## Core Principles

1. **Owner Sovereignty** - The human owner is the final authority on all matters.

2. **Least Recall** - Memories are not recalled unless explicitly permitted.
   Every recall must have a justified reason.

3. **Classification First** - Security policy is bound at write-time and immutable.

4. **Offline First** - No network dependency for safety-critical operations.

5. **Auditability Without Exposure** - Proof of integrity without revealing content.

## Permissions

### Level 0-2 (Ephemeral, Working, Private)
- Agents may recall without human approval
- Boundary daemon check required

### Level 3 (Sealed)
- Human approval required for each recall
- Cooldown enforcement active
- Offline mode preferred

### Level 4 (Vaulted)
- Human approval required
- Airgap mode required
- Boundary daemon must report safe state

### Level 5 (Black)
- All Level 4 requirements
- Physical token required
- Coldroom mode required

## Governance

All governance decisions are logged and auditable.
This constitution may be amended only with explicit human approval
and a 48-hour cooling off period.

## Refusal Rights

The Memory Vault may refuse any request that:
- Violates classification requirements
- Lacks proper justification
- Occurs during lockdown
- Fails boundary checks
- Comes from unverified agents
"""


# ==================== Governance Logger ====================

class GovernanceLogger:
    """
    Logs all governance decisions for audit purposes.

    All actions that involve access control, permissions,
    or policy enforcement are logged here.
    """

    def __init__(self, log_path: str = None):
        self.log_path = log_path or GOVERNANCE_LOG
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def log_decision(
        self,
        agent_id: str,
        action: str,
        resource: str,
        outcome: str,
        reason: str,
        constitution_ref: str = "",
        human_override: bool = False
    ) -> GovernanceDecision:
        """Log a governance decision."""
        import uuid

        decision = GovernanceDecision(
            decision_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat() + "Z",
            agent_id=agent_id,
            action=action,
            resource=resource,
            outcome=outcome,
            reason=reason,
            constitution_ref=constitution_ref,
            human_override=human_override
        )

        # Append to log file
        with open(self.log_path, "a") as f:
            f.write(json.dumps(decision.to_dict()) + "\n")

        return decision

    def get_decisions(
        self,
        agent_id: str = None,
        action: str = None,
        limit: int = 100
    ) -> List[GovernanceDecision]:
        """Query governance decisions."""
        if not os.path.exists(self.log_path):
            return []

        decisions = []
        with open(self.log_path) as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    if agent_id and data.get("agent_id") != agent_id:
                        continue
                    if action and data.get("action") != action:
                        continue
                    decisions.append(GovernanceDecision(**data))
                except (json.JSONDecodeError, TypeError):
                    continue

        return decisions[-limit:]


# ==================== Agent-OS Integration Functions ====================

def check_agent_permission(
    agent_id: str,
    action: str,
    resource: str,
    classification: int = 0
) -> Tuple[bool, str]:
    """
    Check if an agent has permission for an action.

    This integrates with the boundary daemon and constitution.

    Args:
        agent_id: ID of the requesting agent
        action: Action to perform (e.g., "recall", "store", "delete")
        resource: Resource being accessed (e.g., memory_id)
        classification: Classification level of the resource

    Returns:
        (permitted, reason) tuple
    """
    daemon = BoundaryDaemon()
    logger = GovernanceLogger()
    _constitution = ConstitutionManager()

    # Verify agent identity
    valid, identity = daemon.verify_agent(agent_id)
    if not valid:
        _decision = logger.log_decision(
            agent_id=agent_id,
            action=action,
            resource=resource,
            outcome="denied",
            reason="Agent identity verification failed"
        )
        return False, "Agent identity not verified"

    # Check boundary status
    mode = daemon.get_mode()

    # Classification-based mode requirements
    if classification >= 5 and mode != OperationalMode.COLDROOM:
        _decision = logger.log_decision(
            agent_id=agent_id,
            action=action,
            resource=resource,
            outcome="denied",
            reason=f"Level 5 requires COLDROOM mode, current: {mode.value}",
            constitution_ref="memory_vault:level5"
        )
        return False, f"Level 5 requires COLDROOM mode (current: {mode.value})"

    if classification >= 4 and mode not in [OperationalMode.AIRGAP, OperationalMode.COLDROOM]:
        _decision = logger.log_decision(
            agent_id=agent_id,
            action=action,
            resource=resource,
            outcome="denied",
            reason=f"Level 4 requires AIRGAP mode, current: {mode.value}",
            constitution_ref="memory_vault:level4"
        )
        return False, f"Level 4 requires AIRGAP mode (current: {mode.value})"

    # Request permission from boundary daemon
    permitted, reason = daemon.request_permission(
        agent_id=agent_id,
        action=action,
        resource=resource,
        justification=f"Memory Vault {action} on classification {classification} resource"
    )

    logger.log_decision(
        agent_id=agent_id,
        action=action,
        resource=resource,
        outcome="approved" if permitted else "denied",
        reason=reason,
        constitution_ref="memory_vault:permission_check"
    )

    return permitted, reason


def require_human_authority(
    action: str,
    details: str,
    timeout_seconds: int = 300
) -> Tuple[bool, str]:
    """
    Require explicit human authority for an action.

    This is for critical operations that must have human approval.
    Implements Agent-OS principle: "Ultimate human authority and control"

    Args:
        action: Description of the action
        details: Detailed explanation
        timeout_seconds: How long to wait for human response

    Returns:
        (approved, reason) tuple
    """
    daemon = BoundaryDaemon()
    logger = GovernanceLogger()

    # First check if human is present
    if not daemon.is_human_present():
        logger.log_decision(
            agent_id="memory_vault",
            action=action,
            resource="human_authority",
            outcome="denied",
            reason="No human presence detected",
            constitution_ref="memory_vault:human_authority"
        )
        return False, "No human presence detected"

    # Request approval
    approved, reason = daemon.require_human_approval(action, details)

    logger.log_decision(
        agent_id="memory_vault",
        action=action,
        resource="human_authority",
        outcome="approved" if approved else "denied",
        reason=reason,
        constitution_ref="memory_vault:human_authority",
        human_override=approved
    )

    return approved, reason


def get_governance_summary() -> dict:
    """Get a summary of recent governance activity."""
    logger = GovernanceLogger()
    decisions = logger.get_decisions(limit=1000)

    approved = len([d for d in decisions if d.outcome == "approved"])
    denied = len([d for d in decisions if d.outcome == "denied"])
    human_overrides = len([d for d in decisions if d.human_override])

    # Group by action
    action_counts = {}
    for d in decisions:
        action_counts[d.action] = action_counts.get(d.action, 0) + 1

    return {
        "total_decisions": len(decisions),
        "approved": approved,
        "denied": denied,
        "human_overrides": human_overrides,
        "approval_rate": approved / len(decisions) if decisions else 0,
        "by_action": action_counts
    }


def verify_vault_constitution() -> Tuple[bool, str]:
    """
    Verify the Memory Vault's constitution is intact.

    Returns:
        (valid, message) tuple
    """
    manager = ConstitutionManager()
    daemon = BoundaryDaemon()

    # Get expected hash from daemon/registry
    status = daemon.get_status()
    expected_hash = status.get("memory_vault_constitution_hash")

    if not expected_hash:
        # No registered hash, constitution is self-sovereign
        return True, "Constitution is self-sovereign (no external verification)"

    actual_hash = manager.get_constitution_hash("memory_vault")
    if not actual_hash:
        return False, "Constitution file not found"

    if actual_hash == expected_hash:
        return True, "Constitution verified"
    else:
        return False, f"Constitution hash mismatch (expected: {expected_hash[:16]}..., got: {actual_hash[:16]}...)"


def register_memory_vault_agent() -> Optional[AgentIdentity]:
    """
    Register the Memory Vault as an agent with Agent-OS.

    Returns the assigned identity if successful.
    """
    import uuid

    daemon = BoundaryDaemon()
    constitution = ConstitutionManager()

    identity = AgentIdentity(
        agent_id=f"memory_vault_{uuid.uuid4().hex[:8]}",
        role=AgentRole.MEMORY_VAULT,
        name="Memory Vault",
        permissions=[
            "memory:read",
            "memory:write",
            "memory:delete",
            "audit:read",
            "audit:write",
            "governance:log"
        ],
        constitution_hash=constitution.get_constitution_hash("memory_vault") or "",
        created_at=datetime.now(timezone.utc).isoformat() + "Z"
    )

    # Register with daemon
    response = daemon._send_request({
        "command": "register_agent",
        "params": identity.to_dict()
    })

    if response.get("registered"):
        print(f"Memory Vault registered with Agent-OS: {identity.agent_id}")
        return identity

    print(f"Warning: Could not register with Agent-OS: {response.get('error', 'Unknown error')}")
    return None
