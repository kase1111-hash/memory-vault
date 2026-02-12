"""
Boundary Daemon Client for Memory Vault.

Provides connection protection and operational mode enforcement via
the boundary-daemon Unix socket protocol.
"""

import socket
import json
import os
import logging
import threading
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum

from errors import (
    BoundaryConnectionError,
    BoundaryDeniedError,
    BoundaryTimeoutError,
    BoundaryError,
)


logger = logging.getLogger(__name__)

# Socket path is configurable via environment variable, defaults to standard Agent-OS path
SOCKET_PATH = os.environ.get(
    "MEMORY_VAULT_BOUNDARY_SOCKET",
    os.path.expanduser("~/.agent-os/api/boundary.sock")
)
DEFAULT_TIMEOUT = 5.0
MAX_RESPONSE_SIZE = 65536


class OperationalMode(Enum):
    """Operational modes supported by boundary-daemon."""
    ONLINE = "online"          # Full network access
    OFFLINE = "offline"        # No external network
    AIRGAP = "airgap"          # Complete isolation
    COLDROOM = "coldroom"      # Minimal operations only


@dataclass
class BoundaryStatus:
    """Current boundary daemon status."""
    connected: bool
    operational_mode: Optional[OperationalMode]
    restrictions: Dict[str, Any]
    last_check: Optional[float] = None


class BoundaryClient:
    """Client for boundary-daemon connection protection.

    Provides:
    - Recall permission checks
    - Operational mode queries
    - Connection protection enforcement
    - Automatic reconnection
    """

    def __init__(
        self,
        socket_path: str = SOCKET_PATH,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        """Initialize boundary client.

        Args:
            socket_path: Path to boundary-daemon Unix socket
            timeout: Socket timeout in seconds
        """
        self.socket_path = socket_path
        self.timeout = timeout
        self._lock = threading.Lock()
        self._status_cache: Optional[BoundaryStatus] = None

    def _send_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Send request to boundary-daemon and get response.

        Args:
            request: Request dictionary with command and params

        Returns:
            Response dictionary from daemon

        Raises:
            BoundaryConnectionError: Cannot connect to daemon
            BoundaryTimeoutError: Daemon did not respond in time
            BoundaryError: Other communication errors
        """
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect(self.socket_path)
                s.sendall(json.dumps(request).encode('utf-8') + b'\n')

                # Read response (may be fragmented)
                chunks = []
                total_size = 0
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total_size += len(chunk)
                    if total_size > MAX_RESPONSE_SIZE:
                        raise BoundaryError(
                            "Response too large from boundary daemon"
                        )
                    # Check for complete JSON
                    try:
                        data = b''.join(chunks).decode('utf-8')
                        return json.loads(data)
                    except json.JSONDecodeError:
                        continue

                raise BoundaryError("Empty response from boundary daemon")

        except FileNotFoundError as e:
            raise BoundaryConnectionError(
                "Boundary daemon socket not found (offline/airgap mode?)",
                socket_path=self.socket_path
            ) from e
        except ConnectionRefusedError as e:
            raise BoundaryConnectionError(
                "Boundary daemon not running",
                socket_path=self.socket_path
            ) from e
        except socket.timeout as e:
            raise BoundaryTimeoutError(
                "Boundary daemon did not respond in time"
            ) from e
        except OSError as e:
            raise BoundaryConnectionError(
                f"Socket error: {e}",
                socket_path=self.socket_path
            ) from e

    def check_recall(
        self,
        memory_class: int,
        memory_id: str = None,
        requester: str = None,
        justification: str = None
    ) -> Tuple[bool, str]:
        """Query boundary-daemon for recall permission.

        Args:
            memory_class: Classification level of memory (0-5)
            memory_id: Optional memory identifier
            requester: Who is requesting recall
            justification: Why recall is needed

        Returns:
            Tuple of (permitted: bool, reason: str)

        Raises:
            BoundaryDeniedError: If recall is explicitly denied
            BoundaryConnectionError: Cannot connect to daemon
        """
        request = {
            "command": "check_recall",
            "params": {
                "memory_class": memory_class,
                "memory_id": memory_id,
                "requester": requester,
                "justification": justification
            }
        }

        try:
            response = self._send_request(request)
            permitted = response.get("permitted", False)
            reason = response.get("reason", "No reason provided")

            if not permitted:
                raise BoundaryDeniedError(
                    f"Recall denied by boundary daemon: {reason}",
                    operational_mode=response.get("operational_mode"),
                    reason=reason
                )

            return permitted, reason

        except (BoundaryConnectionError, BoundaryTimeoutError):
            raise

    def get_operational_mode(self) -> OperationalMode:
        """Query current operational mode from boundary-daemon.

        Returns:
            Current operational mode

        Raises:
            BoundaryConnectionError: Cannot connect to daemon
        """
        request = {
            "command": "get_mode",
            "params": {}
        }

        try:
            response = self._send_request(request)
            mode_str = response.get("mode", "offline")
            return OperationalMode(mode_str.lower())
        except ValueError:
            logger.warning(f"Unknown operational mode: {mode_str}")
            return OperationalMode.OFFLINE

    def get_status(self, force_refresh: bool = False) -> BoundaryStatus:
        """Get current boundary daemon status.

        Args:
            force_refresh: Force query even if cached

        Returns:
            BoundaryStatus with current state
        """
        import time

        if not force_refresh and self._status_cache:
            # Use cache if less than 5 seconds old
            if time.time() - (self._status_cache.last_check or 0) < 5:
                return self._status_cache

        try:
            request = {"command": "status", "params": {}}
            response = self._send_request(request)

            mode_str = response.get("operational_mode", "offline")
            try:
                mode = OperationalMode(mode_str.lower())
            except ValueError:
                mode = OperationalMode.OFFLINE

            self._status_cache = BoundaryStatus(
                connected=True,
                operational_mode=mode,
                restrictions=response.get("restrictions", {}),
                last_check=time.time()
            )

        except BoundaryConnectionError:
            self._status_cache = BoundaryStatus(
                connected=False,
                operational_mode=OperationalMode.AIRGAP,  # Assume airgap if can't connect
                restrictions={"all_network": False},
                last_check=time.time()
            )

        return self._status_cache

    def register_vault(
        self,
        vault_id: str,
        capabilities: Dict[str, Any] = None
    ) -> bool:
        """Register this vault instance with boundary-daemon.

        Allows boundary-daemon to track and protect vault connections.

        Args:
            vault_id: Unique identifier for this vault instance
            capabilities: Vault capabilities to advertise

        Returns:
            True if registration succeeded
        """
        request = {
            "command": "register_service",
            "params": {
                "service_type": "memory_vault",
                "service_id": vault_id,
                "capabilities": capabilities or {
                    "encryption": "XSalsa20-Poly1305",
                    "classification_levels": 6,
                    "merkle_audit": True,
                    "hardware_binding": True
                }
            }
        }

        try:
            response = self._send_request(request)
            return response.get("registered", False)
        except BoundaryError:
            return False

    def request_connection_protection(
        self,
        connection_type: str,
        target: str,
        duration_seconds: int = 300
    ) -> Tuple[bool, Optional[str]]:
        """Request connection protection from boundary-daemon.

        Asks boundary-daemon to monitor and protect a specific connection.

        Args:
            connection_type: Type of connection ('database', 'network', 'file')
            target: Connection target (path, URL, etc.)
            duration_seconds: How long to protect

        Returns:
            Tuple of (granted: bool, protection_token: Optional[str])
        """
        request = {
            "command": "request_protection",
            "params": {
                "connection_type": connection_type,
                "target": target,
                "duration_seconds": duration_seconds,
                "service_type": "memory_vault"
            }
        }

        try:
            response = self._send_request(request)
            granted = response.get("granted", False)
            token = response.get("protection_token")
            return granted, token
        except BoundaryError:
            return False, None

    def release_connection_protection(self, protection_token: str) -> bool:
        """Release a connection protection.

        Args:
            protection_token: Token from request_connection_protection

        Returns:
            True if released successfully
        """
        request = {
            "command": "release_protection",
            "params": {"protection_token": protection_token}
        }

        try:
            response = self._send_request(request)
            return response.get("released", False)
        except BoundaryError:
            return False

    def is_available(self) -> bool:
        """Check if boundary-daemon is available.

        Returns:
            True if daemon is running and reachable
        """
        try:
            self.get_status(force_refresh=True)
            return self._status_cache.connected
        except Exception:
            return False


# Global client instance
_global_client: Optional[BoundaryClient] = None
_client_lock = threading.Lock()


def get_client() -> BoundaryClient:
    """Get or create global boundary client."""
    global _global_client

    if _global_client is None:
        with _client_lock:
            if _global_client is None:
                _global_client = BoundaryClient()

    return _global_client


def check_recall(memory_class: int) -> Tuple[bool, str]:
    """
    Query the boundary-daemon via Unix socket for recall permission.
    Returns (permitted: bool, reason: str)

    This is the legacy API - new code should use BoundaryClient directly.
    """
    try:
        client = get_client()
        return client.check_recall(memory_class)
    except BoundaryDeniedError as e:
        return False, e.message
    except BoundaryConnectionError as e:
        return False, e.message
    except BoundaryTimeoutError as e:
        return False, e.message
    except BoundaryError as e:
        return False, f"Boundary daemon error: {e.message}"
