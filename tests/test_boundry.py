"""
Tests for boundry.py - Boundary daemon client.

Tests data structures, error handling, and client behavior
without requiring a running boundary daemon.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from boundry import (
    OperationalMode,
    BoundaryStatus,
    BoundaryClient,
    get_client,
    check_recall,
)
from errors import (
    BoundaryConnectionError,
)


class TestOperationalMode:
    """Test OperationalMode enum."""

    def test_all_modes_exist(self):
        assert OperationalMode.ONLINE.value == "online"
        assert OperationalMode.OFFLINE.value == "offline"
        assert OperationalMode.AIRGAP.value == "airgap"
        assert OperationalMode.COLDROOM.value == "coldroom"

    def test_from_string(self):
        assert OperationalMode("online") == OperationalMode.ONLINE
        assert OperationalMode("airgap") == OperationalMode.AIRGAP


class TestBoundaryStatus:
    """Test BoundaryStatus dataclass."""

    def test_basic_creation(self):
        status = BoundaryStatus(
            connected=True,
            operational_mode=OperationalMode.OFFLINE,
            restrictions={"all_network": False},
        )
        assert status.connected is True
        assert status.operational_mode == OperationalMode.OFFLINE
        assert status.restrictions == {"all_network": False}
        assert status.last_check is None

    def test_with_last_check(self):
        status = BoundaryStatus(
            connected=False,
            operational_mode=OperationalMode.AIRGAP,
            restrictions={},
            last_check=1234567890.0,
        )
        assert status.last_check == 1234567890.0


class TestBoundaryClient:
    """Test BoundaryClient initialization and error handling."""

    def test_default_initialization(self):
        client = BoundaryClient()
        assert client.timeout == 5.0
        assert client.siem_reporter is None

    def test_custom_initialization(self):
        client = BoundaryClient(
            socket_path="/tmp/test.sock",
            timeout=10.0,
        )
        assert client.socket_path == "/tmp/test.sock"
        assert client.timeout == 10.0

    def test_send_request_no_socket_raises(self):
        """Connecting to nonexistent socket raises BoundaryConnectionError."""
        client = BoundaryClient(socket_path="/tmp/nonexistent_socket_12345.sock")
        with pytest.raises(BoundaryConnectionError):
            client._send_request({"command": "status"})

    def test_get_status_no_daemon(self):
        """get_status returns disconnected status when daemon unavailable."""
        client = BoundaryClient(socket_path="/tmp/nonexistent_socket_12345.sock")
        status = client.get_status()
        assert status.connected is False
        assert status.operational_mode == OperationalMode.AIRGAP

    def test_is_available_no_daemon(self):
        """is_available returns False when daemon unavailable."""
        client = BoundaryClient(socket_path="/tmp/nonexistent_socket_12345.sock")
        assert client.is_available() is False

    def test_register_vault_no_daemon(self):
        """register_vault returns False when daemon unavailable."""
        client = BoundaryClient(socket_path="/tmp/nonexistent_socket_12345.sock")
        result = client.register_vault("test-vault-id")
        assert result is False

    def test_request_connection_protection_no_daemon(self):
        """request_connection_protection returns (False, None) when unavailable."""
        client = BoundaryClient(socket_path="/tmp/nonexistent_socket_12345.sock")
        granted, token = client.request_connection_protection("database", "/tmp/db")
        assert granted is False
        assert token is None

    def test_release_connection_protection_no_daemon(self):
        """release_connection_protection returns False when unavailable."""
        client = BoundaryClient(socket_path="/tmp/nonexistent_socket_12345.sock")
        result = client.release_connection_protection("fake-token")
        assert result is False

    def test_status_cache(self):
        """Status cache is populated after get_status call."""
        client = BoundaryClient(socket_path="/tmp/nonexistent_socket_12345.sock")
        status1 = client.get_status()
        # Second call should use cache (last_check will be recent)
        status2 = client.get_status()
        assert status1.connected == status2.connected


class TestLegacyCheckRecall:
    """Test the legacy check_recall module-level function."""

    def test_returns_tuple(self, monkeypatch):
        """check_recall returns (bool, str) tuple."""
        import boundry
        # Reset global client so it reconnects with bad socket
        monkeypatch.setattr(boundry, "_global_client", None)
        monkeypatch.setattr(boundry, "SOCKET_PATH", "/tmp/nonexistent_socket_12345.sock")
        permitted, reason = check_recall(memory_class=0)
        assert isinstance(permitted, bool)
        assert isinstance(reason, str)
        assert permitted is False  # Can't connect


class TestGetClient:
    """Test global client management."""

    def test_returns_boundary_client(self, monkeypatch):
        import boundry
        monkeypatch.setattr(boundry, "_global_client", None)
        client = get_client()
        assert isinstance(client, BoundaryClient)
