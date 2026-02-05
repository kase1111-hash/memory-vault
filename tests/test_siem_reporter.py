"""
Tests for siem_reporter.py - SIEM configuration, event building, and CEF formatting.

Tests the reporter without making actual network connections.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from siem_reporter import (
    Protocol,
    SIEMConfig,
    SIEMReporter,
)
from errors import DecryptionError, Severity


class TestProtocolEnum:
    """Test Protocol enum."""

    def test_values(self):
        assert Protocol.HTTP_JSON.value == "http"
        assert Protocol.CEF_UDP.value == "cef_udp"
        assert Protocol.CEF_TCP.value == "cef_tcp"


class TestSIEMConfig:
    """Test SIEM configuration."""

    def test_defaults(self):
        config = SIEMConfig()
        assert config.endpoint == ""
        assert config.protocol == Protocol.HTTP_JSON
        assert config.verify_ssl is True
        assert config.timeout == 5.0
        assert config.retry_count == 3
        assert config.batch_size == 0
        assert config.async_reporting is True
        assert config.enabled is True

    def test_custom_config(self):
        config = SIEMConfig(
            endpoint="https://siem.example.com/events",
            api_key="secret-key",
            protocol=Protocol.CEF_UDP,
            verify_ssl=False,
            timeout=10.0,
            retry_count=5,
            batch_size=10,
            async_reporting=False,
            enabled=False,
        )
        assert config.endpoint == "https://siem.example.com/events"
        assert config.api_key == "secret-key"
        assert config.protocol == Protocol.CEF_UDP
        assert config.batch_size == 10

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("SIEM_ENDPOINT", "http://test:8080/events")
        monkeypatch.setenv("SIEM_API_KEY", "test-key")
        monkeypatch.setenv("SIEM_PROTOCOL", "cef_udp")
        monkeypatch.setenv("SIEM_VERIFY_SSL", "false")
        monkeypatch.setenv("SIEM_TIMEOUT", "15.0")
        monkeypatch.setenv("SIEM_RETRY_COUNT", "5")
        monkeypatch.setenv("SIEM_BATCH_SIZE", "20")
        monkeypatch.setenv("SIEM_ASYNC", "false")
        monkeypatch.setenv("SIEM_ENABLED", "false")

        config = SIEMConfig.from_env()
        assert config.endpoint == "http://test:8080/events"
        assert config.api_key == "test-key"
        assert config.protocol == Protocol.CEF_UDP
        assert config.verify_ssl is False
        assert config.timeout == 15.0
        assert config.retry_count == 5
        assert config.batch_size == 20
        assert config.async_reporting is False
        assert config.enabled is False


class TestSIEMReporter:
    """Test SIEM reporter event building and formatting."""

    def _disabled_reporter(self):
        """Create a reporter with reporting disabled (no network needed)."""
        config = SIEMConfig(enabled=False, async_reporting=False)
        return SIEMReporter(config)

    def _sync_reporter(self):
        """Create a sync reporter for testing event building."""
        config = SIEMConfig(enabled=True, async_reporting=False, endpoint="http://localhost:9999")
        return SIEMReporter(config)

    def test_build_event(self):
        reporter = self._sync_reporter()
        event = reporter._build_event(
            action="memory.recall",
            outcome="success",
            severity=2,
            actor={"type": "agent", "id": "agent-1"},
            target={"type": "memory", "id": "mem-001"},
            metadata={"classification": 3},
        )

        assert event["action"] == "memory.recall"
        assert event["outcome"] == "success"
        assert event["severity"] == 2
        assert event["actor"]["id"] == "agent-1"
        assert event["target"]["id"] == "mem-001"
        assert event["metadata"]["classification"] == 3
        assert "event_id" in event
        assert "timestamp" in event
        assert event["source"]["product"] == "memory-vault"

    def test_build_event_defaults(self):
        reporter = self._sync_reporter()
        event = reporter._build_event(
            action="test.action",
            outcome="failure",
            severity=5,
            actor=None,
            target=None,
            metadata=None,
        )

        assert event["actor"] == {"type": "system", "id": "unknown"}
        assert event["target"] is None
        assert event["metadata"] == {}

    def test_report_event_disabled(self):
        reporter = self._disabled_reporter()
        result = reporter.report_event("test.action")
        assert result is False

    def test_report_exception_disabled(self):
        reporter = self._disabled_reporter()
        err = DecryptionError("test")
        result = reporter.report_exception(err)
        assert result is False

    def test_generate_event_id(self):
        reporter = self._sync_reporter()
        id1 = reporter._generate_event_id()
        id2 = reporter._generate_event_id()
        assert id1 != id2  # UUIDs should be unique
        assert len(id1) == 36  # UUID format

    def test_format_cef(self):
        reporter = self._sync_reporter()
        event = {
            "event_id": "test-123",
            "timestamp": "2025-01-15T10:00:00Z",
            "action": "memory.recall",
            "outcome": "success",
            "severity": 3,
            "actor": {"type": "agent", "id": "agent-1", "name": "TestAgent"},
            "target": {"type": "memory", "id": "mem-001"},
            "source": {"host": "vault-host"},
        }
        cef = reporter._format_cef(event)

        assert cef.startswith("CEF:0|Anthropic|memory-vault|")
        assert "memory.recall" in cef
        assert "Memory Vault Event" in cef
        assert "suid=agent-1" in cef
        assert "suser=TestAgent" in cef
        assert "externalId=test-123" in cef

    def test_format_cef_clamps_severity(self):
        reporter = self._sync_reporter()
        # Test severity > 10 is clamped
        event = {"severity": 15, "action": "test", "outcome": "test",
                 "actor": {}, "target": {}, "source": {}, "event_id": "x",
                 "timestamp": "now"}
        cef = reporter._format_cef(event)
        # Should contain |10| as severity (clamped)
        assert "|10|" in cef

    def test_parse_host_port(self):
        reporter = self._sync_reporter()
        host, port = reporter._parse_host_port("siem.example.com:514", 514)
        assert host == "siem.example.com"
        assert port == 514

    def test_parse_host_port_default(self):
        reporter = self._sync_reporter()
        host, port = reporter._parse_host_port("siem.example.com", 514)
        assert host == "siem.example.com"
        assert port == 514

    def test_shutdown(self):
        reporter = self._disabled_reporter()
        reporter.shutdown()  # Should not raise

    def test_report_exception_builds_event(self):
        config = SIEMConfig(enabled=True, async_reporting=False, endpoint="http://localhost:9999")
        SIEMReporter(config)  # Ensure reporter can be created
        err = DecryptionError(
            "bad key",
            actor={"type": "agent", "id": "a1"},
            metadata={"memory_id": "m1"},
        )
        event = err.to_siem_event(source_host=config.source_host)
        assert event["action"] == "crypto.decrypt"
        assert event["severity"] == int(Severity.ALERT)


class TestBatchOperations:
    """Test batch event operations."""

    def test_add_to_batch_accumulates(self):
        config = SIEMConfig(
            enabled=True, async_reporting=False,
            batch_size=5, endpoint="http://localhost:9999",
        )
        reporter = SIEMReporter(config)
        event = reporter._build_event("test", "ok", 1, None, None, None)

        # Add events below batch size
        for _ in range(3):
            reporter._add_to_batch(event)

        assert len(reporter._batch) == 3

    def test_flush_empty_batch(self):
        config = SIEMConfig(enabled=True, async_reporting=False, batch_size=5)
        reporter = SIEMReporter(config)
        result = reporter._flush_batch()
        assert result is True  # Empty batch flushes successfully
