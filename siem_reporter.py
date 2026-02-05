"""
SIEM Reporter for Memory Vault.

Integrates with Boundary-SIEM to report security events, access attempts,
and integrity violations. Supports both HTTP/JSON and CEF protocols.
"""

import os
import json
import socket
import logging
import threading
import queue
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum
import urllib.request
import urllib.error
import ssl

from errors import (
    MemoryVaultError,
)


logger = logging.getLogger(__name__)


class Protocol(Enum):
    """SIEM communication protocols."""
    HTTP_JSON = "http"
    CEF_UDP = "cef_udp"
    CEF_TCP = "cef_tcp"


@dataclass
class SIEMConfig:
    """Configuration for SIEM reporter.

    Attributes:
        endpoint: SIEM endpoint URL (for HTTP) or host:port (for CEF)
        api_key: API key for authentication (HTTP only)
        protocol: Communication protocol
        verify_ssl: Whether to verify SSL certificates
        timeout: Connection timeout in seconds
        retry_count: Number of retries on failure
        batch_size: Events to batch before sending (0 = immediate)
        async_reporting: Use background thread for reporting
        source_host: Hostname to report as event source
        enabled: Whether SIEM reporting is enabled
    """
    endpoint: str = ""
    api_key: str = ""
    protocol: Protocol = Protocol.HTTP_JSON
    verify_ssl: bool = True
    timeout: float = 5.0
    retry_count: int = 3
    batch_size: int = 0
    async_reporting: bool = True
    source_host: str = field(default_factory=socket.gethostname)
    enabled: bool = True

    @classmethod
    def from_env(cls) -> "SIEMConfig":
        """Create config from environment variables."""
        return cls(
            endpoint=os.environ.get("SIEM_ENDPOINT", "http://localhost:8080/v1/events"),
            api_key=os.environ.get("SIEM_API_KEY", ""),
            protocol=Protocol(os.environ.get("SIEM_PROTOCOL", "http")),
            verify_ssl=os.environ.get("SIEM_VERIFY_SSL", "true").lower() == "true",
            timeout=float(os.environ.get("SIEM_TIMEOUT", "5.0")),
            retry_count=int(os.environ.get("SIEM_RETRY_COUNT", "3")),
            batch_size=int(os.environ.get("SIEM_BATCH_SIZE", "0")),
            async_reporting=os.environ.get("SIEM_ASYNC", "true").lower() == "true",
            source_host=os.environ.get("SIEM_SOURCE_HOST", socket.gethostname()),
            enabled=os.environ.get("SIEM_ENABLED", "true").lower() == "true",
        )


class SIEMReporter:
    """Reports security events to Boundary-SIEM.

    Supports multiple protocols and async/batched reporting for performance.
    Thread-safe for concurrent use from multiple vault operations.
    """

    VERSION = "1.1.0"
    PRODUCT_NAME = "memory-vault"

    def __init__(self, config: Optional[SIEMConfig] = None):
        """Initialize SIEM reporter.

        Args:
            config: SIEM configuration. If None, reads from environment.
        """
        self.config = config or SIEMConfig.from_env()
        self._event_queue: queue.Queue = queue.Queue()
        self._batch: List[Dict[str, Any]] = []
        self._batch_lock = threading.Lock()
        self._worker_thread: Optional[threading.Thread] = None
        self._shutdown = threading.Event()

        if self.config.async_reporting and self.config.enabled:
            self._start_worker()

    def _start_worker(self) -> None:
        """Start background worker thread for async reporting."""
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="siem-reporter",
            daemon=True
        )
        self._worker_thread.start()
        logger.debug("SIEM reporter worker thread started")

    def _worker_loop(self) -> None:
        """Background worker that processes event queue."""
        while not self._shutdown.is_set():
            try:
                # Get event with timeout to allow shutdown check
                event = self._event_queue.get(timeout=1.0)
                self._send_event_sync(event)
                self._event_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"SIEM worker error: {e}")

    def shutdown(self, timeout: float = 5.0) -> None:
        """Gracefully shutdown the reporter.

        Args:
            timeout: Maximum seconds to wait for pending events
        """
        self._shutdown.set()

        # Flush any batched events
        self._flush_batch()

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)

    def report_event(
        self,
        action: str,
        outcome: str = "success",
        severity: int = 2,
        actor: Optional[Dict[str, str]] = None,
        target: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Report a security event to SIEM.

        Args:
            action: Event action in dot-notation (e.g., 'memory.recall')
            outcome: Result ('success', 'failure', 'denied', 'blocked')
            severity: SIEM severity (1-10)
            actor: Actor information (type, id, name, ip_address)
            target: Target resource information
            metadata: Additional event context

        Returns:
            True if event was queued/sent, False if disabled/failed
        """
        if not self.config.enabled:
            return False

        event = self._build_event(action, outcome, severity, actor, target, metadata)

        if self.config.async_reporting:
            self._event_queue.put(event)
            return True
        else:
            return self._send_event_sync(event)

    def report_exception(self, exc: MemoryVaultError) -> bool:
        """Report a MemoryVaultError as a SIEM event.

        Args:
            exc: The exception to report

        Returns:
            True if event was queued/sent, False if disabled/failed
        """
        if not self.config.enabled:
            return False

        event = exc.to_siem_event(source_host=self.config.source_host)
        event["event_id"] = self._generate_event_id()

        if self.config.async_reporting:
            self._event_queue.put(event)
            return True
        else:
            return self._send_event_sync(event)

    def _build_event(
        self,
        action: str,
        outcome: str,
        severity: int,
        actor: Optional[Dict[str, str]],
        target: Optional[Dict[str, str]],
        metadata: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Build SIEM event payload."""
        return {
            "event_id": self._generate_event_id(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": {
                "product": self.PRODUCT_NAME,
                "host": self.config.source_host,
                "version": self.VERSION
            },
            "action": action,
            "outcome": outcome,
            "severity": severity,
            "actor": actor or {"type": "system", "id": "unknown"},
            "target": target,
            "metadata": metadata or {}
        }

    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        import uuid
        return str(uuid.uuid4())

    def _send_event_sync(self, event: Dict[str, Any]) -> bool:
        """Synchronously send event to SIEM.

        Handles batching if configured.
        """
        if self.config.batch_size > 0:
            return self._add_to_batch(event)

        return self._transmit_events([event])

    def _add_to_batch(self, event: Dict[str, Any]) -> bool:
        """Add event to batch, flush if batch is full."""
        with self._batch_lock:
            self._batch.append(event)
            if len(self._batch) >= self.config.batch_size:
                return self._flush_batch_locked()
        return True

    def _flush_batch(self) -> bool:
        """Flush any pending batched events."""
        with self._batch_lock:
            return self._flush_batch_locked()

    def _flush_batch_locked(self) -> bool:
        """Flush batch (must hold _batch_lock)."""
        if not self._batch:
            return True

        events = self._batch[:]
        self._batch.clear()
        return self._transmit_events(events)

    def _transmit_events(self, events: List[Dict[str, Any]]) -> bool:
        """Transmit events using configured protocol."""
        protocol = self.config.protocol

        for attempt in range(self.config.retry_count):
            try:
                if protocol == Protocol.HTTP_JSON:
                    return self._send_http(events)
                elif protocol == Protocol.CEF_UDP:
                    return self._send_cef_udp(events)
                elif protocol == Protocol.CEF_TCP:
                    return self._send_cef_tcp(events)
                else:
                    logger.error(f"Unknown SIEM protocol: {protocol}")
                    return False

            except (urllib.error.URLError, OSError) as e:
                logger.warning(
                    f"SIEM transmission attempt {attempt + 1}/{self.config.retry_count} "
                    f"failed: {e}"
                )
                if attempt < self.config.retry_count - 1:
                    import time
                    time.sleep(2 ** attempt)  # Exponential backoff

        logger.error("SIEM transmission failed after all retries")
        return False

    def _send_http(self, events: List[Dict[str, Any]]) -> bool:
        """Send events via HTTP/JSON to Boundary-SIEM."""
        endpoint = self.config.endpoint

        # Build request
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"memory-vault/{self.VERSION}",
        }

        if self.config.api_key:
            headers["X-API-Key"] = self.config.api_key

        # Send individual events or batch
        for event in events:
            data = json.dumps(event).encode("utf-8")

            request = urllib.request.Request(  # noqa: S310
                endpoint,
                data=data,
                headers=headers,
                method="POST"
            )

            # Configure SSL context
            if self.config.verify_ssl:
                context = ssl.create_default_context()
            else:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            try:
                with urllib.request.urlopen(  # noqa: S310
                    request,
                    timeout=self.config.timeout,
                    context=context
                ) as response:
                    if response.status >= 400:
                        logger.error(f"SIEM HTTP error: {response.status}")
                        return False
            except urllib.error.HTTPError as e:
                logger.error(f"SIEM HTTP error: {e.code} - {e.reason}")
                raise

        return True

    def _send_cef_udp(self, events: List[Dict[str, Any]]) -> bool:
        """Send events via CEF over UDP."""
        host, port = self._parse_host_port(self.config.endpoint, default_port=514)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.config.timeout)

        try:
            for event in events:
                cef_message = self._format_cef(event)
                sock.sendto(cef_message.encode("utf-8"), (host, port))
            return True
        finally:
            sock.close()

    def _send_cef_tcp(self, events: List[Dict[str, Any]]) -> bool:
        """Send events via CEF over TCP."""
        host, port = self._parse_host_port(self.config.endpoint, default_port=514)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.config.timeout)

        try:
            sock.connect((host, port))
            for event in events:
                cef_message = self._format_cef(event) + "\n"
                sock.sendall(cef_message.encode("utf-8"))
            return True
        finally:
            sock.close()

    def _parse_host_port(self, endpoint: str, default_port: int) -> tuple:
        """Parse host:port from endpoint string."""
        if ":" in endpoint:
            parts = endpoint.rsplit(":", 1)
            return parts[0], int(parts[1])
        return endpoint, default_port

    def _format_cef(self, event: Dict[str, Any]) -> str:
        """Format event as CEF (Common Event Format) message.

        Format: CEF:Version|Device Vendor|Device Product|Device Version|
                Signature ID|Name|Severity|Extension
        """
        # Map severity to CEF level (0-10)
        cef_severity = min(10, max(0, event.get("severity", 5)))

        # Build extension key-value pairs
        extensions = []

        # Standard CEF extensions
        extensions.append(f"rt={event.get('timestamp', '')}")
        extensions.append(f"act={event.get('action', 'unknown')}")
        extensions.append(f"outcome={event.get('outcome', 'unknown')}")

        # Actor info
        actor = event.get("actor", {})
        if actor.get("id"):
            extensions.append(f"suid={actor['id']}")
        if actor.get("name"):
            extensions.append(f"suser={actor['name']}")
        if actor.get("type"):
            extensions.append(f"cs1={actor['type']}")
            extensions.append("cs1Label=actorType")

        # Target info
        target = event.get("target", {})
        if target:
            if target.get("id"):
                extensions.append(f"destinationServiceName={target['id']}")

        # Event ID
        extensions.append(f"externalId={event.get('event_id', '')}")

        # Source info
        source = event.get("source", {})
        extensions.append(f"dvchost={source.get('host', 'unknown')}")

        extension_str = " ".join(extensions)

        # CEF header
        action = event.get("action", "unknown")
        return (
            f"CEF:0|Anthropic|memory-vault|{self.VERSION}|"
            f"{action}|Memory Vault Event|{cef_severity}|{extension_str}"
        )


# Global reporter instance (initialized on first use)
_global_reporter: Optional[SIEMReporter] = None
_reporter_lock = threading.Lock()


def get_reporter() -> SIEMReporter:
    """Get or create the global SIEM reporter instance."""
    global _global_reporter

    if _global_reporter is None:
        with _reporter_lock:
            if _global_reporter is None:
                _global_reporter = SIEMReporter()

    return _global_reporter


def report_event(
    action: str,
    outcome: str = "success",
    severity: int = 2,
    actor: Optional[Dict[str, str]] = None,
    target: Optional[Dict[str, str]] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> bool:
    """Convenience function to report event via global reporter."""
    return get_reporter().report_event(
        action=action,
        outcome=outcome,
        severity=severity,
        actor=actor,
        target=target,
        metadata=metadata
    )


def report_exception(exc: MemoryVaultError) -> bool:
    """Convenience function to report exception via global reporter."""
    return get_reporter().report_exception(exc)


def configure_siem(config: SIEMConfig) -> None:
    """Configure the global SIEM reporter."""
    global _global_reporter

    with _reporter_lock:
        if _global_reporter:
            _global_reporter.shutdown()
        _global_reporter = SIEMReporter(config)


def shutdown_siem() -> None:
    """Shutdown the global SIEM reporter."""
    global _global_reporter

    with _reporter_lock:
        if _global_reporter:
            _global_reporter.shutdown()
            _global_reporter = None
