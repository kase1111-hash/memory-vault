"""
Memory Vault Error Handling Framework.

Provides structured exception classes with severity levels for
classification-gated access control.
"""

from enum import IntEnum


class Severity(IntEnum):
    """Severity levels (1-10) for error classification."""
    DEBUG = 1
    INFO = 2
    NOTICE = 3
    WARNING = 4
    ERROR = 5
    CRITICAL = 6
    ALERT = 7
    EMERGENCY = 8
    SECURITY_VIOLATION = 9
    BREACH_DETECTED = 10


class MemoryVaultError(Exception):
    """Base exception for all Memory Vault errors.

    Attributes:
        message: Human-readable error message
        severity: Severity level (1-10)
        action: Dot-notation action that failed (e.g., 'memory.recall')
        outcome: Result of the action ('failure', 'blocked', 'denied')
    """

    severity: Severity = Severity.ERROR
    action: str = "vault.error"
    outcome: str = "failure"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


# ============================================================================
# Cryptographic Errors
# ============================================================================

class CryptoError(MemoryVaultError):
    """Base class for cryptographic operation failures."""
    severity = Severity.CRITICAL
    action = "crypto.operation"


class DecryptionError(CryptoError):
    """Failed to decrypt data. May indicate tampering or wrong key."""
    severity = Severity.ALERT
    action = "crypto.decrypt"


# ============================================================================
# Access Control Errors
# ============================================================================

class AccessError(MemoryVaultError):
    """Base class for access control violations."""
    severity = Severity.WARNING
    action = "access.check"
    outcome = "denied"


class CooldownError(AccessError):
    """Access denied due to cooldown period."""
    severity = Severity.NOTICE
    action = "access.cooldown"

    def __init__(self, message: str, remaining_seconds: float = None):
        super().__init__(message)
        self.remaining_seconds = remaining_seconds


class ApprovalRequiredError(AccessError):
    """Operation requires human approval."""
    severity = Severity.INFO
    action = "access.approval_required"
    outcome = "blocked"


class LockdownError(AccessError):
    """Vault is in lockdown mode."""
    severity = Severity.ALERT
    action = "access.lockdown"

    def __init__(self, message: str, lockdown_reason: str = None):
        super().__init__(message)
        self.lockdown_reason = lockdown_reason


class TombstoneError(AccessError):
    """Memory has been tombstoned (permanently sealed)."""
    severity = Severity.WARNING
    action = "access.tombstoned"


# ============================================================================
# Boundary Daemon Errors
# ============================================================================

class BoundaryError(MemoryVaultError):
    """Base class for boundary daemon communication errors."""
    severity = Severity.CRITICAL
    action = "boundary.communication"


class BoundaryConnectionError(BoundaryError):
    """Failed to connect to boundary daemon."""
    action = "boundary.connect"

    def __init__(self, message: str, socket_path: str = None):
        super().__init__(message)
        self.socket_path = socket_path


class BoundaryDeniedError(BoundaryError):
    """Boundary daemon denied the operation."""
    severity = Severity.SECURITY_VIOLATION
    action = "boundary.denied"
    outcome = "blocked"

    def __init__(self, message: str, operational_mode: str = None,
                 reason: str = None):
        super().__init__(message)
        self.operational_mode = operational_mode
        self.reason = reason


class BoundaryTimeoutError(BoundaryError):
    """Boundary daemon did not respond in time."""
    action = "boundary.timeout"


# ============================================================================
# Database Errors
# ============================================================================

class DatabaseError(MemoryVaultError):
    """Base class for database operation failures."""
    severity = Severity.ERROR
    action = "database.operation"


class MemoryNotFoundError(DatabaseError):
    """Requested memory does not exist."""
    severity = Severity.WARNING
    action = "memory.not_found"


# ============================================================================
# Profile Errors
# ============================================================================

class ProfileError(MemoryVaultError):
    """Base class for encryption profile errors."""
    severity = Severity.ERROR
    action = "profile.operation"


class ProfileKeyMissingError(ProfileError):
    """Profile key not loaded or available."""
    severity = Severity.WARNING
    action = "profile.key_missing"


# ============================================================================
# Hardware Security Errors
# ============================================================================

class HardwareSecurityError(MemoryVaultError):
    """Base class for hardware security module errors."""
    severity = Severity.CRITICAL
    action = "hardware.security"


class PhysicalTokenError(HardwareSecurityError):
    """Physical token required but not present."""
    severity = Severity.ALERT
    action = "hardware.physical_token"
    outcome = "blocked"
