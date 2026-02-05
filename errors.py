"""
Memory Vault Error Handling Framework.

Provides structured exception classes with SIEM integration support.
All exceptions include severity levels and can be reported to Boundary-SIEM.
"""

from enum import IntEnum
from typing import Optional, Dict, Any
from datetime import datetime, timezone
import traceback


class Severity(IntEnum):
    """SIEM-compatible severity levels (1-10 scale)."""
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
        severity: SIEM severity level (1-10)
        action: Dot-notation action that failed (e.g., 'memory.recall')
        outcome: Result of the action ('failure', 'blocked', 'denied')
        actor: Actor information dict (type, id, name)
        metadata: Additional context for debugging/auditing
        timestamp: When the error occurred
    """

    severity: Severity = Severity.ERROR
    action: str = "vault.error"
    outcome: str = "failure"

    def __init__(
        self,
        message: str,
        actor: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(message)
        self.message = message
        self.actor = actor or {"type": "system", "id": "unknown"}
        self.metadata = metadata or {}
        self.cause = cause
        self.timestamp = datetime.now(timezone.utc).isoformat()

        # Include cause traceback in metadata if available
        if cause:
            self.metadata["cause_type"] = type(cause).__name__
            self.metadata["cause_message"] = str(cause)
            self.metadata["cause_traceback"] = traceback.format_exception(
                type(cause), cause, cause.__traceback__
            )

    def to_siem_event(self, source_host: str = "localhost") -> Dict[str, Any]:
        """Convert exception to SIEM-compatible event format."""
        return {
            "timestamp": self.timestamp,
            "source": {
                "product": "memory-vault",
                "host": source_host,
                "version": "0.1.0-alpha"
            },
            "action": self.action,
            "outcome": self.outcome,
            "severity": int(self.severity),
            "actor": self.actor,
            "metadata": {
                "error_type": type(self).__name__,
                "message": self.message,
                **self.metadata
            }
        }


# ============================================================================
# Cryptographic Errors
# ============================================================================

class CryptoError(MemoryVaultError):
    """Base class for cryptographic operation failures."""
    severity = Severity.CRITICAL
    action = "crypto.operation"


class KeyDerivationError(CryptoError):
    """Failed to derive encryption key from passphrase."""
    action = "crypto.key_derivation"


class EncryptionError(CryptoError):
    """Failed to encrypt data."""
    action = "crypto.encrypt"


class DecryptionError(CryptoError):
    """Failed to decrypt data. May indicate tampering or wrong key."""
    severity = Severity.ALERT
    action = "crypto.decrypt"


class SignatureError(CryptoError):
    """Signature verification failed."""
    severity = Severity.SECURITY_VIOLATION
    action = "crypto.signature_verify"
    outcome = "denied"


# ============================================================================
# Access Control Errors
# ============================================================================

class AccessError(MemoryVaultError):
    """Base class for access control violations."""
    severity = Severity.WARNING
    action = "access.check"
    outcome = "denied"


class ClassificationError(AccessError):
    """Access denied due to classification level."""
    severity = Severity.ALERT
    action = "access.classification"

    def __init__(self, message: str, required_level: int,
                 actual_level: int = None, **kwargs):
        super().__init__(message, **kwargs)
        self.metadata["required_classification"] = required_level
        if actual_level is not None:
            self.metadata["actual_classification"] = actual_level


class CooldownError(AccessError):
    """Access denied due to cooldown period."""
    severity = Severity.NOTICE
    action = "access.cooldown"

    def __init__(self, message: str, remaining_seconds: float = None, **kwargs):
        super().__init__(message, **kwargs)
        if remaining_seconds is not None:
            self.metadata["remaining_seconds"] = remaining_seconds


class ApprovalRequiredError(AccessError):
    """Operation requires human approval."""
    severity = Severity.INFO
    action = "access.approval_required"
    outcome = "blocked"


class LockdownError(AccessError):
    """Vault is in lockdown mode."""
    severity = Severity.ALERT
    action = "access.lockdown"

    def __init__(self, message: str, lockdown_reason: str = None, **kwargs):
        super().__init__(message, **kwargs)
        if lockdown_reason:
            self.metadata["lockdown_reason"] = lockdown_reason


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

    def __init__(self, message: str, socket_path: str = None, **kwargs):
        super().__init__(message, **kwargs)
        if socket_path:
            self.metadata["socket_path"] = socket_path


class BoundaryDeniedError(BoundaryError):
    """Boundary daemon denied the operation."""
    severity = Severity.SECURITY_VIOLATION
    action = "boundary.denied"
    outcome = "blocked"

    def __init__(self, message: str, operational_mode: str = None,
                 reason: str = None, **kwargs):
        super().__init__(message, **kwargs)
        if operational_mode:
            self.metadata["operational_mode"] = operational_mode
        if reason:
            self.metadata["boundary_reason"] = reason


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


class DatabaseConnectionError(DatabaseError):
    """Failed to connect to database."""
    action = "database.connect"


class DatabaseIntegrityError(DatabaseError):
    """Database integrity check failed."""
    severity = Severity.BREACH_DETECTED
    action = "database.integrity"

    def __init__(self, message: str, table: str = None,
                 expected_hash: str = None, actual_hash: str = None, **kwargs):
        super().__init__(message, **kwargs)
        if table:
            self.metadata["table"] = table
        if expected_hash:
            self.metadata["expected_hash"] = expected_hash
        if actual_hash:
            self.metadata["actual_hash"] = actual_hash


class MemoryNotFoundError(DatabaseError):
    """Requested memory does not exist."""
    severity = Severity.WARNING
    action = "memory.not_found"


class ProfileNotFoundError(DatabaseError):
    """Requested encryption profile does not exist."""
    severity = Severity.WARNING
    action = "profile.not_found"


# ============================================================================
# Profile Errors
# ============================================================================

class ProfileError(MemoryVaultError):
    """Base class for encryption profile errors."""
    severity = Severity.ERROR
    action = "profile.operation"


class ProfileExistsError(ProfileError):
    """Profile with this ID already exists."""
    severity = Severity.WARNING
    action = "profile.duplicate"


class ProfileKeyMissingError(ProfileError):
    """Profile key not loaded or available."""
    severity = Severity.WARNING
    action = "profile.key_missing"


# ============================================================================
# Integrity Errors
# ============================================================================

class IntegrityError(MemoryVaultError):
    """Base class for integrity verification failures."""
    severity = Severity.BREACH_DETECTED
    action = "integrity.verification"
    outcome = "failure"


class MerkleVerificationError(IntegrityError):
    """Merkle tree verification failed."""
    action = "integrity.merkle"

    def __init__(self, message: str, leaf_hash: str = None,
                 root_hash: str = None, **kwargs):
        super().__init__(message, **kwargs)
        if leaf_hash:
            self.metadata["leaf_hash"] = leaf_hash
        if root_hash:
            self.metadata["root_hash"] = root_hash


class AuditTrailError(IntegrityError):
    """Audit trail verification failed."""
    action = "integrity.audit_trail"


# ============================================================================
# Backup/Restore Errors
# ============================================================================

class BackupError(MemoryVaultError):
    """Base class for backup operation failures."""
    severity = Severity.ERROR
    action = "backup.operation"


class BackupEncryptionError(BackupError):
    """Failed to encrypt backup."""
    action = "backup.encrypt"


class RestoreError(BackupError):
    """Failed to restore from backup."""
    action = "restore.operation"


class RestoreDecryptionError(RestoreError):
    """Failed to decrypt backup during restore."""
    severity = Severity.ALERT
    action = "restore.decrypt"


class RestoreVersionError(RestoreError):
    """Backup version incompatible."""
    severity = Severity.WARNING
    action = "restore.version"

    def __init__(self, message: str, backup_version: str = None,
                 supported_versions: list = None, **kwargs):
        super().__init__(message, **kwargs)
        if backup_version:
            self.metadata["backup_version"] = backup_version
        if supported_versions:
            self.metadata["supported_versions"] = supported_versions


# ============================================================================
# Hardware Security Errors
# ============================================================================

class HardwareSecurityError(MemoryVaultError):
    """Base class for hardware security module errors."""
    severity = Severity.CRITICAL
    action = "hardware.security"


class TPMError(HardwareSecurityError):
    """TPM operation failed."""
    action = "hardware.tpm"


class FIDO2Error(HardwareSecurityError):
    """FIDO2 token operation failed."""
    action = "hardware.fido2"


class PhysicalTokenError(HardwareSecurityError):
    """Physical token required but not present."""
    severity = Severity.ALERT
    action = "hardware.physical_token"
    outcome = "blocked"


# ============================================================================
# Configuration Errors
# ============================================================================

class ConfigurationError(MemoryVaultError):
    """Invalid or missing configuration."""
    severity = Severity.ERROR
    action = "config.validation"


class PolicyViolationError(MemoryVaultError):
    """Operation violates configured policy."""
    severity = Severity.SECURITY_VIOLATION
    action = "policy.violation"
    outcome = "denied"


# ============================================================================
# SIEM Integration Errors
# ============================================================================

class SIEMError(MemoryVaultError):
    """Base class for SIEM integration errors."""
    severity = Severity.WARNING
    action = "siem.operation"


class SIEMConnectionError(SIEMError):
    """Failed to connect to SIEM endpoint."""
    action = "siem.connect"


class SIEMReportingError(SIEMError):
    """Failed to report event to SIEM."""
    action = "siem.report"
