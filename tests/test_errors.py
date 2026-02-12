"""
Tests for errors.py - Exception hierarchy and severity levels.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from errors import (
    Severity,
    MemoryVaultError,
    CryptoError,
    DecryptionError,
    AccessError,
    CooldownError,
    ApprovalRequiredError,
    LockdownError,
    TombstoneError,
    BoundaryError,
    BoundaryConnectionError,
    BoundaryDeniedError,
    BoundaryTimeoutError,
    DatabaseError,
    MemoryNotFoundError,
    ProfileError,
    ProfileKeyMissingError,
    HardwareSecurityError,
    PhysicalTokenError,
)


class TestSeverityEnum:
    """Test Severity IntEnum."""

    def test_severity_values(self):
        assert Severity.DEBUG == 1
        assert Severity.INFO == 2
        assert Severity.NOTICE == 3
        assert Severity.WARNING == 4
        assert Severity.ERROR == 5
        assert Severity.CRITICAL == 6
        assert Severity.ALERT == 7
        assert Severity.EMERGENCY == 8
        assert Severity.SECURITY_VIOLATION == 9
        assert Severity.BREACH_DETECTED == 10

    def test_severity_is_int(self):
        assert int(Severity.ERROR) == 5
        assert Severity.CRITICAL > Severity.WARNING


class TestMemoryVaultError:
    """Test base exception class."""

    def test_basic_instantiation(self):
        err = MemoryVaultError("Something failed")
        assert str(err) == "Something failed"
        assert err.message == "Something failed"
        assert err.outcome == "failure"

    def test_is_exception(self):
        err = MemoryVaultError("test")
        assert isinstance(err, Exception)

    def test_default_severity(self):
        err = MemoryVaultError("test")
        assert err.severity == Severity.ERROR
        assert err.action == "vault.error"


class TestCryptoErrors:
    """Test cryptographic exception subclasses."""

    def test_crypto_error_severity(self):
        err = CryptoError("crypto fail")
        assert err.severity == Severity.CRITICAL
        assert err.action == "crypto.operation"

    def test_decryption_error(self):
        err = DecryptionError("decrypt fail")
        assert err.severity == Severity.ALERT
        assert err.action == "crypto.decrypt"
        assert isinstance(err, CryptoError)
        assert isinstance(err, MemoryVaultError)


class TestAccessErrors:
    """Test access control exception subclasses."""

    def test_access_error_defaults(self):
        err = AccessError("access denied")
        assert err.severity == Severity.WARNING
        assert err.outcome == "denied"

    def test_cooldown_error(self):
        err = CooldownError("wait", remaining_seconds=120.5)
        assert err.severity == Severity.NOTICE
        assert err.remaining_seconds == 120.5

    def test_cooldown_error_no_seconds(self):
        err = CooldownError("wait")
        assert err.remaining_seconds is None

    def test_approval_required_error(self):
        err = ApprovalRequiredError("needs human")
        assert err.severity == Severity.INFO
        assert err.outcome == "blocked"

    def test_lockdown_error(self):
        err = LockdownError("vault locked", lockdown_reason="security incident")
        assert err.severity == Severity.ALERT
        assert err.lockdown_reason == "security incident"

    def test_lockdown_error_no_reason(self):
        err = LockdownError("locked")
        assert err.lockdown_reason is None

    def test_tombstone_error(self):
        err = TombstoneError("memory sealed")
        assert isinstance(err, AccessError)
        assert err.severity == Severity.WARNING


class TestBoundaryErrors:
    """Test boundary daemon exception subclasses."""

    def test_boundary_error_severity(self):
        err = BoundaryError("boundary fail")
        assert err.severity == Severity.CRITICAL

    def test_boundary_connection_error(self):
        err = BoundaryConnectionError(
            "socket not found", socket_path="/tmp/test.sock"
        )
        assert isinstance(err, BoundaryError)
        assert err.socket_path == "/tmp/test.sock"

    def test_boundary_denied_error(self):
        err = BoundaryDeniedError(
            "denied", operational_mode="airgap", reason="restricted"
        )
        assert err.severity == Severity.SECURITY_VIOLATION
        assert err.outcome == "blocked"
        assert err.operational_mode == "airgap"
        assert err.reason == "restricted"

    def test_boundary_timeout_error(self):
        err = BoundaryTimeoutError("timeout")
        assert err.action == "boundary.timeout"


class TestDatabaseErrors:
    """Test database exception subclasses."""

    def test_memory_not_found(self):
        err = MemoryNotFoundError("not found")
        assert isinstance(err, DatabaseError)
        assert err.severity == Severity.WARNING


class TestProfileErrors:
    """Test profile exception subclasses."""

    def test_profile_key_missing(self):
        err = ProfileKeyMissingError("no key")
        assert isinstance(err, ProfileError)
        assert err.action == "profile.key_missing"


class TestHardwareErrors:
    """Test hardware security exception subclasses."""

    def test_physical_token_error(self):
        err = PhysicalTokenError("no token")
        assert isinstance(err, HardwareSecurityError)
        assert err.severity == Severity.ALERT
        assert err.outcome == "blocked"


class TestInheritanceChain:
    """Verify the complete inheritance chain."""

    def test_all_inherit_from_base(self):
        simple_subclasses = [
            CryptoError, DecryptionError,
            AccessError, CooldownError,
            ApprovalRequiredError, LockdownError, TombstoneError,
            BoundaryError, BoundaryConnectionError, BoundaryDeniedError,
            BoundaryTimeoutError, DatabaseError, MemoryNotFoundError,
            ProfileError, ProfileKeyMissingError,
            HardwareSecurityError, PhysicalTokenError,
        ]
        for cls in simple_subclasses:
            err = cls("test")
            assert isinstance(err, MemoryVaultError), f"{cls.__name__} does not inherit MemoryVaultError"
            assert isinstance(err, Exception)
