"""
Tests for errors.py - Exception hierarchy and SIEM integration.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from errors import (
    Severity,
    MemoryVaultError,
    CryptoError,
    KeyDerivationError,
    EncryptionError,
    DecryptionError,
    SignatureError,
    AccessError,
    ClassificationError,
    CooldownError,
    ApprovalRequiredError,
    LockdownError,
    TombstoneError,
    BoundaryError,
    BoundaryConnectionError,
    BoundaryDeniedError,
    BoundaryTimeoutError,
    DatabaseError,
    DatabaseConnectionError,
    DatabaseIntegrityError,
    MemoryNotFoundError,
    ProfileNotFoundError,
    ProfileError,
    ProfileExistsError,
    ProfileKeyMissingError,
    IntegrityError,
    MerkleVerificationError,
    AuditTrailError,
    BackupError,
    BackupEncryptionError,
    RestoreError,
    RestoreDecryptionError,
    RestoreVersionError,
    HardwareSecurityError,
    TPMError,
    FIDO2Error,
    PhysicalTokenError,
    ConfigurationError,
    PolicyViolationError,
    SIEMError,
    SIEMConnectionError,
    SIEMReportingError,
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
        assert err.actor == {"type": "system", "id": "unknown"}
        assert err.metadata == {}
        assert err.timestamp  # Should be set

    def test_with_actor(self):
        actor = {"type": "agent", "id": "agent-007", "name": "Test Agent"}
        err = MemoryVaultError("test", actor=actor)
        assert err.actor == actor

    def test_with_metadata(self):
        meta = {"detail": "extra info", "code": 42}
        err = MemoryVaultError("test", metadata=meta)
        assert err.metadata["detail"] == "extra info"
        assert err.metadata["code"] == 42

    def test_with_cause(self):
        cause = ValueError("original error")
        err = MemoryVaultError("wrapped", cause=cause)
        assert err.cause is cause
        assert err.metadata["cause_type"] == "ValueError"
        assert err.metadata["cause_message"] == "original error"
        assert "cause_traceback" in err.metadata

    def test_to_siem_event(self):
        err = MemoryVaultError(
            "test event",
            actor={"type": "human", "id": "user1"},
            metadata={"key": "value"},
        )
        event = err.to_siem_event(source_host="vault-host")

        assert event["source"]["product"] == "memory-vault"
        assert event["source"]["host"] == "vault-host"
        assert event["action"] == "vault.error"
        assert event["outcome"] == "failure"
        assert event["severity"] == int(Severity.ERROR)
        assert event["actor"]["type"] == "human"
        assert event["metadata"]["error_type"] == "MemoryVaultError"
        assert event["metadata"]["message"] == "test event"
        assert event["metadata"]["key"] == "value"
        assert "timestamp" in event

    def test_is_exception(self):
        err = MemoryVaultError("test")
        assert isinstance(err, Exception)


class TestCryptoErrors:
    """Test cryptographic exception subclasses."""

    def test_crypto_error_severity(self):
        err = CryptoError("crypto fail")
        assert err.severity == Severity.CRITICAL
        assert err.action == "crypto.operation"

    def test_key_derivation_error(self):
        err = KeyDerivationError("bad passphrase")
        assert isinstance(err, CryptoError)
        assert isinstance(err, MemoryVaultError)
        assert err.action == "crypto.key_derivation"

    def test_encryption_error(self):
        err = EncryptionError("encrypt fail")
        assert err.action == "crypto.encrypt"

    def test_decryption_error(self):
        err = DecryptionError("decrypt fail")
        assert err.severity == Severity.ALERT
        assert err.action == "crypto.decrypt"

    def test_signature_error(self):
        err = SignatureError("sig fail")
        assert err.severity == Severity.SECURITY_VIOLATION
        assert err.action == "crypto.signature_verify"
        assert err.outcome == "denied"


class TestAccessErrors:
    """Test access control exception subclasses."""

    def test_access_error_defaults(self):
        err = AccessError("access denied")
        assert err.severity == Severity.WARNING
        assert err.outcome == "denied"

    def test_classification_error(self):
        err = ClassificationError(
            "need level 5", required_level=5, actual_level=3
        )
        assert err.severity == Severity.ALERT
        assert err.metadata["required_classification"] == 5
        assert err.metadata["actual_classification"] == 3

    def test_classification_error_no_actual(self):
        err = ClassificationError("need level 3", required_level=3)
        assert "required_classification" in err.metadata
        assert "actual_classification" not in err.metadata

    def test_cooldown_error(self):
        err = CooldownError("wait", remaining_seconds=120.5)
        assert err.severity == Severity.NOTICE
        assert err.metadata["remaining_seconds"] == 120.5

    def test_cooldown_error_no_seconds(self):
        err = CooldownError("wait")
        assert "remaining_seconds" not in err.metadata

    def test_approval_required_error(self):
        err = ApprovalRequiredError("needs human")
        assert err.severity == Severity.INFO
        assert err.outcome == "blocked"

    def test_lockdown_error(self):
        err = LockdownError("vault locked", lockdown_reason="security incident")
        assert err.severity == Severity.ALERT
        assert err.metadata["lockdown_reason"] == "security incident"

    def test_lockdown_error_no_reason(self):
        err = LockdownError("locked")
        assert "lockdown_reason" not in err.metadata

    def test_tombstone_error(self):
        err = TombstoneError("memory sealed")
        assert isinstance(err, AccessError)


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
        assert err.metadata["socket_path"] == "/tmp/test.sock"

    def test_boundary_denied_error(self):
        err = BoundaryDeniedError(
            "denied", operational_mode="airgap", reason="restricted"
        )
        assert err.severity == Severity.SECURITY_VIOLATION
        assert err.outcome == "blocked"
        assert err.metadata["operational_mode"] == "airgap"
        assert err.metadata["boundary_reason"] == "restricted"

    def test_boundary_timeout_error(self):
        err = BoundaryTimeoutError("timeout")
        assert err.action == "boundary.timeout"


class TestDatabaseErrors:
    """Test database exception subclasses."""

    def test_database_integrity_error(self):
        err = DatabaseIntegrityError(
            "tampered",
            table="memories",
            expected_hash="abc123",
            actual_hash="def456",
        )
        assert err.severity == Severity.BREACH_DETECTED
        assert err.metadata["table"] == "memories"
        assert err.metadata["expected_hash"] == "abc123"
        assert err.metadata["actual_hash"] == "def456"

    def test_memory_not_found(self):
        err = MemoryNotFoundError("not found")
        assert isinstance(err, DatabaseError)
        assert err.severity == Severity.WARNING

    def test_profile_not_found(self):
        err = ProfileNotFoundError("no profile")
        assert isinstance(err, DatabaseError)


class TestProfileErrors:
    """Test profile exception subclasses."""

    def test_profile_exists_error(self):
        err = ProfileExistsError("duplicate")
        assert isinstance(err, ProfileError)
        assert err.severity == Severity.WARNING

    def test_profile_key_missing(self):
        err = ProfileKeyMissingError("no key")
        assert err.action == "profile.key_missing"


class TestIntegrityErrors:
    """Test integrity exception subclasses."""

    def test_merkle_verification_error(self):
        err = MerkleVerificationError(
            "proof failed", leaf_hash="aaa", root_hash="bbb"
        )
        assert err.severity == Severity.BREACH_DETECTED
        assert err.metadata["leaf_hash"] == "aaa"
        assert err.metadata["root_hash"] == "bbb"

    def test_audit_trail_error(self):
        err = AuditTrailError("trail broken")
        assert isinstance(err, IntegrityError)


class TestBackupErrors:
    """Test backup/restore exception subclasses."""

    def test_restore_version_error(self):
        err = RestoreVersionError(
            "version mismatch",
            backup_version="0.9",
            supported_versions=["1.0", "1.1"],
        )
        assert err.severity == Severity.WARNING
        assert err.metadata["backup_version"] == "0.9"
        assert err.metadata["supported_versions"] == ["1.0", "1.1"]

    def test_restore_decryption_error(self):
        err = RestoreDecryptionError("bad key")
        assert isinstance(err, RestoreError)
        assert isinstance(err, BackupError)
        assert err.severity == Severity.ALERT

    def test_backup_encryption_error(self):
        err = BackupEncryptionError("encrypt fail")
        assert isinstance(err, BackupError)


class TestHardwareErrors:
    """Test hardware security exception subclasses."""

    def test_tpm_error(self):
        err = TPMError("tpm fail")
        assert isinstance(err, HardwareSecurityError)
        assert err.severity == Severity.CRITICAL

    def test_fido2_error(self):
        err = FIDO2Error("fido fail")
        assert isinstance(err, HardwareSecurityError)

    def test_physical_token_error(self):
        err = PhysicalTokenError("no token")
        assert err.severity == Severity.ALERT
        assert err.outcome == "blocked"


class TestOtherErrors:
    """Test remaining exception classes."""

    def test_configuration_error(self):
        err = ConfigurationError("bad config")
        assert err.action == "config.validation"

    def test_policy_violation(self):
        err = PolicyViolationError("policy broken")
        assert err.severity == Severity.SECURITY_VIOLATION
        assert err.outcome == "denied"

    def test_siem_connection_error(self):
        err = SIEMConnectionError("cannot connect")
        assert isinstance(err, SIEMError)

    def test_siem_reporting_error(self):
        err = SIEMReportingError("report failed")
        assert err.action == "siem.report"


class TestInheritanceChain:
    """Verify the complete inheritance chain."""

    def test_all_inherit_from_base(self):
        # Subclasses that take only (message) as required arg
        simple_subclasses = [
            CryptoError, KeyDerivationError, EncryptionError, DecryptionError,
            SignatureError, AccessError, CooldownError,
            ApprovalRequiredError, LockdownError, TombstoneError,
            BoundaryError, BoundaryConnectionError, BoundaryDeniedError,
            BoundaryTimeoutError, DatabaseError, DatabaseConnectionError,
            DatabaseIntegrityError, MemoryNotFoundError, ProfileNotFoundError,
            ProfileError, ProfileExistsError, ProfileKeyMissingError,
            IntegrityError, MerkleVerificationError, AuditTrailError,
            BackupError, BackupEncryptionError, RestoreError,
            RestoreDecryptionError, RestoreVersionError,
            HardwareSecurityError, TPMError, FIDO2Error, PhysicalTokenError,
            ConfigurationError, PolicyViolationError,
            SIEMError, SIEMConnectionError, SIEMReportingError,
        ]
        for cls in simple_subclasses:
            err = cls("test")
            assert isinstance(err, MemoryVaultError), f"{cls.__name__} does not inherit MemoryVaultError"
            assert isinstance(err, Exception)

        # ClassificationError requires required_level
        err = ClassificationError("test", required_level=3)
        assert isinstance(err, MemoryVaultError)
        assert isinstance(err, Exception)
