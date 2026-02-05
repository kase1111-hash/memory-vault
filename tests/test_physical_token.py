"""
Tests for physical_token.py - Token availability and setup.

Tests that can run without actual hardware tokens.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import physical_token


class TestCheckTokenAvailability:
    """Test check_token_availability function."""

    def test_returns_dict_with_expected_keys(self):
        status = physical_token.check_token_availability()
        assert "fido2" in status
        assert "hmac" in status
        assert "totp" in status

    def test_fido2_has_expected_fields(self):
        status = physical_token.check_token_availability()
        assert "available" in status["fido2"]
        assert "devices" in status["fido2"]
        assert isinstance(status["fido2"]["devices"], int)

    def test_hmac_has_expected_fields(self):
        status = physical_token.check_token_availability()
        assert "available" in status["hmac"]
        assert "configured" in status["hmac"]

    def test_totp_has_expected_fields(self):
        status = physical_token.check_token_availability()
        assert "available" in status["totp"]
        assert "configured" in status["totp"]


class TestHmacChallengeResponse:
    """Test HMAC challenge-response mechanism."""

    def test_no_secret_file_returns_false(self, monkeypatch):
        """Without a challenge file, HMAC auth should fail."""
        monkeypatch.setattr(physical_token, "TOKEN_CHALLENGE_PATH", "/nonexistent/path")
        assert physical_token._hmac_challenge_response() is False

    def test_wrong_size_secret_returns_false(self, tmp_path):
        """Secret file with wrong size should fail."""
        secret_path = tmp_path / "token_challenge"
        secret_path.write_bytes(b"too short")
        old_path = physical_token.TOKEN_CHALLENGE_PATH
        physical_token.TOKEN_CHALLENGE_PATH = str(secret_path)
        try:
            assert physical_token._hmac_challenge_response() is False
        finally:
            physical_token.TOKEN_CHALLENGE_PATH = old_path


class TestSetupHmacToken:
    """Test HMAC token setup."""

    def test_setup_creates_file(self, tmp_path, monkeypatch):
        challenge_path = tmp_path / "token_challenge"
        monkeypatch.setattr(physical_token, "TOKEN_CHALLENGE_PATH", str(challenge_path))
        result = physical_token.setup_hmac_token()
        assert result == str(challenge_path)
        assert challenge_path.exists()
        assert len(challenge_path.read_bytes()) == 32

    def test_setup_with_custom_secret(self, tmp_path, monkeypatch):
        challenge_path = tmp_path / "token_challenge"
        monkeypatch.setattr(physical_token, "TOKEN_CHALLENGE_PATH", str(challenge_path))
        secret = os.urandom(32)
        physical_token.setup_hmac_token(secret=secret)
        assert challenge_path.read_bytes() == secret

    def test_setup_rejects_wrong_size(self, tmp_path, monkeypatch):
        challenge_path = tmp_path / "token_challenge"
        monkeypatch.setattr(physical_token, "TOKEN_CHALLENGE_PATH", str(challenge_path))
        with pytest.raises(ValueError, match="32 bytes"):
            physical_token.setup_hmac_token(secret=b"short")


class TestRequirePhysicalToken:
    """Test the main require_physical_token function."""

    def test_all_methods_fail_returns_false(self, monkeypatch):
        """When no token methods succeed, returns False."""
        monkeypatch.setattr(physical_token, "FIDO2_AVAILABLE", False)
        monkeypatch.setattr(physical_token, "OTP_AVAILABLE", False)
        monkeypatch.setattr(physical_token, "TOKEN_CHALLENGE_PATH", "/nonexistent")
        result = physical_token.require_physical_token("test")
        assert result is False


class TestFido2Challenge:
    """Test FIDO2 challenge mechanism."""

    def test_not_available_returns_false(self, monkeypatch):
        monkeypatch.setattr(physical_token, "FIDO2_AVAILABLE", False)
        assert physical_token._fido2_challenge() is False


class TestOtpChallenge:
    """Test OTP challenge mechanism."""

    def test_not_available_returns_false(self, monkeypatch):
        monkeypatch.setattr(physical_token, "OTP_AVAILABLE", False)
        assert physical_token._otp_challenge() is False

    def test_no_secret_file_returns_false(self, monkeypatch):
        monkeypatch.setattr(physical_token, "OTP_AVAILABLE", True)
        monkeypatch.setattr(physical_token, "TOTP_SECRET_PATH", "/nonexistent")
        assert physical_token._otp_challenge() is False
