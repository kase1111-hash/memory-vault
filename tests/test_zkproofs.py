"""
Tests for zkproofs.py - Zero-knowledge proofs and attestations.

Tests pure hash functions, commitment verification, and Ed25519 attestations.
"""
import os
import sys
import hashlib
import base64

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nacl.signing import SigningKey

from zkproofs import (
    _double_sha256,
    verify_existence_commitment,
    verify_signed_attestation,
)


class TestDoubleSha256:
    """Test Bitcoin-style double SHA256 hash."""

    def test_deterministic(self):
        data = b"test data"
        assert _double_sha256(data) == _double_sha256(data)

    def test_different_inputs_different_hashes(self):
        assert _double_sha256(b"input A") != _double_sha256(b"input B")

    def test_returns_hex_string(self):
        result = _double_sha256(b"test")
        assert isinstance(result, str)
        assert len(result) == 64  # SHA256 hex digest is 64 chars
        int(result, 16)  # Should be valid hex

    def test_matches_manual_computation(self):
        data = b"verify this"
        h1 = hashlib.sha256(data).digest()
        expected = hashlib.sha256(h1).hexdigest()
        assert _double_sha256(data) == expected


class TestVerifyExistenceCommitment:
    """Test commitment verification (pure function, no DB needed)."""

    def _make_commitment(self, memory_id, content_hash, created_at, classification):
        """Helper to create a valid commitment."""
        mid_commitment = _double_sha256(memory_id.encode())
        ts_commitment = _double_sha256(created_at.encode())
        combined = f"{mid_commitment}|{content_hash}|{ts_commitment}|{classification}"
        commitment_hash = _double_sha256(combined.encode())
        return {
            "version": 1,
            "type": "existence_proof",
            "commitment_hash": commitment_hash,
            "memory_id_commitment": mid_commitment,
            "content_hash": content_hash,
            "timestamp_commitment": ts_commitment,
            "classification": classification,
        }

    def test_valid_commitment(self):
        memory_id = "mem-001"
        created_at = "2025-01-15T10:00:00"
        content_hash = hashlib.sha256(b"secret content").hexdigest()
        commitment = self._make_commitment(memory_id, content_hash, created_at, 3)

        valid, msg = verify_existence_commitment(commitment, memory_id, created_at)
        assert valid is True
        assert "verified" in msg.lower()

    def test_wrong_memory_id(self):
        commitment = self._make_commitment("mem-001", "abc123", "2025-01-01", 1)
        valid, msg = verify_existence_commitment(commitment, "mem-002", "2025-01-01")
        assert valid is False
        assert "Memory ID" in msg

    def test_wrong_timestamp(self):
        commitment = self._make_commitment("mem-001", "abc123", "2025-01-01", 1)
        valid, msg = verify_existence_commitment(commitment, "mem-001", "2025-06-01")
        assert valid is False
        assert "Timestamp" in msg

    def test_wrong_version(self):
        commitment = {"version": 99, "type": "existence_proof"}
        valid, msg = verify_existence_commitment(commitment, "x", "y")
        assert valid is False
        assert "version" in msg.lower()

    def test_wrong_type(self):
        commitment = {"version": 1, "type": "something_else"}
        valid, msg = verify_existence_commitment(commitment, "x", "y")
        assert valid is False
        assert "type" in msg.lower()

    def test_tampered_commitment_hash(self):
        commitment = self._make_commitment("mem-001", "abc", "2025-01-01", 1)
        commitment["commitment_hash"] = "0000" + commitment["commitment_hash"][4:]
        valid, msg = verify_existence_commitment(commitment, "mem-001", "2025-01-01")
        assert valid is False
        assert "hash" in msg.lower()


class TestSignedAttestation:
    """Test Ed25519 signed attestation verification."""

    def _make_attestation(self, memory_id, signing_key, statement="Test statement"):
        """Helper to create a signed attestation without DB."""
        import json
        from datetime import datetime, timezone

        content_hash = hashlib.sha256(b"content").hexdigest()

        attestation = {
            "version": 1,
            "type": "signed_attestation",
            "memory_id_commitment": _double_sha256(memory_id.encode()),
            "content_hash": content_hash,
            "classification": 2,
            "statement": statement,
            "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
            "signer_public_key": base64.b64encode(signing_key.verify_key.encode()).decode(),
        }

        message = json.dumps(dict(attestation.items()), sort_keys=True).encode()
        signed = signing_key.sign(message)
        attestation["signature"] = base64.b64encode(signed.signature).decode()

        return attestation

    def test_valid_attestation(self):
        sk = SigningKey.generate()
        vk = sk.verify_key
        attestation = self._make_attestation("mem-001", sk)
        valid, msg = verify_signed_attestation(attestation, vk)
        assert valid is True
        assert "verified" in msg.lower()

    def test_wrong_verify_key(self):
        sk1 = SigningKey.generate()
        sk2 = SigningKey.generate()
        attestation = self._make_attestation("mem-001", sk1)
        valid, msg = verify_signed_attestation(attestation, sk2.verify_key)
        assert valid is False
        assert "failed" in msg.lower()

    def test_tampered_statement(self):
        sk = SigningKey.generate()
        attestation = self._make_attestation("mem-001", sk, "original")
        attestation["statement"] = "tampered"  # Modify after signing
        valid, msg = verify_signed_attestation(attestation, sk.verify_key)
        assert valid is False

    def test_wrong_version(self):
        valid, msg = verify_signed_attestation(
            {"version": 99, "type": "signed_attestation"}, SigningKey.generate().verify_key
        )
        assert valid is False
        assert "version" in msg.lower()

    def test_wrong_type(self):
        valid, msg = verify_signed_attestation(
            {"version": 1, "type": "other"}, SigningKey.generate().verify_key
        )
        assert valid is False
        assert "type" in msg.lower()
