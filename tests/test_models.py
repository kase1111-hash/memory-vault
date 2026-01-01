"""
Tests for data models.
"""
import os
import sys
import pytest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import MemoryObject, EncryptionProfile, RecallRequest


class TestMemoryObject:
    """Test MemoryObject dataclass."""

    def test_create_memory_object(self):
        """Verify MemoryObject can be created with required fields."""
        memory = MemoryObject(
            memory_id="test-123",
            content_plaintext=b"test content",
            classification=2,
            encryption_profile="default",
        )

        assert memory.memory_id == "test-123"
        assert memory.content_plaintext == b"test content"
        assert memory.classification == 2
        assert memory.encryption_profile == "default"

    def test_memory_object_defaults(self):
        """Verify MemoryObject has sensible defaults."""
        memory = MemoryObject(
            memory_id="test-456",
            content_plaintext=b"content",
            classification=1,
            encryption_profile="profile",
        )

        # Optional fields should have defaults
        assert memory.intent_ref is None
        assert memory.value_metadata is None
        assert memory.access_policy is None

    def test_memory_object_with_metadata(self):
        """Verify MemoryObject accepts metadata."""
        metadata = {
            "source": "test",
            "importance": "high",
            "tags": ["unit", "test"]
        }

        memory = MemoryObject(
            memory_id="test-meta",
            content_plaintext=b"content with metadata",
            classification=3,
            encryption_profile="profile",
            value_metadata=metadata,
        )

        assert memory.value_metadata == metadata
        assert memory.value_metadata["importance"] == "high"

    def test_memory_object_with_access_policy(self):
        """Verify MemoryObject accepts access policy."""
        policy = {
            "cooldown_seconds": 3600,
            "require_justification": True,
        }

        memory = MemoryObject(
            memory_id="test-policy",
            content_plaintext=b"protected content",
            classification=4,
            encryption_profile="secure",
            access_policy=policy,
        )

        assert memory.access_policy["cooldown_seconds"] == 3600

    def test_classification_range(self):
        """Verify classification accepts values 0-5."""
        for level in range(6):
            memory = MemoryObject(
                memory_id=f"level-{level}",
                content_plaintext=b"content",
                classification=level,
                encryption_profile="profile",
            )
            assert memory.classification == level


class TestEncryptionProfile:
    """Test EncryptionProfile dataclass."""

    def test_create_encryption_profile(self):
        """Verify EncryptionProfile can be created."""
        profile = EncryptionProfile(
            profile_id="my-profile",
            cipher="AES-256-GCM",
            key_source="HumanPassphrase",
        )

        assert profile.profile_id == "my-profile"
        assert profile.cipher == "AES-256-GCM"
        assert profile.key_source == "HumanPassphrase"

    def test_encryption_profile_defaults(self):
        """Verify EncryptionProfile has sensible defaults."""
        profile = EncryptionProfile(
            profile_id="test-profile",
            cipher="AES-256-GCM",
            key_source="KeyFile",
        )

        assert profile.rotation_policy == "manual"
        assert profile.exportable is False

    def test_encryption_profile_exportable(self):
        """Verify EncryptionProfile can be set as exportable."""
        profile = EncryptionProfile(
            profile_id="export-profile",
            cipher="AES-256-GCM",
            key_source="HumanPassphrase",
            exportable=True,
        )

        assert profile.exportable is True

    def test_key_sources(self):
        """Verify different key sources are accepted."""
        sources = ["HumanPassphrase", "KeyFile", "TPM"]

        for source in sources:
            profile = EncryptionProfile(
                profile_id=f"{source.lower()}-profile",
                cipher="AES-256-GCM",
                key_source=source,
            )
            assert profile.key_source == source


class TestRecallRequest:
    """Test RecallRequest dataclass."""

    def test_create_recall_request(self):
        """Verify RecallRequest can be created."""
        request = RecallRequest(
            memory_id="mem-123",
            requester="human",
            justification="Need to access for review",
        )

        assert request.memory_id == "mem-123"
        assert request.requester == "human"
        assert request.justification == "Need to access for review"

    def test_recall_request_defaults(self):
        """Verify RecallRequest has sensible defaults."""
        request = RecallRequest(
            memory_id="mem-456",
            requester="agent",
            justification="Automated recall",
        )

        assert request.approved is False
        assert request.request_id is not None

    def test_recall_request_approved(self):
        """Verify RecallRequest can be marked approved."""
        request = RecallRequest(
            memory_id="mem-789",
            requester="human",
            justification="Emergency access",
            approved=True,
        )

        assert request.approved is True
