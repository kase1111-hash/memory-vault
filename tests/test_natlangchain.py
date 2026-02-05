"""
Tests for natlangchain.py - NatLangChain data structures and client.

Tests dataclasses and client initialization without a running server.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from natlangchain import (
    NatLangEntry,
    ChainProof,
    NatLangChainClient,
    anchor_memory_to_chain,
    verify_memory_anchor,
    get_memory_chain_history,
)


class TestNatLangEntry:
    """Test NatLangEntry dataclass."""

    def test_basic_creation(self):
        entry = NatLangEntry(content="Test entry", author="test-user")
        assert entry.content == "Test entry"
        assert entry.author == "test-user"
        assert entry.intent_type == "memory_vault_record"
        assert entry.metadata == {}
        assert entry.timestamp  # Should be auto-set

    def test_custom_fields(self):
        entry = NatLangEntry(
            content="Custom",
            author="agent",
            intent_type="effort_receipt_mp02",
            metadata={"key": "value"},
        )
        assert entry.intent_type == "effort_receipt_mp02"
        assert entry.metadata["key"] == "value"

    def test_to_dict(self):
        entry = NatLangEntry(content="test", author="user")
        d = entry.to_dict()
        assert d["content"] == "test"
        assert d["author"] == "user"
        assert "timestamp" in d
        assert "metadata" in d

    def test_content_hash_deterministic(self):
        entry = NatLangEntry(
            content="same content",
            author="same author",
            timestamp="2025-01-01T00:00:00Z",
        )
        h1 = entry.content_hash()
        h2 = entry.content_hash()
        assert h1 == h2

    def test_content_hash_changes_with_content(self):
        e1 = NatLangEntry(content="A", author="x", timestamp="2025-01-01")
        e2 = NatLangEntry(content="B", author="x", timestamp="2025-01-01")
        assert e1.content_hash() != e2.content_hash()

    def test_content_hash_is_sha256(self):
        entry = NatLangEntry(content="test", author="user", timestamp="2025-01-01")
        h = entry.content_hash()
        assert len(h) == 64
        int(h, 16)  # Valid hex


class TestChainProof:
    """Test ChainProof dataclass."""

    def test_creation(self):
        proof = ChainProof(
            entry_id="entry-001",
            block_hash="abc123",
            block_height=42,
            merkle_proof=["hash1", "hash2"],
            timestamp="2025-01-15T10:00:00Z",
        )
        assert proof.entry_id == "entry-001"
        assert proof.block_height == 42
        assert len(proof.merkle_proof) == 2

    def test_to_dict(self):
        proof = ChainProof(
            entry_id="e1", block_hash="bh", block_height=1,
            merkle_proof=[], timestamp="now",
        )
        d = proof.to_dict()
        assert d["entry_id"] == "e1"
        assert d["block_height"] == 1


class TestNatLangChainClient:
    """Test client initialization and request building."""

    def test_default_init(self):
        client = NatLangChainClient()
        assert client.timeout == 30
        assert "localhost" in client.api_url or "NATLANGCHAIN_API_URL" in os.environ

    def test_custom_init(self):
        client = NatLangChainClient(api_url="http://chain:9000/", timeout=10)
        assert client.api_url == "http://chain:9000"  # Trailing slash stripped
        assert client.timeout == 10

    def test_health_check_no_server(self):
        client = NatLangChainClient(api_url="http://localhost:19999", timeout=1)
        assert client.health_check() is False

    def test_get_version_no_server(self):
        client = NatLangChainClient(api_url="http://localhost:19999", timeout=1)
        assert client.get_version() == "unknown"

    def test_request_connection_error(self):
        client = NatLangChainClient(api_url="http://localhost:19999", timeout=1)
        with pytest.raises(ConnectionError):
            client._request("GET", "/test")

    @patch("natlangchain.NatLangChainClient._request")
    def test_add_entry(self, mock_request):
        mock_request.return_value = {"entry_id": "eid-001", "status": "pending"}
        client = NatLangChainClient()
        entry = NatLangEntry(content="test", author="user")
        result = client.add_entry(entry)
        assert result["entry_id"] == "eid-001"

    @patch("natlangchain.NatLangChainClient._request")
    def test_get_entry(self, mock_request):
        mock_request.return_value = {"entry_id": "eid-001", "content": "test"}
        client = NatLangChainClient()
        result = client.get_entry("eid-001")
        assert result["entry_id"] == "eid-001"

    @patch("natlangchain.NatLangChainClient._request")
    def test_search_entries(self, mock_request):
        mock_request.return_value = {"entries": [{"entry_id": "e1"}]}
        client = NatLangChainClient()
        results = client.search_entries(query="test")
        assert len(results) == 1

    @patch("natlangchain.NatLangChainClient._request")
    def test_mine_pending(self, mock_request):
        mock_request.return_value = {"block_hash": "abc", "height": 5}
        client = NatLangChainClient()
        result = client.mine_pending()
        assert result["height"] == 5

    @patch("natlangchain.NatLangChainClient._request")
    def test_get_inclusion_proof_included(self, mock_request):
        mock_request.return_value = {
            "included": True,
            "block_hash": "bh",
            "block_height": 3,
            "merkle_proof": ["p1"],
            "timestamp": "now",
        }
        client = NatLangChainClient()
        proof = client.get_inclusion_proof("eid-001")
        assert proof is not None
        assert proof.block_height == 3

    @patch("natlangchain.NatLangChainClient._request")
    def test_get_inclusion_proof_not_included(self, mock_request):
        mock_request.return_value = {"included": False}
        client = NatLangChainClient()
        proof = client.get_inclusion_proof("eid-001")
        assert proof is None


class TestAnchorFunctions:
    """Test module-level anchor helper functions."""

    @patch("natlangchain.NatLangChainClient.add_entry")
    def test_anchor_memory_to_chain_success(self, mock_add):
        mock_add.return_value = {"entry_id": "chain-001"}
        result = anchor_memory_to_chain(
            memory_id="mem-001",
            content_hash="abc123",
            classification=2,
        )
        assert result == "chain-001"

    @patch("natlangchain.NatLangChainClient.add_entry")
    def test_anchor_memory_to_chain_failure(self, mock_add):
        mock_add.side_effect = ConnectionError("no server")
        result = anchor_memory_to_chain(
            memory_id="mem-001",
            content_hash="abc123",
            classification=2,
        )
        assert result is None

    @patch("natlangchain.NatLangChainClient.search_entries")
    @patch("natlangchain.NatLangChainClient.get_inclusion_proof")
    def test_verify_memory_anchor_found(self, mock_proof, mock_search):
        mock_search.return_value = [{"entry_id": "e1", "timestamp": "now"}]
        mock_proof.return_value = ChainProof(
            entry_id="e1", block_hash="bh", block_height=5,
            merkle_proof=[], timestamp="now",
        )
        result = verify_memory_anchor("mem-001")
        assert result is not None
        assert result["verified"] is True

    @patch("natlangchain.NatLangChainClient.search_entries")
    def test_verify_memory_anchor_not_found(self, mock_search):
        mock_search.return_value = []
        result = verify_memory_anchor("mem-001")
        assert result is None

    @patch("natlangchain.NatLangChainClient.search_entries")
    def test_get_memory_chain_history(self, mock_search):
        mock_search.return_value = [{"entry_id": "e1"}, {"entry_id": "e2"}]
        result = get_memory_chain_history("mem-001")
        assert len(result) == 2

    @patch("natlangchain.NatLangChainClient.search_entries")
    def test_get_memory_chain_history_failure(self, mock_search):
        mock_search.side_effect = ConnectionError("fail")
        result = get_memory_chain_history("mem-001")
        assert result == []
