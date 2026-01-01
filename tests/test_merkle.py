"""
Tests for Merkle tree operations.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from merkle import hash_leaf, hash_node, build_tree, verify_proof


class TestMerkleTree:
    """Test Merkle tree construction and verification."""

    def test_hash_leaf_deterministic(self):
        """Verify leaf hashing is deterministic."""
        data = b"test data for hashing"
        hash1 = hash_leaf(data)
        hash2 = hash_leaf(data)
        assert hash1 == hash2

    def test_hash_leaf_different_data(self):
        """Verify different data produces different hashes."""
        hash1 = hash_leaf(b"data one")
        hash2 = hash_leaf(b"data two")
        assert hash1 != hash2

    def test_hash_node_combines_children(self):
        """Verify node hash combines left and right children."""
        left = hash_leaf(b"left child")
        right = hash_leaf(b"right child")
        parent = hash_node(left, right)

        # Parent should be different from children
        assert parent != left
        assert parent != right

        # Should be deterministic
        parent2 = hash_node(left, right)
        assert parent == parent2

    def test_hash_node_order_matters(self):
        """Verify order of children affects hash."""
        left = hash_leaf(b"left")
        right = hash_leaf(b"right")

        hash1 = hash_node(left, right)
        hash2 = hash_node(right, left)

        assert hash1 != hash2

    def test_build_tree_single_leaf(self):
        """Verify tree with single leaf."""
        leaves = [hash_leaf(b"only leaf")]
        root, proofs = build_tree(leaves)

        assert root is not None
        assert root == leaves[0]  # Single leaf is the root

    def test_build_tree_multiple_leaves(self):
        """Verify tree with multiple leaves."""
        leaves = [
            hash_leaf(b"leaf 1"),
            hash_leaf(b"leaf 2"),
            hash_leaf(b"leaf 3"),
            hash_leaf(b"leaf 4"),
        ]
        root, proofs = build_tree(leaves)

        assert root is not None
        assert len(proofs) == len(leaves)

    def test_verify_proof_valid(self):
        """Verify valid proof passes verification."""
        leaves = [
            hash_leaf(b"leaf 1"),
            hash_leaf(b"leaf 2"),
            hash_leaf(b"leaf 3"),
            hash_leaf(b"leaf 4"),
        ]
        root, proofs = build_tree(leaves)

        # Verify each leaf's proof
        for i, leaf in enumerate(leaves):
            assert verify_proof(leaf, root, proofs[i]) is True

    def test_verify_proof_invalid_leaf(self):
        """Verify proof fails for wrong leaf."""
        leaves = [
            hash_leaf(b"leaf 1"),
            hash_leaf(b"leaf 2"),
        ]
        root, proofs = build_tree(leaves)

        # Wrong leaf should fail
        wrong_leaf = hash_leaf(b"wrong leaf")
        assert verify_proof(wrong_leaf, root, proofs[0]) is False

    def test_verify_proof_invalid_root(self):
        """Verify proof fails for wrong root."""
        leaves = [
            hash_leaf(b"leaf 1"),
            hash_leaf(b"leaf 2"),
        ]
        root, proofs = build_tree(leaves)

        # Wrong root should fail
        wrong_root = hash_leaf(b"wrong root")
        assert verify_proof(leaves[0], wrong_root, proofs[0]) is False

    def test_build_tree_empty(self):
        """Verify tree with no leaves."""
        root, proofs = build_tree([])
        assert root is None
        assert proofs == {}

    def test_build_tree_odd_leaves(self):
        """Verify tree handles odd number of leaves."""
        leaves = [
            hash_leaf(b"leaf 1"),
            hash_leaf(b"leaf 2"),
            hash_leaf(b"leaf 3"),
        ]
        root, proofs = build_tree(leaves)

        assert root is not None
        # All proofs should be valid
        for i, leaf in enumerate(leaves):
            assert verify_proof(leaf, root, proofs[i]) is True
