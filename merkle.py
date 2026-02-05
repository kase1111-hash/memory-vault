# memory_vault/merkle.py

import hashlib
import json
from typing import List, Tuple, Optional, Union

def hash_leaf(data: Union[bytes, str]) -> str:
    """Double SHA256 for Merkle leaf (Bitcoin-style)."""
    if isinstance(data, str):
        data = data.encode()
    h = hashlib.sha256(data).digest()
    return hashlib.sha256(h).hexdigest()

def hash_node(left: str, right: str) -> str:
    """Hash concatenation of two child nodes."""
    data = left + right
    return hashlib.sha256(hashlib.sha256(data.encode()).digest()).hexdigest()

def build_tree(leaves: List[str]) -> Tuple[Optional[str], dict]:
    """
    Build Merkle tree and return (root, proof_map).
    proof_map[i] = list of sibling hashes needed to verify leaf i against the root.
    """
    if not leaves:
        return None, {}

    n = len(leaves)
    if n == 1:
        return leaves[0], {0: []}

    # Per-original-leaf proof paths
    proofs = {i: [] for i in range(n)}
    # Track which original leaf indices each current-level node represents
    current_level = list(leaves)
    current_members = [[i] for i in range(n)]

    while len(current_level) > 1:
        next_level = []
        next_members = []

        for i in range(0, len(current_level), 2):
            left = current_level[i]
            left_members = current_members[i]

            if i + 1 < len(current_level):
                right = current_level[i + 1]
                right_members = current_members[i + 1]
            else:
                right = left  # Duplicate for odd count
                right_members = []

            # Sort children before hashing to match verify_proof's sorted concatenation
            if int(left, 16) <= int(right, 16):
                parent = hash_node(left, right)
            else:
                parent = hash_node(right, left)
            next_level.append(parent)

            # Each original leaf in the left subtree needs the right sibling
            for idx in left_members:
                proofs[idx].append(right)
            # Each original leaf in the right subtree needs the left sibling
            for idx in right_members:
                proofs[idx].append(left)

            next_members.append(left_members + right_members)

        current_level = next_level
        current_members = next_members

    return current_level[0], proofs

def verify_proof(leaf_hash: str, root_hash: str, proof: List[str]) -> bool:
    """Verify a leaf belongs to the tree using sibling proofs."""
    current = leaf_hash
    for sibling in proof:
        data = current + sibling if int(current, 16) <= int(sibling, 16) else sibling + current
        current = hashlib.sha256(hashlib.sha256(data.encode()).digest()).hexdigest()
    return current == root_hash

# Helper to rebuild entire tree from DB (for integrity check)
def rebuild_merkle_tree(conn) -> Tuple[str, dict]:
    c = conn.cursor()
    c.execute("SELECT leaf_hash FROM merkle_leaves ORDER BY leaf_id")
    leaves = [row[0] for row in c.fetchall()]
    if not leaves:
        return None, {}
    root, proofs = build_tree(leaves)
    proof_map = {i: proofs[i] for i in range(len(leaves))}
    return root, proof_map
