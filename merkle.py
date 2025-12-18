# memory_vault/merkle.py

import hashlib
import json
from typing import List, Tuple, Optional

def hash_leaf(data: str) -> str:
    """Double SHA256 for Merkle leaf (Bitcoin-style)."""
    h = hashlib.sha256(data.encode()).digest()
    return hashlib.sha256(h).hexdigest()

def hash_node(left: str, right: str) -> str:
    """Hash concatenation of two child nodes."""
    data = left + right
    return hashlib.sha256(hashlib.sha256(data.encode()).digest()).hexdigest()

def build_tree(leaves: List[str]) -> Tuple[str, List[List[str]]]:
    """
    Build Merkle tree and return (root, proof_map)
    proof_map[i] = list of sibling hashes needed to prove leaf i
    """
    if not leaves:
        return hash_leaf(""), []

    n = len(leaves)
    tree = leaves[:]
    proofs = [[] for _ in leaves]

    # Bottom-up construction
    level = 0
    while n > 1:
        new_level = []
        new_proofs = [[] for _ in range((n + 1) // 2)]
        for i in range(0, n, 2):
            left = tree[i]
            right = tree[i + 1] if i + 1 < n else left  # Duplicate for odd
            parent = hash_node(left, right)
            new_level.append(parent)

            # Record sibling for proofs
            if i + 1 < n:
                proofs[i].append(right)
                proofs[i + 1].append(left)
            else:
                proofs[i].append(left)  # Duplicate sibling

        # Propagate previous proofs up
        for j, proof_list in enumerate(proofs[:n]):
            new_proofs[j // 2].extend(proof_list)

        tree = new_level
        proofs = new_proofs
        n = len(tree)
        level += 1

    return tree[0], proofs

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
        return hash_leaf(""), {}
    root, proofs = build_tree(leaves)
    proof_map = {i: proofs[i] for i in range(len(leaves))}
    return root, proof_map
