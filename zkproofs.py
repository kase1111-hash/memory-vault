# memory_vault/zkproofs.py
"""
Zero-Knowledge Proofs for Memory Vault.

Provides mechanisms to prove memory existence without revealing content.
Uses commitment schemes and Merkle proofs for cryptographic verification.
"""

import sqlite3
import hashlib
import json
import base64
from datetime import datetime, timezone
from typing import Tuple

from nacl.signing import SigningKey, VerifyKey

from .db import DB_PATH


def _double_sha256(data: bytes) -> str:
    """Bitcoin-style double SHA256 hash."""
    h = hashlib.sha256(data).digest()
    return hashlib.sha256(h).hexdigest()


def generate_existence_commitment(memory_id: str) -> dict:
    """
    Generate a commitment that proves a memory exists without revealing its content.

    The commitment includes:
    - Memory ID hash (not the raw ID)
    - Content hash (already stored, proves content without revealing)
    - Timestamp proof
    - Classification level (public metadata)

    Args:
        memory_id: The memory to create commitment for

    Returns:
        dict: Commitment data that can be shared publicly
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        SELECT memory_id, content_hash, created_at, classification, tombstoned
        FROM memories WHERE memory_id = ?
    """, (memory_id,))
    row = c.fetchone()

    if not row:
        conn.close()
        raise ValueError(f"Memory '{memory_id}' not found")

    memory_id_db, content_hash, created_at, classification, tombstoned = row

    if tombstoned:
        conn.close()
        raise ValueError("Cannot create commitment for tombstoned memory")

    conn.close()

    # Create commitment components
    # Memory ID is hashed so the actual ID is not revealed
    memory_id_commitment = _double_sha256(memory_id.encode())

    # Timestamp commitment (proves memory existed before this time)
    timestamp_commitment = _double_sha256(created_at.encode())

    # Combined commitment hash
    combined = f"{memory_id_commitment}|{content_hash}|{timestamp_commitment}|{classification}"
    commitment_hash = _double_sha256(combined.encode())

    commitment = {
        "version": 1,
        "type": "existence_proof",
        "commitment_hash": commitment_hash,
        "memory_id_commitment": memory_id_commitment,
        "content_hash": content_hash,  # SHA256 of plaintext
        "timestamp_commitment": timestamp_commitment,
        "classification": classification,
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
        "verification_hint": "Verify with original memory_id, created_at timestamp"
    }

    return commitment


def verify_existence_commitment(
    commitment: dict,
    memory_id: str,
    created_at: str
) -> Tuple[bool, str]:
    """
    Verify an existence commitment against known memory details.

    The verifier must have access to:
    - The original memory_id
    - The created_at timestamp

    Args:
        commitment: The commitment dict from generate_existence_commitment
        memory_id: The claimed memory ID
        created_at: The claimed creation timestamp

    Returns:
        Tuple of (is_valid: bool, message: str)
    """
    if commitment.get("version") != 1:
        return False, "Unknown commitment version"

    if commitment.get("type") != "existence_proof":
        return False, "Invalid commitment type"

    # Verify memory ID commitment
    expected_memory_id_commitment = _double_sha256(memory_id.encode())
    if commitment.get("memory_id_commitment") != expected_memory_id_commitment:
        return False, "Memory ID does not match commitment"

    # Verify timestamp commitment
    expected_timestamp_commitment = _double_sha256(created_at.encode())
    if commitment.get("timestamp_commitment") != expected_timestamp_commitment:
        return False, "Timestamp does not match commitment"

    # Verify combined hash
    combined = (
        f"{commitment['memory_id_commitment']}|"
        f"{commitment['content_hash']}|"
        f"{commitment['timestamp_commitment']}|"
        f"{commitment['classification']}"
    )
    expected_commitment_hash = _double_sha256(combined.encode())
    if commitment.get("commitment_hash") != expected_commitment_hash:
        return False, "Commitment hash verification failed"

    return True, "Commitment verified successfully"


def generate_content_proof(memory_id: str, content_hash_claim: str) -> dict:
    """
    Generate a proof that a specific content hash matches a memory.

    This allows proving you know what content a memory contains
    without revealing the actual content.

    Args:
        memory_id: The memory to prove
        content_hash_claim: SHA256 hash of the claimed content

    Returns:
        dict: Proof data
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        SELECT content_hash, classification, tombstoned
        FROM memories WHERE memory_id = ?
    """, (memory_id,))
    row = c.fetchone()

    if not row:
        conn.close()
        raise ValueError(f"Memory '{memory_id}' not found")

    stored_hash, classification, tombstoned = row
    conn.close()

    if tombstoned:
        raise ValueError("Cannot create proof for tombstoned memory")

    # Check if claim matches
    matches = (stored_hash == content_hash_claim)

    # Create proof
    proof = {
        "version": 1,
        "type": "content_proof",
        "memory_id_commitment": _double_sha256(memory_id.encode()),
        "claimed_hash": content_hash_claim,
        "matches": matches,
        "classification": classification,
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z"
    }

    # Sign the proof
    # Note: In production, this would use the vault's signing key
    proof_data = json.dumps({k: v for k, v in proof.items() if k != "signature"}, sort_keys=True)
    proof["proof_hash"] = _double_sha256(proof_data.encode())

    return proof


def generate_time_bound_proof(memory_id: str, before_timestamp: str) -> dict:
    """
    Generate a proof that a memory existed before a specific time.

    This is useful for proving prior art, establishing timelines, etc.

    Args:
        memory_id: The memory to prove
        before_timestamp: ISO timestamp to prove existence before

    Returns:
        dict: Time-bound proof
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        SELECT created_at, content_hash, classification, tombstoned
        FROM memories WHERE memory_id = ?
    """, (memory_id,))
    row = c.fetchone()

    if not row:
        conn.close()
        raise ValueError(f"Memory '{memory_id}' not found")

    created_at, content_hash, classification, tombstoned = row
    conn.close()

    if tombstoned:
        raise ValueError("Cannot create proof for tombstoned memory")

    # Parse timestamps
    created_dt = datetime.fromisoformat(created_at.rstrip("Z"))
    before_dt = datetime.fromisoformat(before_timestamp.rstrip("Z"))

    existed_before = created_dt < before_dt

    proof = {
        "version": 1,
        "type": "time_bound_proof",
        "memory_id_commitment": _double_sha256(memory_id.encode()),
        "content_hash": content_hash,
        "before_timestamp": before_timestamp,
        "existed_before": existed_before,
        "classification": classification,
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z"
    }

    # Create verifiable hash
    proof_data = json.dumps({k: v for k, v in proof.items() if k != "proof_hash"}, sort_keys=True)
    proof["proof_hash"] = _double_sha256(proof_data.encode())

    return proof


def generate_signed_attestation(
    memory_id: str,
    signing_key: SigningKey,
    statement: str
) -> dict:
    """
    Generate a signed attestation about a memory.

    The attestation is cryptographically signed by the vault owner,
    proving they vouch for the statement about the memory.

    Args:
        memory_id: The memory being attested
        signing_key: Ed25519 signing key
        statement: Natural language statement being attested

    Returns:
        dict: Signed attestation
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        SELECT content_hash, classification, created_at, tombstoned
        FROM memories WHERE memory_id = ?
    """, (memory_id,))
    row = c.fetchone()

    if not row:
        conn.close()
        raise ValueError(f"Memory '{memory_id}' not found")

    content_hash, classification, created_at, tombstoned = row
    conn.close()

    if tombstoned:
        raise ValueError("Cannot create attestation for tombstoned memory")

    attestation = {
        "version": 1,
        "type": "signed_attestation",
        "memory_id_commitment": _double_sha256(memory_id.encode()),
        "content_hash": content_hash,
        "classification": classification,
        "statement": statement,
        "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
        "signer_public_key": base64.b64encode(signing_key.verify_key.encode()).decode()
    }

    # Create message to sign
    message = json.dumps(dict(attestation.items()), sort_keys=True).encode()

    # Sign the attestation
    signed = signing_key.sign(message)
    attestation["signature"] = base64.b64encode(signed.signature).decode()

    return attestation


def verify_signed_attestation(attestation: dict, verify_key: VerifyKey) -> Tuple[bool, str]:
    """
    Verify a signed attestation.

    Args:
        attestation: The attestation dict
        verify_key: Ed25519 verification key

    Returns:
        Tuple of (is_valid: bool, message: str)
    """
    if attestation.get("version") != 1:
        return False, "Unknown attestation version"

    if attestation.get("type") != "signed_attestation":
        return False, "Invalid attestation type"

    try:
        # Reconstruct message (without signature)
        attest_copy = {k: v for k, v in attestation.items() if k != "signature"}
        message = json.dumps(attest_copy, sort_keys=True).encode()

        # Verify signature
        signature = base64.b64decode(attestation["signature"])
        verify_key.verify(message, signature)

        return True, f"Attestation verified: {attestation.get('statement', '')}"

    except Exception as e:
        return False, f"Signature verification failed: {e}"
