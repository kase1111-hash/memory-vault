# memory_vault/escrow.py
"""
Escrowed Keys - Shamir's Secret Sharing for Memory Vault.

This module provides third-party key escrow using Shamir's Secret Sharing Scheme (SSSS).
Keys are split into N shards, where any K shards (threshold) can reconstruct the original.

This is distinct from the dead-man switch:
- Dead-man switch: Automatic release after owner incapacitation
- Escrow: Quorum-based recovery requiring multiple parties to cooperate

Use cases:
- Corporate key recovery (e.g., 3 of 5 executives)
- Estate planning with multiple heirs
- Regulatory compliance (auditor + legal + owner)
"""

import sqlite3
import os
import uuid
import secrets
import base64
import re
from datetime import datetime, timezone
from typing import List, Tuple

from nacl.public import SealedBox, PublicKey

from .db import DB_PATH
from .crypto import derive_key_from_passphrase

# Security: Profile ID validation pattern to prevent path traversal
_PROFILE_ID_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$')

def _validate_profile_id(profile_id: str) -> None:
    """Validate profile_id to prevent path traversal attacks."""
    if not profile_id or len(profile_id) > 64:
        raise ValueError("Profile ID must be 1-64 characters")
    if not _PROFILE_ID_PATTERN.match(profile_id):
        raise ValueError("Profile ID must start with alphanumeric and contain only alphanumeric, underscore, or hyphen")


# Shamir's Secret Sharing implementation
# Using finite field arithmetic over GF(256)

# Irreducible polynomial for GF(256): x^8 + x^4 + x^3 + x + 1 = 0x11B
_GF256_EXP = [0] * 512
_GF256_LOG = [0] * 256


def _init_gf256_tables():
    """Initialize GF(256) lookup tables for fast arithmetic."""
    x = 1
    for i in range(255):
        _GF256_EXP[i] = x
        _GF256_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11B
    for i in range(255, 512):
        _GF256_EXP[i] = _GF256_EXP[i - 255]


_init_gf256_tables()


def _gf256_mul(a: int, b: int) -> int:
    """Multiply two elements in GF(256)."""
    if a == 0 or b == 0:
        return 0
    return _GF256_EXP[_GF256_LOG[a] + _GF256_LOG[b]]


def _gf256_div(a: int, b: int) -> int:
    """Divide a by b in GF(256)."""
    if b == 0:
        raise ZeroDivisionError("Division by zero in GF(256)")
    if a == 0:
        return 0
    return _GF256_EXP[(_GF256_LOG[a] - _GF256_LOG[b]) % 255]


def _evaluate_polynomial(coefficients: List[int], x: int) -> int:
    """Evaluate polynomial at x in GF(256)."""
    result = 0
    for coef in reversed(coefficients):
        result = _gf256_mul(result, x) ^ coef
    return result


def _lagrange_interpolate(points: List[Tuple[int, int]], x: int = 0) -> int:
    """
    Lagrange interpolation in GF(256) to find f(x).
    points = [(x1, y1), (x2, y2), ...]
    """
    result = 0
    for i, (xi, yi) in enumerate(points):
        term = yi
        for j, (xj, _) in enumerate(points):
            if i != j:
                # term *= (x - xj) / (xi - xj)
                term = _gf256_mul(term, _gf256_div(x ^ xj, xi ^ xj))
        result ^= term
    return result


def split_secret(secret: bytes, threshold: int, total_shards: int) -> List[Tuple[int, bytes]]:
    """
    Split a secret into shards using Shamir's Secret Sharing.

    Args:
        secret: The secret bytes to split
        threshold: Minimum shards needed to reconstruct (k)
        total_shards: Total number of shards to create (n)

    Returns:
        List of (shard_index, shard_data) tuples
    """
    if threshold > total_shards:
        raise ValueError("Threshold cannot exceed total shards")
    if threshold < 2:
        raise ValueError("Threshold must be at least 2")
    if total_shards > 255:
        raise ValueError("Maximum 255 shards supported")

    shards = []

    for byte_idx, secret_byte in enumerate(secret):
        # Create random polynomial with secret as constant term
        # f(0) = secret_byte, f(x) = secret_byte + a1*x + a2*x^2 + ... + a_{k-1}*x^{k-1}
        coefficients = [secret_byte] + [secrets.randbelow(256) for _ in range(threshold - 1)]

        # Evaluate polynomial at x = 1, 2, ..., n
        for shard_idx in range(1, total_shards + 1):
            if byte_idx == 0:
                shards.append((shard_idx, []))
            shards[shard_idx - 1][1].append(_evaluate_polynomial(coefficients, shard_idx))

    return [(idx, bytes(data)) for idx, data in shards]


def reconstruct_secret(shards: List[Tuple[int, bytes]]) -> bytes:
    """
    Reconstruct a secret from shards using Lagrange interpolation.

    Args:
        shards: List of (shard_index, shard_data) tuples

    Returns:
        The reconstructed secret bytes
    """
    if not shards:
        raise ValueError("No shards provided")

    # Verify all shards have same length
    shard_len = len(shards[0][1])
    if not all(len(s[1]) == shard_len for s in shards):
        raise ValueError("Shards have inconsistent lengths")

    # Reconstruct each byte
    secret = []
    for byte_idx in range(shard_len):
        points = [(idx, data[byte_idx]) for idx, data in shards]
        secret_byte = _lagrange_interpolate(points, 0)
        secret.append(secret_byte)

    return bytes(secret)


def create_escrow(
    profile_id: str,
    threshold: int,
    recipients: List[Tuple[str, str]],  # (name, public_key_b64)
    vault_passphrase: str = None
) -> str:
    """
    Create an escrowed key for a profile.

    The profile's key is split into shards and encrypted for each recipient.
    Any `threshold` recipients can cooperate to recover the key.

    Args:
        profile_id: The encryption profile to escrow
        threshold: Minimum shards needed for recovery
        recipients: List of (name, public_key_b64) tuples
        vault_passphrase: Passphrase to derive the key (for HumanPassphrase profiles)

    Returns:
        escrow_id: Unique identifier for this escrow
    """
    from .physical_token import require_physical_token

    # Security: Validate profile_id to prevent path traversal
    _validate_profile_id(profile_id)

    total_shards = len(recipients)

    if threshold > total_shards:
        raise ValueError(f"Threshold ({threshold}) cannot exceed number of recipients ({total_shards})")
    if threshold < 2:
        raise ValueError("Threshold must be at least 2")

    print("\n" + "="*50)
    print(f"KEY ESCROW: {profile_id}")
    print("="*50)
    print(f"\nRecipients: {total_shards}")
    print(f"Threshold: {threshold} of {total_shards}")
    print("\nRecipients:")
    for name, _ in recipients:
        print(f"  - {name}")

    print("\nPhysical token required for escrow creation.\n")

    if not require_physical_token("Create key escrow"):
        print("Escrow aborted: Physical token required")
        return None

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Get profile key source
    c.execute("SELECT key_source FROM encryption_profiles WHERE profile_id = ?", (profile_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise ValueError(f"Profile '{profile_id}' not found")

    key_source = row[0]

    if key_source == "TPM":
        conn.close()
        raise ValueError("TPM profiles cannot be escrowed (hardware-bound)")

    # Get the actual key
    if key_source == "HumanPassphrase":
        if not vault_passphrase:
            import getpass
            vault_passphrase = getpass.getpass(f"Enter passphrase for profile '{profile_id}': ")
        # We'll escrow the passphrase itself (or derived key)
        key, _ = derive_key_from_passphrase(vault_passphrase)
    else:  # KeyFile
        keyfile_path = os.path.expanduser(f"~/.memory_vault/keys/{profile_id}.key")
        with open(keyfile_path, "rb") as f:
            key = f.read()

    # Split the key using Shamir's
    shards = split_secret(key, threshold, total_shards)

    # Create escrow record
    escrow_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat() + "Z"

    # Encrypt each shard for its recipient
    for _, ((shard_idx, shard_data), (name, pubkey_b64)) in enumerate(zip(shards, recipients)):
        try:
            pubkey_bytes = base64.b64decode(pubkey_b64)
            pubkey = PublicKey(pubkey_bytes)
            box = SealedBox(pubkey)
            encrypted_shard = box.encrypt(shard_data)

            c.execute("""
                INSERT INTO escrow_shards
                (escrow_id, shard_index, shard_data, recipient, created_at, threshold, total_shards, profile_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (escrow_id, shard_idx, encrypted_shard, name, timestamp, threshold, total_shards, profile_id))

            print(f"  Shard {shard_idx} encrypted for {name}")

        except Exception as e:
            conn.rollback()
            conn.close()
            raise ValueError(f"Failed to encrypt shard for {name}: {e}") from e

    conn.commit()
    conn.close()

    print("\n" + "="*50)
    print("KEY ESCROW CREATED")
    print(f"  Escrow ID: {escrow_id}")
    print(f"  Profile: {profile_id}")
    print(f"  Shards: {total_shards}")
    print(f"  Threshold: {threshold}")
    print("="*50 + "\n")

    return escrow_id


def get_escrow_info(escrow_id: str) -> dict:
    """
    Get information about an escrow.

    Args:
        escrow_id: The escrow identifier

    Returns:
        dict with escrow details
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        SELECT shard_index, recipient, created_at, threshold, total_shards, profile_id
        FROM escrow_shards
        WHERE escrow_id = ?
        ORDER BY shard_index
    """, (escrow_id,))

    rows = c.fetchall()
    conn.close()

    if not rows:
        raise ValueError(f"Escrow '{escrow_id}' not found")

    return {
        "escrow_id": escrow_id,
        "profile_id": rows[0][5],
        "threshold": rows[0][3],
        "total_shards": rows[0][4],
        "created_at": rows[0][2],
        "recipients": [{"index": r[0], "name": r[1]} for r in rows]
    }


def list_escrows(profile_id: str = None) -> List[dict]:
    """
    List all escrows, optionally filtered by profile.

    Args:
        profile_id: Optional profile to filter by

    Returns:
        List of escrow summaries
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    if profile_id:
        c.execute("""
            SELECT DISTINCT escrow_id, profile_id, threshold, total_shards, created_at
            FROM escrow_shards
            WHERE profile_id = ?
        """, (profile_id,))
    else:
        c.execute("""
            SELECT DISTINCT escrow_id, profile_id, threshold, total_shards, created_at
            FROM escrow_shards
        """)

    rows = c.fetchall()
    conn.close()

    return [
        {
            "escrow_id": r[0],
            "profile_id": r[1],
            "threshold": r[2],
            "total_shards": r[3],
            "created_at": r[4]
        }
        for r in rows
    ]


def export_shard_package(escrow_id: str, recipient_name: str) -> dict:
    """
    Export an encrypted shard package for a specific recipient.

    Args:
        escrow_id: The escrow identifier
        recipient_name: Name of the recipient

    Returns:
        dict: Shard package for the recipient
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        SELECT shard_index, shard_data, threshold, total_shards, profile_id, created_at
        FROM escrow_shards
        WHERE escrow_id = ? AND recipient = ?
    """, (escrow_id, recipient_name))

    row = c.fetchone()
    conn.close()

    if not row:
        raise ValueError(f"Shard for '{recipient_name}' not found in escrow '{escrow_id}'")

    return {
        "escrow_id": escrow_id,
        "shard_index": row[0],
        "encrypted_shard": base64.b64encode(row[1]).decode(),
        "recipient": recipient_name,
        "threshold": row[2],
        "total_shards": row[3],
        "profile_id": row[4],
        "created_at": row[5],
        "instructions": (
            f"This shard is part of a {row[2]}-of-{row[3]} escrow scheme. "
            f"Decrypt with your private key, then combine with at least {row[2]-1} other shards "
            f"to recover the key for profile '{row[4]}'."
        )
    }


def recover_from_escrow(shards: List[Tuple[int, bytes]]) -> bytes:
    """
    Recover a key from decrypted shards.

    Each shard must already be decrypted by its recipient using their private key.

    Args:
        shards: List of (shard_index, decrypted_shard_data) tuples

    Returns:
        The recovered encryption key
    """
    if len(shards) < 2:
        raise ValueError("At least 2 shards required for recovery")

    print(f"\nRecovering key from {len(shards)} shards...")

    try:
        recovered_key = reconstruct_secret(shards)
        print("Key successfully recovered!")
        return recovered_key
    except Exception as e:
        raise ValueError(f"Recovery failed: {e}") from e


def delete_escrow(escrow_id: str) -> bool:
    """
    Delete an escrow and all its shards.

    Args:
        escrow_id: The escrow to delete

    Returns:
        bool: True if deleted
    """
    from .physical_token import require_physical_token

    info = get_escrow_info(escrow_id)

    print("\n" + "="*50)
    print(f"DELETE ESCROW: {escrow_id}")
    print("="*50)
    print(f"\nProfile: {info['profile_id']}")
    print(f"Shards: {info['total_shards']}")
    print("\nThis will permanently delete all shards!")
    print("Physical token required.\n")

    if not require_physical_token("Delete escrow"):
        print("Deletion aborted: Physical token required")
        return False

    confirm = input("Type 'DELETE ESCROW' to confirm: ").strip()
    if confirm != "DELETE ESCROW":
        print("Deletion aborted")
        return False

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM escrow_shards WHERE escrow_id = ?", (escrow_id,))
    conn.commit()
    conn.close()

    print(f"\nEscrow '{escrow_id}' deleted.")
    return True
