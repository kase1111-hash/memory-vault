# memory_vault/crypto.py

import os
from nacl.secret import SecretBox
from nacl.utils import random
from nacl.pwhash import argon2id
from nacl.pwhash.argon2id import SALTBYTES, OPSLIMIT_SENSITIVE, MEMLIMIT_SENSITIVE

# Constants
KEY_SIZE = SecretBox.KEY_SIZE          # 32 bytes
NONCE_SIZE = SecretBox.NONCE_SIZE      # 24 bytes


def derive_key_from_passphrase(passphrase: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    Derive a cryptographic key from a human passphrase using Argon2id.
    If salt is None, generates a new random salt.
    Returns (key, salt)
    """
    if salt is None:
        salt = random(SALTBYTES)

    key = argon2id.kdf(
        size=KEY_SIZE,
        password=passphrase.encode('utf-8'),
        salt=salt,
        opslimit=OPSLIMIT_SENSITIVE,
        memlimit=MEMLIMIT_SENSITIVE
    )
    return key, salt


def load_key_from_file(keyfile_path: str) -> bytes:
    """
    Load a raw encryption key from a file.
    Ensures the key is exactly KEY_SIZE bytes.
    """
    if not os.path.exists(keyfile_path):
        raise FileNotFoundError(f"Keyfile not found: {keyfile_path}")

    with open(keyfile_path, "rb") as f:
        key = f.read()

    key = key.strip()  # Remove any whitespace/newlines
    if len(key) != KEY_SIZE:
        raise ValueError(f"Keyfile must contain exactly {KEY_SIZE} bytes (got {len(key)})")

    return key


def generate_keyfile(profile_id: str, directory: str = "~/.memory_vault/keys") -> str:
    """
    Generate a new random 32-byte key and securely save it to a file.
    Creates directory if needed and sets permissions to 0600.
    Returns the full path to the created keyfile.
    """
    directory = os.path.expanduser(directory)
    os.makedirs(directory, exist_ok=True)
    keyfile_path = os.path.join(directory, f"{profile_id}.key")

    key = random(KEY_SIZE)

    with open(keyfile_path, "wb") as f:
        os.fchmod(f.fileno(), 0o600)  # Secure permissions before writing
        f.write(key)

    return keyfile_path


def encrypt_memory(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-256-GCM (via libsodium SecretBox).
    Returns (ciphertext, nonce) — nonce is stored separately.
    """
    box = SecretBox(key)
    nonce = random(NONCE_SIZE)
    encrypted = box.encrypt(plaintext, nonce)
    ciphertext = encrypted[len(nonce):]  # Remove nonce from ciphertext
    return ciphertext, nonce


def decrypt_memory(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
    """
    Decrypt ciphertext using the provided key and nonce.
    Reconstructs full encrypted message before decryption.
    """
    box = SecretBox(key)
    full_ciphertext = nonce + ciphertext
    return box.decrypt(full_ciphertext)
