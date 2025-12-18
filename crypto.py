import nacl.secret
import nacl.utils
import nacl.pwhash
import hashlib
import os
from nacl.bindings import crypto_kdf_KEYBYTES

def derive_key_from_passphrase(passphrase: str, salt: bytes = None) -> tuple[bytes, bytes]:
    if salt is None:
        salt = nacl.utils.random(nacl.pwhash.SALTBYTES)
    key = nacl.pwhash.argon2id.kdf(
        nacl.secret.SecretBox.KEY_SIZE,
        passphrase.encode('utf-8'),
        salt,
        opslimit=nacl.pwhash.OPSLIMIT_SENSITIVE,
        memlimit=nacl.pwhash.MEMLIMIT_SENSITIVE
    )
    return key, salt

def load_key_from_file(keyfile_path: str) -> bytes:
    if not os.path.exists(keyfile_path):
        raise FileNotFoundError(f"Keyfile not found: {keyfile_path}")
    raw = open(keyfile_path, "rb").read().strip()
    if len(raw) != nacl.secret.SecretBox.KEY_SIZE:
        raise ValueError(f"Keyfile must contain exactly {nacl.secret.SecretBox.KEY_SIZE} bytes")
    return raw

def encrypt_memory(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    box = nacl.secret.SecretBox(key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    ciphertext = box.encrypt(plaintext, nonce)[len(nonce):]  # Strip nonce (we store separately)
    return ciphertext, nonce

def decrypt_memory(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
    box = nacl.secret.SecretBox(key)
    full_ct = nonce + ciphertext  # Reconstruct
    return box.decrypt(full_ct)
