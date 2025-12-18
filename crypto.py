import nacl.secret
import nacl.utils
import nacl.pwhash
import hashlib

def derive_key_from_passphrase(passphrase: str, salt: bytes = None) -> tuple[bytes, bytes]:
    if salt is None:
        salt = nacl.utils.random(nacl.pwhash.SALTBYTES)
    key = nacl.pwhash.argon2id.kdf(
        nacl.secret.SecretBox.KEY_SIZE,
        passphrase.encode(),
        salt,
        opslimit=nacl.pwhash.OPSLIMIT_SENSITIVE,
        memlimit=nacl.pwhash.MEMLIMIT_SENSITIVE
    )
    return key, salt

def encrypt_memory(key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    box = nacl.secret.SecretBox(key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    ciphertext = box.encrypt(plaintext, nonce)
    return ciphertext, nonce, ciphertext  # Last is placeholder; separate if needed

def decrypt_memory(key: bytes, ciphertext: bytes) -> bytes:
    box = nacl.secret.SecretBox(key)
    return box.decrypt(ciphertext)
