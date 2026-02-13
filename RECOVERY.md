# Memory Vault Recovery Guide

**Version:** 0.2.0-alpha
**Last Updated:** February 2026

This document explains how to recover encrypted data from Memory Vault using only written values and the PyNaCl library. **No Memory Vault code is required for recovery.**

---

## Recovery Guarantee

Memory Vault uses standard cryptographic primitives that can be implemented with just PyNaCl:

- **Encryption:** XSalsa20-Poly1305 (via PyNaCl's SecretBox)
- **Key Derivation:** Argon2id with OPSLIMIT_SENSITIVE and MEMLIMIT_SENSITIVE
- **Signing:** Ed25519 (for audit trail, not needed for decryption)

---

## Values Required for Recovery

### For HumanPassphrase Profiles

1. **Passphrase** - The password you chose (memorized or written down)
2. **Salt** - 16 bytes, stored in database `memories.salt` column (hex)
3. **Nonce** - 24 bytes, stored in database `memories.nonce` column (hex)
4. **Ciphertext** - Variable length, stored in database `memories.ciphertext` column (hex)

### For KeyFile Profiles

1. **Key** - 32 bytes from `~/.memory_vault/keys/<profile>.key` file (hex)
2. **Nonce** - 24 bytes, stored in database `memories.nonce` column (hex)
3. **Ciphertext** - Variable length, stored in database `memories.ciphertext` column (hex)

### For TPM Profiles

**WARNING:** TPM profiles are NON-RECOVERABLE by design. The encryption key is sealed to the TPM hardware and PCR state. If the TPM changes or PCRs change (firmware update, boot chain change), data is permanently lost.

---

## Extracting Values from Database

```bash
# Open the database
sqlite3 ~/.memory_vault/vault.db

# List all memories
SELECT memory_id, classification, encryption_profile,
       hex(salt), hex(nonce), hex(ciphertext)
FROM memories;

# Get specific memory
SELECT hex(salt), hex(nonce), hex(ciphertext)
FROM memories WHERE memory_id = 'your-memory-id';
```

---

## Minimal Recovery Script

This script requires ONLY Python 3 and PyNaCl (`pip install pynacl`):

```python
#!/usr/bin/env python3
"""
Memory Vault Minimal Recovery Script
No Memory Vault code required - just PyNaCl
"""
from nacl.pwhash.argon2id import kdf, OPSLIMIT_SENSITIVE, MEMLIMIT_SENSITIVE
from nacl.secret import SecretBox

# ===========================================
# PASTE YOUR VALUES HERE
# ===========================================

# For HumanPassphrase profiles:
PASSPHRASE = "your-passphrase-here"
SALT_HEX = "your-salt-hex-here"

# For KeyFile profiles, use KEY_HEX instead:
# KEY_HEX = "your-32-byte-key-hex-here"

# Always needed:
NONCE_HEX = "your-nonce-hex-here"
CIPHERTEXT_HEX = "your-ciphertext-hex-here"

# ===========================================
# RECOVERY CODE
# ===========================================

def recover_with_passphrase(passphrase, salt_hex, nonce_hex, ciphertext_hex):
    """Recover data encrypted with HumanPassphrase profile."""
    salt = bytes.fromhex(salt_hex)
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    # Derive key using Argon2id (same params as Memory Vault)
    key = kdf(
        size=32,
        password=passphrase.encode('utf-8'),
        salt=salt,
        opslimit=OPSLIMIT_SENSITIVE,
        memlimit=MEMLIMIT_SENSITIVE
    )

    # Decrypt using SecretBox (XSalsa20-Poly1305)
    box = SecretBox(key)
    plaintext = box.decrypt(nonce + ciphertext)

    return plaintext

def recover_with_keyfile(key_hex, nonce_hex, ciphertext_hex):
    """Recover data encrypted with KeyFile profile."""
    key = bytes.fromhex(key_hex)
    nonce = bytes.fromhex(nonce_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    box = SecretBox(key)
    plaintext = box.decrypt(nonce + ciphertext)

    return plaintext

# ===========================================
# RUN RECOVERY
# ===========================================

if __name__ == "__main__":
    # Choose one:

    # For HumanPassphrase:
    plaintext = recover_with_passphrase(PASSPHRASE, SALT_HEX, NONCE_HEX, CIPHERTEXT_HEX)

    # For KeyFile:
    # plaintext = recover_with_keyfile(KEY_HEX, NONCE_HEX, CIPHERTEXT_HEX)

    print("Recovered data:")
    print(plaintext.decode('utf-8', errors='replace'))
```

---

## Argon2id Parameters

Memory Vault uses these exact parameters for key derivation:

| Parameter | Value | Notes |
|-----------|-------|-------|
| Algorithm | Argon2id | Memory-hard KDF |
| Output size | 32 bytes | XSalsa20-Poly1305 key |
| Salt size | 16 bytes | Random per-memory |
| opslimit | OPSLIMIT_SENSITIVE | 4 iterations |
| memlimit | MEMLIMIT_SENSITIVE | 1GB memory |

These are the maximum security settings from libsodium/PyNaCl.

---

## Database Schema Reference

```sql
-- Memories table (contains encrypted data)
CREATE TABLE memories (
    memory_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    classification INTEGER NOT NULL,
    encryption_profile TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    ciphertext BLOB NOT NULL,      -- Encrypted content
    nonce BLOB NOT NULL,           -- 24-byte nonce
    salt BLOB,                     -- 16-byte salt (HumanPassphrase only)
    intent_ref TEXT,
    value_metadata TEXT,
    access_policy TEXT,
    audit_proof TEXT,
    sealed_blob BLOB               -- TPM-sealed key (TPM only)
);

-- Encryption profiles
CREATE TABLE encryption_profiles (
    profile_id TEXT PRIMARY KEY,
    cipher TEXT NOT NULL DEFAULT 'XSalsa20-Poly1305',
    key_source TEXT NOT NULL,      -- HumanPassphrase, KeyFile, or TPM
    rotation_policy TEXT DEFAULT 'manual',
    exportable INTEGER NOT NULL DEFAULT 0
);
```

---

## Softlock Prevention Checklist

To ensure you can always recover your data:

### For HumanPassphrase Profiles (Recommended)
- [ ] Write down your passphrase in a secure location
- [ ] Regularly backup `~/.memory_vault/vault.db`
- [ ] Test recovery procedure with a test memory

### For KeyFile Profiles
- [ ] Backup `~/.memory_vault/keys/` directory
- [ ] Write down key hex values in secure storage
- [ ] Store backups in multiple physical locations

### For TPM Profiles (High Risk)
- [ ] **DO NOT** use for irreplaceable data
- [ ] Understand that firmware updates may cause data loss
- [ ] Keep duplicate copies in non-TPM profiles

---

## Emergency Recovery Procedure

If Memory Vault code is unavailable:

1. **Install PyNaCl:**
   ```bash
   pip install pynacl
   ```

2. **Extract values from database:**
   ```bash
   sqlite3 ~/.memory_vault/vault.db "SELECT hex(salt), hex(nonce), hex(ciphertext) FROM memories WHERE memory_id='...'"
   ```

3. **Run the minimal recovery script** with your values

4. **Verify recovered data** matches the expected content

---

## Security Notes

- The salt prevents rainbow table attacks on passphrases
- The nonce ensures each encryption is unique
- Argon2id with SENSITIVE parameters makes brute-force extremely expensive
- XSalsa20-Poly1305 provides authenticated encryption (detects tampering)
- Signing keys (Ed25519) are for audit trail integrity, not needed for decryption

---

## Disclaimer

This recovery method bypasses all Memory Vault access controls (classification levels, cooldowns, human approval, physical tokens). Use only for legitimate data recovery purposes.
