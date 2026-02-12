# Memory Vault Integration Guide

**Date:** February 2026
**Status:** Updated for v0.2.0-alpha refocus

This document covers integration guides for the Memory Vault system: Boundary Daemon, IntentLog, Physical Tokens (experimental), and Dead-Man Switch (experimental).

---

## Table of Contents

1. [Boundary Daemon Integration](#1-boundary-daemon-integration)
2. [IntentLog Integration](#2-intentlog-integration)
3. [Physical Token Integration (Level 5)](#3-physical-token-integration-level-5) (experimental)
4. [Encrypted Release to Heirs (Dead-Man Switch)](#4-encrypted-release-to-heirs-dead-man-switch) (experimental)

---

## 1. Boundary Daemon Integration

The Boundary Daemon (`boundary-daemon` from the Agent-OS ecosystem) is the runtime environment guardian. It enforces operational modes (e.g., ONLINE, OFFLINE, AIRGAP, COLDROOM) and validates safety conditions before allowing sensitive operations.

### Role of the Boundary Daemon

- Monitors network status, attached devices, user presence, etc.
- Exposes a Unix socket API at `api/boundary.sock` (configurable)
- Answers permission queries like `check_recall` with:

```json
{"permitted": true/false, "reason": "string"}
```

### Implementation

**boundary.py:**

```python
import socket
import json
import os

SOCKET_PATH = os.path.expanduser("~/.agent-os/api/boundary.sock")

def check_recall(classification: int) -> tuple[bool, str]:
    """
    Query the boundary-daemon for recall permission.
    Returns (permitted: bool, reason: str)
    """
    request = {
        "command": "check_recall",
        "params": {"memory_class": classification}
    }

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(SOCKET_PATH)
            s.sendall(json.dumps(request).encode('utf-8') + b'\n')
            response_data = s.recv(4096).decode('utf-8')
            response = json.loads(response_data)
            permitted = response.get("permitted", False)
            reason = response.get("reason", "No reason provided")
            return permitted, reason
    except FileNotFoundError:
        return False, "Boundary daemon socket not found (offline/airgap mode?)"
    except ConnectionRefusedError:
        return False, "Boundary daemon not running"
    except socket.timeout:
        return False, "Boundary daemon timeout"
    except Exception as e:
        return False, f"Boundary daemon error: {str(e)}"
```

### Classification → Boundary Policy Mapping

| Vault Level | Typical Boundary Requirement | Example Daemon Response |
|-------------|------------------------------|------------------------|
| 0–2 | Usually permitted | `{"permitted": true}` |
| 3 | Offline preferred | Deny if network detected |
| 4 | AIRGAP or COLDROOM | Deny if any network/USB |
| 5 | COLDROOM + physical presence | Strictest checks |

### Daemon-Side Example Policy

```json
{
  "recall_policy": {
    "3": {"require_offline": true},
    "4": {"require_airgap": true},
    "5": {"require_mode": "COLDROOM", "require_user_presence": true}
  }
}
```

### Testing the Integration

```bash
# Start boundary-daemon in permissive mode
boundary-daemon --mode ONLINE

# Recall low-level memory → succeeds
# Switch daemon to AIRGAP
boundary-daemon --mode AIRGAP

# Recall level 4 memory → denied with reason
memory-vault recall <id>
# → Recall failed: Boundary check failed: Network interface active in AIRGAP mode
```

### Fallback Behavior

If the daemon is not running or socket missing:
- All recalls are safely denied
- Reason clearly logged
- Enforces "fail-closed" security

---

## 2. IntentLog Integration

The Memory Vault serves as the secure, auditable, classification-bound persistence layer for IntentLog — ensuring that high-value intent references, failed paths, heuristics, and root secrets are stored with appropriate sovereignty guarantees.

### Why Integrate?

- IntentLog tracks agent intent, outcomes, and lessons learned
- Many entries are low-value (transient) → fine in plain synth-mind memory
- High-value entries (root keys, recovery seeds, critical heuristics) must be protected by Memory Vault's gates

### Integration Strategy

**Dual Persistence Model:**
- Low-value intent log entries → synth-mind's existing `memory.db`
- High-value entries → Memory Vault via `intent_ref` linkage

**intent_ref Field:**
- Every MemoryObject has an optional `intent_ref: str`
- UUID or identifier from your IntentLog system
- Enables bidirectional linking: IntentLog → Vault memory ID

### Code Example

```python
from memory_vault.vault import MemoryVault
from memory_vault.models import MemoryObject
from uuid import uuid4

vault = MemoryVault()

def store_critical_intent(
    content: bytes,
    classification: int,
    intent_id: str,
    metadata: dict,
    cooldown_seconds: int = 0
):
    """
    Store a high-value intent artifact in the Memory Vault.
    Returns vault memory_id for linking.
    """
    obj = MemoryObject(
        memory_id=str(uuid4()),
        content_plaintext=content,
        classification=classification,
        encryption_profile="default-passphrase",
        intent_ref=intent_id,
        access_policy={"cooldown_seconds": cooldown_seconds},
        value_metadata=metadata | {"source": "IntentLog", "intent_id": intent_id}
    )
    vault.store_memory(obj)
    print(f"Critical intent {intent_id} secured in Vault as {obj.memory_id}")
    return obj.memory_id


def recall_critical_intent(memory_id: str, justification: str) -> bytes:
    """Recall with full Vault gates."""
    return vault.recall_memory(memory_id, justification=justification)
```

### Recommended Classification Mapping

| IntentLog Type | Vault Level | Justification Required | Cooldown |
|----------------|-------------|------------------------|----------|
| Transient goal/outcome | None (synth-mind only) | No | No |
| Learned heuristic | 1–2 | No | No |
| Failed path lesson | 2 | No | No |
| Long-term goal / principle | 3 | Yes | Optional |
| Recovery seed / root key | 5 | Yes + strong justification | 30+ days |
| Master encryption key | 5 (TPM profile) | Yes + boundary check | 90+ days |

### Audit & Forensics

```bash
# Find all IntentLog-related recalls
memory-vault search-justifications "IntentLog"

# Verify entire audit trail
memory-vault verify-integrity
```

---

## 3. Physical Token Integration (Level 5)

Level 5 memories represent the highest classification — existential secrets (root keys, dead-man switches, final recovery seeds). Recall requires explicit physical presence via a hardware security token.

### Design Principles

- **Multi-factor physical presence:** "Something you have" (token) + "something you know" (PIN) + "something you are" (human approval)
- **Fail-closed:** No token = no recall
- **Standard protocols:** Challenge-response using HMAC-SHA1 (FIDO2/U2F fallback compatible)
- **Supported devices:** YubiKey, Nitrokey, OnlyKey, any U2F/FIDO2/HOTP/TOTP device
- **No plaintext key storage:** Token never exposes private key

### Implementation (physical_token.py)

```python
import os
import hmac
import hashlib
import struct
import time
from typing import Optional

try:
    from fido2.hid import CtapHidDevice
    from fido2.client import Fido2Client
    FIDO2_AVAILABLE = True
except ImportError:
    FIDO2_AVAILABLE = False

try:
    import pyotp
    OTP_AVAILABLE = True
except ImportError:
    OTP_AVAILABLE = False

TOKEN_CHALLENGE_PATH = os.path.expanduser("~/.memory_vault/token_challenge")

def require_physical_token(justification: str = "") -> bool:
    """
    Enforce physical token presence for Level 5 recall.
    Returns True only if token successfully responds.
    """
    print("[Level 5] Physical security token required. Insert token and touch button if needed.")

    # Preference order: FIDO2 > Challenge-Response (YubiKey HMAC) > TOTP/HOTP
    if FIDO2_AVAILABLE and _fido2_challenge():
        print("FIDO2 token authenticated")
        return True

    if _hmac_challenge_response():
        print("HMAC challenge-response token authenticated")
        return True

    if OTP_AVAILABLE and _otp_challenge():
        print("OTP token authenticated")
        return True

    print("Physical token authentication failed")
    return False
```

### Setup Instructions

**FIDO2 (Recommended - YubiKey 5, Nitrokey 3):**
```bash
pip install fido2
```

**HMAC Challenge-Response (YubiKey):**
```bash
ykman hmac-secret 1 ~/.memory_vault/token_challenge --generate
```

**TOTP Fallback:**
```bash
python -c "import pyotp, os; secret = pyotp.random_base32(); open(os.path.expanduser('~/.memory_vault/totp_secret'), 'w').write(secret); print('TOTP Secret:', secret)"
```

### Recall Flow for Level 5

1. Boundary daemon check → must be COLDROOM/AIRGAP
2. Human approval prompt
3. Cooldown check
4. Physical token insertion + touch/PIN
5. Decryption (TPM-sealed if used)
6. Full audit log + signed Merkle root

### Example Usage

```bash
memory-vault recall abc123-def456 --justification "Final system recovery"
# → Boundary: OK (COLDROOM)
# → Human: Approve? yes
# → Cooldown: OK
# → [Level 5] Insert token and touch...
# → Token authenticated
# → Content decrypted
```

---

## 4. Encrypted Release to Heirs (Dead-Man Switch)

The Encrypted Release to Heirs feature enables secure, automatic delivery of designated Level 5 memories to trusted recipients upon trigger.

Payload is pre-encrypted for each recipient using their public key (age / x25519), ensuring:
- Only intended recipients can decrypt
- No plaintext ever leaves the vault prematurely
- Full forward secrecy and deniability until release

### Core Features

- Recipient public key registration
- Per-recipient encrypted payloads stored in vault
- Trigger releases encrypted blobs (external monitor delivers)
- Zero-knowledge to vault — vault never sees recipient private keys
- Audit-logged release event

### Implementation (deadman.py additions)

```python
from nacl.public import Box, SealedBox
from nacl.encoding import Base64Encoder
import base64

def add_heir(name: str, public_key_b64: str):
    """Register a trusted heir with their public key"""
    try:
        pubkey = base64.b64decode(public_key_b64)
        SealedBox(pubkey)  # Validate key
    except:
        print("Invalid public key")
        return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO dms_heirs (name, public_key_b64) VALUES (?, ?)",
              (name, public_key_b64))
    conn.commit()
    conn.close()
    print(f"Heir '{name}' added")


def get_heir_release_packages() -> list[dict]:
    """Return encrypted payloads for delivery on trigger"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""SELECT name, public_key_b64, encrypted_payload, memory_ids
                 FROM dms_heirs WHERE encrypted_payload IS NOT NULL""")
    results = []
    for name, pubkey, enc_blob, mids_json in c.fetchall():
        if enc_blob:
            results.append({
                "heir": name,
                "public_key": pubkey,
                "encrypted_payload_b64": base64.b64encode(enc_blob).decode(),
                "memory_ids": json.loads(mids_json) if mids_json else []
            })
    conn.close()
    return results
```

### Recipient Key Generation

Heirs generate keys with `age`:
```bash
# Heir generates keypair
age-keygen -o heir-key.txt

# Public key → send to owner
cat heir-key.txt | grep "public key:" | awk '{print $4}'
```

### Workflow

**1. Owner adds heirs:**
```bash
memory-vault dms-heir-add "Alice" age1ql3...
memory-vault dms-heir-add "Legal Trust" age1xyz...
```

**2. Arm DMS with payload:**
```bash
memory-vault dms-arm 180 --memory-ids root-seed-1,recovery-key-2 --justification "Succession plan"
```

**3. Encrypt payload for heirs:**
```bash
memory-vault dms-encrypt-payload
```

**4. On trigger → external monitor runs:**
```bash
if memory-vault dms-status | grep TRIGGERED; then
  memory-vault dms-release-packages
  # Deliver .json files to heirs via secure channel
fi
```

**5. Heir decrypts:**
```bash
age -d -i heir-key.txt dms-release-alice.json
```

### Security Achieved

- Recipient-only decryption
- No private keys in vault
- Payload encrypted at rest
- Full audit trail of encryption and release
- Physical token required for arming and encryption

---

## Summary

| Component | Purpose | Status |
|-----------|---------|--------|
| Boundary Daemon | Environmental security enforcement | Production |
| IntentLog | Secure persistence for high-value intents | Production |
| Physical Tokens | Level 5 physical presence requirement | Experimental |
| Heir Release | Secure succession and dead-man switches | Experimental |
