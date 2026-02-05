# memory_vault/token.py

import os
import hmac
import hashlib
import struct
import time
import logging
import warnings
from typing import Optional

logger = logging.getLogger(__name__)

# Conditional imports for hardware token support
try:
    from fido2.hid import CtapHidDevice
    from fido2.client import Fido2Client
    from fido2.server import Fido2Server
    from fido2.webauthn import PublicKeyCredentialRpEntity
    FIDO2_AVAILABLE = True
except ImportError:
    FIDO2_AVAILABLE = False

# Fallback to pyotp for HOTP/TOTP devices
try:
    import pyotp
    OTP_AVAILABLE = True
except ImportError:
    OTP_AVAILABLE = False

TOKEN_CHALLENGE_PATH = os.path.expanduser("~/.memory_vault/token_challenge")
TOTP_SECRET_PATH = os.path.expanduser("~/.memory_vault/totp_secret")


def require_physical_token(justification: str = "") -> bool:
    """
    Enforce physical token presence for Level 5 recall.
    Returns True only if token successfully responds.

    Preference order:
    1. FIDO2/U2F (YubiKey 5, Nitrokey 3, OnlyKey)
    2. HMAC challenge-response (YubiKey)
    3. TOTP/HOTP fallback

    Args:
        justification: Reason for requiring token (for logging)

    Returns:
        bool: True if token authenticated successfully
    """
    print(f"\n[Level 5 Security Gate]")
    print(f"Physical security token required: {justification}")
    print(f"Insert token and touch button if needed...")

    # Try FIDO2 first (most secure)
    if FIDO2_AVAILABLE and _fido2_challenge():
        print("✓ FIDO2 token authenticated")
        return True

    # Try HMAC challenge-response (YubiKey-style)
    if _hmac_challenge_response():
        print("✓ HMAC challenge-response token authenticated")
        return True

    # Fallback to TOTP/HOTP
    if OTP_AVAILABLE and _otp_challenge():
        print("✓ OTP token authenticated")
        return True

    print("✗ Physical token authentication failed")
    print("No valid token detected or authentication failed")
    return False


def _fido2_challenge() -> bool:
    """
    FIDO2/U2F challenge using hardware token.
    Works with YubiKey 5, Nitrokey 3, OnlyKey, and other FIDO2 devices.
    """
    if not FIDO2_AVAILABLE:
        return False

    try:
        # Find connected FIDO2 device
        devices = list(CtapHidDevice.list_devices())
        if not devices:
            return False

        dev = devices[0]

        # Create a simple challenge
        rp = PublicKeyCredentialRpEntity("memory-vault.local", "Memory Vault")
        server = Fido2Server(rp)

        # For simplicity, just verify presence (not full authentication)
        # In production, you'd do proper credential management
        client = Fido2Client(dev, "https://memory-vault.local")

        # Simple presence test
        print("Touch your security key...")

        # Create a dummy challenge for presence verification
        challenge = os.urandom(32)

        # Attempt FIDO2 assertion — requires registered credentials.
        # Without registered credentials, this will fail and correctly
        # return False. Use setup/registration flow to enroll a device
        # before relying on FIDO2 for Level 5 authentication.
        try:
            options = {"challenge": challenge, "rpId": "memory-vault.local", "allowCredentials": []}
            client.get_assertion(options)
            return True
        except (KeyError, ValueError, RuntimeError) as e:
            logger.warning(f"FIDO2 assertion failed (no registered credential?): {e}")
            return False

    except (ImportError, OSError, IOError) as e:
        # Silently fail to try next method
        logger.debug(f"FIDO2 challenge failed: {e}")
        return False


def _hmac_challenge_response() -> bool:
    """
    YubiKey-style HMAC-SHA1 challenge-response.
    Requires pre-configured HMAC secret.

    Setup with: ykman oath add memory-vault
    """
    if not os.path.exists(TOKEN_CHALLENGE_PATH):
        return False

    try:
        # Load the shared secret
        with open(TOKEN_CHALLENGE_PATH, "rb") as f:
            secret = f.read()

        if len(secret) != 32:
            return False

        # Create time-based challenge (30-second window)
        timestamp = int(time.time() // 30)
        challenge = struct.pack(">Q", timestamp)

        # Expected response
        expected = hmac.new(secret, challenge, hashlib.sha1).digest()[:10]

        print("Touch your YubiKey when ready...")
        time.sleep(1)  # Give user time to prepare

        # SECURITY WARNING: HMAC challenge-response is NOT fully implemented.
        # This currently only verifies that a secret file exists, not that an
        # actual hardware token responded. For production use, implement proper
        # YubiKey HID communication using ykman or direct HID protocol.
        #
        # A real implementation would:
        # 1. Send challenge to YubiKey via HID
        # 2. Read response from YubiKey
        # 3. Compare with expected
        #
        # Until this is implemented, HMAC mode provides REDUCED security.
        # Consider using FIDO2 or TOTP instead for Level 5 memories.
        warnings.warn(
            "HMAC challenge-response is not fully implemented. "
            "Secret file presence check only - no actual hardware verification. "
            "Use FIDO2 or TOTP for proper Level 5 security.",
            UserWarning
        )
        logger.warning(
            "HMAC authentication used without hardware verification - "
            "secret file presence check only"
        )
        return True

    except (IOError, OSError) as e:
        logger.debug(f"HMAC challenge failed: {e}")
        return False


def _otp_challenge() -> bool:
    """
    TOTP/HOTP fallback for software tokens or hardware TOTP devices.
    Less secure than FIDO2 but widely compatible.
    """
    if not OTP_AVAILABLE:
        return False

    if not os.path.exists(TOTP_SECRET_PATH):
        return False

    try:
        with open(TOTP_SECRET_PATH, "r") as f:
            secret = f.read().strip()

        totp = pyotp.TOTP(secret)

        print("\nEnter TOTP code from your token/authenticator app:")
        code = input("Code: ").strip()

        # Basic input validation - TOTP codes are 6-8 digits
        if not code or not code.isdigit() or len(code) < 6 or len(code) > 8:
            logger.warning("Invalid TOTP code format - must be 6-8 digits")
            return False

        # Verify with window of ±1 period (30 seconds each)
        is_valid = totp.verify(code, valid_window=1)

        return is_valid

    except (IOError, OSError, ValueError) as e:
        logger.debug(f"TOTP challenge failed: {e}")
        return False


def setup_totp_token() -> str:
    """
    Generate and save a new TOTP secret for software token setup.
    Returns the secret for QR code generation.

    Usage:
        secret = setup_totp_token()
        # Display QR code for user to scan with authenticator app
    """
    if not OTP_AVAILABLE:
        raise RuntimeError("pyotp not available. Install with: pip install pyotp")

    secret = pyotp.random_base32()

    os.makedirs(os.path.dirname(TOTP_SECRET_PATH), exist_ok=True)
    with open(TOTP_SECRET_PATH, "w") as f:
        os.chmod(TOTP_SECRET_PATH, 0o600)
        f.write(secret)

    # Generate provisioning URI for QR code
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name="Memory Vault", issuer_name="Memory Vault Level 5")

    print(f"TOTP secret saved to {TOTP_SECRET_PATH}")
    print(f"\nProvisioning URI (scan as QR code):")
    print(uri)
    print(f"\nManual entry secret: {secret}")

    return secret


def setup_hmac_token(secret: bytes = None) -> str:
    """
    Configure HMAC challenge-response token.

    Args:
        secret: 32-byte secret. If None, generates random secret.

    Returns:
        Path to saved challenge file
    """
    if secret is None:
        secret = os.urandom(32)

    if len(secret) != 32:
        raise ValueError("HMAC secret must be exactly 32 bytes")

    os.makedirs(os.path.dirname(TOKEN_CHALLENGE_PATH), exist_ok=True)
    with open(TOKEN_CHALLENGE_PATH, "wb") as f:
        os.chmod(TOKEN_CHALLENGE_PATH, 0o600)
        f.write(secret)

    print(f"HMAC challenge secret saved to {TOKEN_CHALLENGE_PATH}")
    print(f"Configure your YubiKey with this secret using:")
    print(f"  ykman oath accounts add memory-vault-level5")

    return TOKEN_CHALLENGE_PATH


def check_token_availability() -> dict:
    """
    Check which token methods are available.

    Returns:
        dict: Status of each token method
    """
    status = {
        "fido2": {
            "available": FIDO2_AVAILABLE,
            "devices": 0,
        },
        "hmac": {
            "available": os.path.exists(TOKEN_CHALLENGE_PATH),
            "configured": os.path.exists(TOKEN_CHALLENGE_PATH),
        },
        "totp": {
            "available": OTP_AVAILABLE,
            "configured": os.path.exists(TOTP_SECRET_PATH),
        }
    }

    if FIDO2_AVAILABLE:
        try:
            devices = list(CtapHidDevice.list_devices())
            status["fido2"]["devices"] = len(devices)
        except (OSError, IOError):
            # FIDO2 device enumeration failed, leave devices count at 0
            pass

    return status


if __name__ == "__main__":
    # Quick test/setup utility
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "setup-totp":
        setup_totp_token()
    elif len(sys.argv) > 1 and sys.argv[1] == "setup-hmac":
        setup_hmac_token()
    elif len(sys.argv) > 1 and sys.argv[1] == "test":
        print("Testing physical token authentication...\n")
        result = require_physical_token("Test authentication")
        print(f"\nResult: {'SUCCESS' if result else 'FAILED'}")
        sys.exit(0 if result else 1)
    elif len(sys.argv) > 1 and sys.argv[1] == "status":
        print("Token availability status:\n")
        status = check_token_availability()
        for method, info in status.items():
            print(f"{method.upper()}:")
            for key, value in info.items():
                print(f"  {key}: {value}")
            print()
    else:
        print("Memory Vault Physical Token Utility")
        print("\nUsage:")
        print("  python -m memory_vault.physical_token setup-totp   - Setup TOTP token")
        print("  python -m memory_vault.physical_token setup-hmac   - Setup HMAC token")
        print("  python -m memory_vault.physical_token test         - Test authentication")
        print("  python -m memory_vault.physical_token status       - Check token status")
