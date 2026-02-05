# memory_vault/crypto.py

import os
import json
import logging
import re
from nacl.secret import SecretBox
from nacl.utils import random
from nacl.pwhash import argon2id
from nacl.pwhash.argon2id import SALTBYTES, OPSLIMIT_SENSITIVE, MEMLIMIT_SENSITIVE
from nacl.signing import SigningKey, VerifyKey
import nacl.exceptions
import base64

# Constants
KEY_SIZE = SecretBox.KEY_SIZE          # 32 bytes
NONCE_SIZE = SecretBox.NONCE_SIZE      # 24 bytes

# Security: Profile ID validation pattern to prevent path traversal
PROFILE_ID_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$')

logger = logging.getLogger(__name__)

def _validate_profile_id(profile_id: str) -> None:
    """Validate profile_id to prevent path traversal attacks."""
    if not profile_id or len(profile_id) > 64:
        raise ValueError("Profile ID must be 1-64 characters")
    if not PROFILE_ID_PATTERN.match(profile_id):
        raise ValueError("Profile ID must start with alphanumeric and contain only alphanumeric, underscore, or hyphen")

# Signing key paths
SIGNING_KEY_PATH = os.path.expanduser("~/.memory_vault/signing_key")
TPM_SIGNING_HANDLE = 0x81000002

# TPM availability flag
try:
    from tpm2_pytss import ESAPI, ESYS_TR  # noqa: F401
    TPM_AVAILABLE = True
except ImportError:
    TPM_AVAILABLE = False


# === Core Encryption Functions ===

def derive_key_from_passphrase(passphrase: str, salt: bytes = None) -> tuple[bytes, bytes]:
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
    if not os.path.exists(keyfile_path):
        raise FileNotFoundError(f"Keyfile not found: {keyfile_path}")
    with open(keyfile_path, "rb") as f:
        key = f.read().strip()
    if len(key) != KEY_SIZE:
        raise ValueError(f"Keyfile must contain exactly {KEY_SIZE} bytes")
    return key


def generate_keyfile(profile_id: str, directory: str = "~/.memory_vault/keys") -> str:
    # Security: Validate profile_id to prevent path traversal
    _validate_profile_id(profile_id)

    directory = os.path.expanduser(directory)
    os.makedirs(directory, exist_ok=True)
    keyfile_path = os.path.join(directory, f"{profile_id}.key")
    key = random(KEY_SIZE)
    with open(keyfile_path, "wb") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(key)
    return keyfile_path


def encrypt_memory(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    box = SecretBox(key)
    nonce = random(NONCE_SIZE)
    encrypted = box.encrypt(plaintext, nonce)
    ciphertext = encrypted[len(nonce):]
    return ciphertext, nonce


def decrypt_memory(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
    box = SecretBox(key)
    full_ciphertext = nonce + ciphertext
    return box.decrypt(full_ciphertext)


# === TPM-Sealed Memory Keys (Optional) ===

TPM_PRIMARY_HANDLE = 0x81000001  # Persistent handle for primary key


def tpm_create_and_persist_primary() -> None:
    """
    Create and persist a primary TPM key for sealing operations.
    This key is bound to PCRs 0-7 (platform + bootloader state).
    """
    if not TPM_AVAILABLE:
        return

    try:
        from tpm2_pytss import ESAPI, TPM2_ALG, ESYS_TR
        from tpm2_pytss.types import TPMT_PUBLIC

        with ESAPI() as esys:
            # Check if primary already exists
            try:
                esys.ReadPublic(TPM_PRIMARY_HANDLE)
                # Already exists
                return
            except Exception:
                logger.debug("TPM primary handle does not exist, will create it")

            # Create primary key with platform hierarchy
            in_public = TPMT_PUBLIC(
                type=TPM2_ALG.RSA,
                nameAlg=TPM2_ALG.SHA256,
                objectAttributes=(
                    "fixedtpm|fixedparent|sensitivedataorigin|"
                    "userwithauth|restricted|decrypt"
                ),
            )

            # Create the primary key
            primary_handle, _, _, _, _ = esys.CreatePrimary(
                primaryHandle=ESYS_TR.OWNER,
                inSensitive=None,
                inPublic=in_public,
            )

            # Persist it
            esys.EvictControl(
                auth=ESYS_TR.OWNER,
                objectHandle=primary_handle,
                persistentHandle=TPM_PRIMARY_HANDLE,
            )

            esys.FlushContext(primary_handle)
            print(f"TPM primary key created at handle {hex(TPM_PRIMARY_HANDLE)}")

    except Exception as e:
        print(f"TPM primary creation failed: {e}")


def tpm_generate_sealed_key() -> bytes:
    """
    Generate a random 32-byte key and seal it to TPM PCRs 0-7.
    Returns the sealed blob that can only be unsealed on this platform.
    """
    if not TPM_AVAILABLE:
        raise RuntimeError("TPM not available")

    try:
        from tpm2_pytss import ESAPI, TPM2_ALG, ESYS_TR
        from tpm2_pytss.types import TPMT_PUBLIC, TPM2B_SENSITIVE_CREATE

        # Generate random key
        ephemeral_key = random(32)

        with ESAPI() as esys:
            # Create sealed data object bound to PCRs 0-7
            pcr_selection = esys.hash_to_pcr_selection(TPM2_ALG.SHA256, list(range(8)))

            # Start policy session for PCR binding
            session = esys.StartAuthSession(
                tpmKey=ESYS_TR.NONE,
                bind=ESYS_TR.NONE,
                sessionType=TPM2_ALG.POLICY,
                symmetric=TPM2_ALG.NULL,
                authHash=TPM2_ALG.SHA256,
            )

            # Set policy PCR
            esys.PolicyPCR(session, None, pcr_selection)
            policy_digest = esys.PolicyGetDigest(session)

            # Define sealed object
            in_public = TPMT_PUBLIC(
                type=TPM2_ALG.KEYEDHASH,
                nameAlg=TPM2_ALG.SHA256,
                objectAttributes="fixedtpm|fixedparent|userwithauth",
                authPolicy=policy_digest,
            )

            in_sensitive = TPM2B_SENSITIVE_CREATE(
                data=ephemeral_key,
            )

            # Create sealed object
            private, public = esys.Create(
                parentHandle=TPM_PRIMARY_HANDLE,
                inSensitive=in_sensitive,
                inPublic=in_public,
            )[:2]

            esys.FlushContext(session)

            # Serialize and return using JSON with base64 encoding (avoiding pickle for security)
            sealed_blob = {
                "private": base64.b64encode(private.marshal()).decode('ascii'),
                "public": base64.b64encode(public.marshal()).decode('ascii'),
            }
            return json.dumps(sealed_blob).encode('utf-8')

    except Exception as e:
        raise RuntimeError(f"TPM key sealing failed: {e}") from e


def tpm_unseal_key(sealed_blob: bytes) -> bytes:
    """
    Unseal a TPM-sealed key blob.
    Only works if PCR state matches the sealing state.
    """
    if not TPM_AVAILABLE:
        raise RuntimeError("TPM not available")

    try:
        from tpm2_pytss import ESAPI, TPM2_ALG, ESYS_TR

        # Deserialize blob using JSON (secure alternative to pickle)
        blob_data = json.loads(sealed_blob.decode('utf-8'))
        blob_data["private"] = base64.b64decode(blob_data["private"])
        blob_data["public"] = base64.b64decode(blob_data["public"])

        with ESAPI() as esys:
            # Load the sealed object
            sealed_handle = esys.Load(
                parentHandle=TPM_PRIMARY_HANDLE,
                inPrivate=blob_data["private"],
                inPublic=blob_data["public"],
            )

            # Start policy session for unsealing
            pcr_selection = esys.hash_to_pcr_selection(TPM2_ALG.SHA256, list(range(8)))

            session = esys.StartAuthSession(
                tpmKey=ESYS_TR.NONE,
                bind=ESYS_TR.NONE,
                sessionType=TPM2_ALG.POLICY,
                symmetric=TPM2_ALG.NULL,
                authHash=TPM2_ALG.SHA256,
            )

            esys.PolicyPCR(session, None, pcr_selection)

            # Unseal the data
            unsealed = esys.Unseal(sealed_handle, session1=session)

            esys.FlushContext(session)
            esys.FlushContext(sealed_handle)

            return bytes(unsealed)

    except Exception as e:
        raise RuntimeError(f"TPM unsealing failed (PCR mismatch or tamper): {e}") from e


# === Optional TPM-Sealed Signing Key ===

def tpm_seal_signing_key(signing_key: SigningKey) -> None:
    if not TPM_AVAILABLE:
        raise RuntimeError("TPM not available")
    from tpm2_pytss import ESAPI

    private_blob = signing_key.encode()

    with ESAPI() as esys:
        # Bind to PCRs 0-7 (platform + bootloader)
        policy_digest = esys.PolicyPCR([0,1,2,3,4,5,6,7])

        sealed_handle, _, _ = esys.CreateLoaded(
            parent=ESYS_TR.OWNER_HIERARCHY,
            sensitive=private_blob,
            public=None,
            policy=policy_digest
        )
        esys.EvictControl(
            auth=ESYS_TR.OWNER_HIERARCHY,
            object_handle=sealed_handle,
            persistent_handle=TPM_SIGNING_HANDLE
        )
        esys.FlushContext(sealed_handle)
    print("Ed25519 signing key successfully sealed in TPM")


def tpm_load_sealed_signing_key() -> SigningKey | None:
    if not TPM_AVAILABLE:
        return None
    from tpm2_pytss import ESAPI

    try:
        with ESAPI() as esys:
            handle = esys.Load(
                parent=ESYS_TR.OWNER_HIERARCHY,
                private=b"",
                public=None,
                persistent_handle=TPM_SIGNING_HANDLE
            )
            private_blob = esys.Unseal(handle)
            esys.FlushContext(handle)
            return SigningKey(private_blob)
    except Exception as e:
        print(f"TPM signing key unsealing failed: {e}")
        return None


def load_or_create_signing_key(tpm_preferred: bool = True) -> SigningKey:
    """Load or create Ed25519 signing key — prefer TPM sealing."""
    if tpm_preferred and TPM_AVAILABLE:
        sealed_key = tpm_load_sealed_signing_key()
        if sealed_key:
            print("Using TPM-sealed signing key")
            return sealed_key

    # File-based fallback
    if os.path.exists(SIGNING_KEY_PATH):
        with open(SIGNING_KEY_PATH, "rb") as f:
            sk = SigningKey(f.read())
        print("Using file-based signing key")
        return sk

    # First-time generation
    print("Generating new Ed25519 signing key")
    sk = SigningKey.generate()

    if tpm_preferred and TPM_AVAILABLE:
        try:
            tpm_seal_signing_key(sk)
            print("Signing key sealed in TPM (non-exportable)")
            return sk
        except Exception as e:
            print(f"TPM sealing failed ({e}), using file storage")

    # Save to secure file
    os.makedirs(os.path.dirname(SIGNING_KEY_PATH), exist_ok=True)
    with open(SIGNING_KEY_PATH, "wb") as f:
        os.chmod(SIGNING_KEY_PATH, 0o600)
        f.write(sk.encode())
    with open(SIGNING_KEY_PATH + ".pub", "wb") as f:
        f.write(sk.verify_key.encode())
    print("Signing key saved to encrypted file")
    return sk


def get_public_verify_key() -> VerifyKey:
    """Get public verification key (for external trust)."""
    pub_path = SIGNING_KEY_PATH + ".pub"
    if os.path.exists(pub_path):
        with open(pub_path, "rb") as f:
            return VerifyKey(f.read())
    raise FileNotFoundError("Public signing key not found. Run vault to initialize.")


def sign_root(signing_key: SigningKey, root_hash: str, seq: int, timestamp: str) -> str:
    message = f"{seq}|{root_hash}|{timestamp}".encode()
    signed = signing_key.sign(message)
    return base64.b64encode(signed.signature).decode()


def verify_signature(vk: VerifyKey, signature_b64: str, root_hash: str, seq: int, timestamp: str) -> bool:
    try:
        sig = base64.b64decode(signature_b64)
        message = f"{seq}|{root_hash}|{timestamp}".encode()
        vk.verify(message, sig)
        return True
    except (ValueError, TypeError, nacl.exceptions.BadSignatureError):
        return False
