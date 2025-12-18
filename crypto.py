# memory_vault/crypto.py

# ... existing imports ...
from typing import Optional

# New optional import for TPM support
try:
    from tpm2_pytss import TPM2, ESYS_TR, TPM2_TPMU_PUBLIC_PARMS, TPM2_ALG_ERROR
    from tpm2_pytss.policy import Policy
    _TPM_AVAILABLE = True
except ImportError:
    _TPM_AVAILABLE = False

def ensure_tpm_available():
    if not _TPM_AVAILABLE:
        raise RuntimeError("TPM support not available: tpm2-pytss library not installed")

# TPM persistent handle for our primary key (fixed for simplicity)
TPM_PERSISTENT_HANDLE = 0x81000001

def tpm_create_and_persist_primary() -> None:
    """
    Create and persist a primary key in the TPM if not already present.
    Uses default SRK template (ECC or RSA depending on TPM).
    """
    ensure_tpm_available()
    from tpm2_pytss import ESAPI

    with ESAPI() as esys:
        try:
            # Try to load existing
            esys.ReadPublic(ESYS_TR.from_int(TPM_PERSISTENT_HANDLE))
            print("TPM primary key already exists.")
            return
        except TPM2_ALG_ERROR:
            pass  # Not found

        # Create primary (default template)
        primary_handle, _, _, _, _ = esys.CreatePrimary(
            ESYS_TR.OWNER_HIERARCHY,
            b"",  # No auth
            sensitive=None,
            public=None,  # Use default
            outside_info=b"",
            creation_pcr=[],
            persistent_handle=TPM_PERSISTENT_HANDLE
        )
        esys.FlushContext(primary_handle)
        print("TPM primary key created and persisted.")

def tpm_generate_sealed_key() -> bytes:
    """
    Generate a new symmetric key and seal it inside the TPM under PCR 0-7.
    Returns the sealed blob (to store in DB).
    """
    ensure_tpm_available()
    from tpm2_pytss import ESAPI, TPM2B_DATA, TPM2B_ENCRYPTED_SECRET

    key = random(KEY_SIZE)

    with ESAPI() as esys:
        # Policy: PCR 0-7 must match current boot state
        policy = Policy()
        policy.pcr(0, 7)  # PCRs 0-7

        sealed_handle, _, _ = esys.CreateLoaded(
            TPM_PERSISTENT_HANDLE,
            b"",
            sensitive=TPM2B_DATA(key),
            public=None,
            policy=policy.digest
        )
        sealed_blob = esys.ReadPublic(sealed_handle)[1]  # public area contains sealed data
        esys.FlushContext(sealed_handle)

    return sealed_blob

def tpm_unseal_key(sealed_blob: bytes) -> bytes:
    """
    Unseal a previously sealed key blob from the TPM.
    Fails if PCRs don't match (i.e., boot state changed).
    """
    ensure_tpm_available()
    from tpm2_pytss import ESAPI

    with ESAPI() as esys:
        # Load the sealed object
        handle, _, _ = esys.Load(TPM_PERSISTENT_HANDLE, b"", sealed_blob)
        try:
            unsealed = esys.Unseal(handle)
            return bytes(unsealed)
        finally:
            esys.FlushContext(handle)
            # memory_vault/crypto.py (add at bottom)

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder
import base64

SIGNING_KEY_PATH = os.path.expanduser("~/.memory_vault/signing_key")

def generate_signing_keypair() -> tuple[bytes, bytes]:
    """Generate Ed25519 keypair."""
    sk = SigningKey.generate()
    return sk.encode(), sk.verify_key.encode()

def load_or_create_signing_key(tpm_preferred: bool = True) -> SigningKey:
    """Load or create signing key, prefer TPM sealing if available."""
    if TPM_AVAILABLE:
        try:
            # Try to seal signing key in TPM
            sealed = tpm_load_sealed_signing_key()
            if sealed:
                return SigningKey(sealed)
        except:
            pass  # Fall back to file

    # File-based fallback
    if os.path.exists(SIGNING_KEY_PATH):
        with open(SIGNING_KEY_PATH, "rb") as f:
            sk_bytes = f.read()
        return SigningKey(sk_bytes)

    print("Generating new signing keypair (file-based)")
    sk_bytes, vk_bytes = generate_signing_keypair()
    os.makedirs(os.path.dirname(SIGNING_KEY_PATH), exist_ok=True)
    with open(SIGNING_KEY_PATH, "wb") as f:
        os.chmod(SIGNING_KEY_PATH, 0o600)
        f.write(sk_bytes)
    with open(SIGNING_KEY_PATH + ".pub", "wb") as f:
        f.write(vk_bytes)
    return SigningKey(sk_bytes)

def get_public_verify_key() -> VerifyKey:
    pub_path = SIGNING_KEY_PATH + ".pub"
    if os.path.exists(pub_path):
        with open(pub_path, "rb") as f:
            return VerifyKey(f.read())
    # For TPM, would export attestation public key (future)
    raise FileNotFoundError("Public key not found. Run vault once to generate.")

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
    except:
        return False
