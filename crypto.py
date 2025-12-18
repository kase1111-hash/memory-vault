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
