# memory_vault/natlangchain.py
"""
NatLangChain Integration Client

Provides connectivity to the NatLangChain blockchain for:
- Anchoring effort receipts to the prose-first ledger
- Recording memory intent entries for audit trails
- Validating chain integrity
- Querying historical records

NatLangChain is a prose-first, intent-native blockchain protocol
whose purpose is to record explicit human intent in natural language.
"""

import json
import hashlib
import requests
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field, asdict
import os


# Default configuration
DEFAULT_API_URL = os.environ.get("NATLANGCHAIN_API_URL", "http://localhost:8000")
DEFAULT_TIMEOUT = 30


@dataclass
class NatLangEntry:
    """A natural language entry to be recorded on NatLangChain."""
    content: str
    author: str
    intent_type: str = "memory_vault_record"
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")

    def to_dict(self) -> dict:
        return asdict(self)

    def content_hash(self) -> str:
        """Generate deterministic hash of entry content."""
        canonical = json.dumps({
            "content": self.content,
            "author": self.author,
            "intent_type": self.intent_type,
            "timestamp": self.timestamp
        }, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class ChainProof:
    """Proof of inclusion in the NatLangChain ledger."""
    entry_id: str
    block_hash: str
    block_height: int
    merkle_proof: List[str]
    timestamp: str

    def to_dict(self) -> dict:
        return asdict(self)


class NatLangChainClient:
    """
    Client for interacting with NatLangChain blockchain.

    Uses the REST API exposed by NatLangChain's run_server.py
    which provides endpoints for entry operations, mining,
    and integrity validation.
    """

    def __init__(self, api_url: str = None, timeout: int = DEFAULT_TIMEOUT):
        self.api_url = (api_url or DEFAULT_API_URL).rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "MemoryVault/1.0"
        })

    def _request(self, method: str, endpoint: str, data: dict = None) -> dict:
        """Make an API request with error handling."""
        url = f"{self.api_url}{endpoint}"
        try:
            if method == "GET":
                response = self._session.get(url, params=data, timeout=self.timeout)
            elif method == "POST":
                response = self._session.post(url, json=data, timeout=self.timeout)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            return response.json()
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"Cannot connect to NatLangChain at {self.api_url}") from e
        except requests.exceptions.Timeout as e:
            raise TimeoutError(f"Request to NatLangChain timed out after {self.timeout}s") from e
        except requests.exceptions.HTTPError as e:
            raise RuntimeError(f"NatLangChain API error: {e.response.status_code} - {e.response.text}") from e

    # ==================== Entry Operations ====================

    def add_entry(self, entry: NatLangEntry) -> dict:
        """
        Add a natural language entry to the pending pool.

        Returns the entry ID and status.
        """
        payload = {
            "content": entry.content,
            "author": entry.author,
            "intent_type": entry.intent_type,
            "metadata": entry.metadata,
            "timestamp": entry.timestamp
        }
        return self._request("POST", "/entries", payload)

    def get_entry(self, entry_id: str) -> dict:
        """Retrieve an entry by ID."""
        return self._request("GET", f"/entries/{entry_id}")

    def search_entries(self, query: str = None, author: str = None,
                       intent_type: str = None, limit: int = 20) -> List[dict]:
        """Search entries with filters."""
        params = {"limit": limit}
        if query:
            params["query"] = query
        if author:
            params["author"] = author
        if intent_type:
            params["intent_type"] = intent_type

        result = self._request("GET", "/entries/search", params)
        return result.get("entries", [])

    # ==================== Mining & Blocks ====================

    def mine_pending(self) -> dict:
        """
        Request mining of pending entries into a new block.

        Returns the new block information if successful.
        """
        return self._request("POST", "/mine")

    def get_block(self, block_hash: str) -> dict:
        """Retrieve a block by its hash."""
        return self._request("GET", f"/blocks/{block_hash}")

    def get_latest_block(self) -> dict:
        """Get the most recent block in the chain."""
        return self._request("GET", "/blocks/latest")

    def get_chain_stats(self) -> dict:
        """Get blockchain statistics."""
        return self._request("GET", "/chain/stats")

    # ==================== Validation ====================

    def validate_entry(self, entry_id: str) -> dict:
        """
        Request LLM-powered validation of an entry.

        Uses NatLangChain's "Proof of Understanding" mechanism
        where validators demonstrate comprehension through paraphrasing.
        """
        return self._request("POST", f"/entries/{entry_id}/validate")

    def verify_chain_integrity(self) -> dict:
        """Verify the integrity of the entire chain."""
        return self._request("GET", "/chain/verify")

    def get_inclusion_proof(self, entry_id: str) -> Optional[ChainProof]:
        """
        Get a Merkle inclusion proof for an entry.

        Returns None if entry is not yet mined.
        """
        try:
            result = self._request("GET", f"/entries/{entry_id}/proof")
            if result.get("included"):
                return ChainProof(
                    entry_id=entry_id,
                    block_hash=result["block_hash"],
                    block_height=result["block_height"],
                    merkle_proof=result.get("merkle_proof", []),
                    timestamp=result.get("timestamp", "")
                )
        except RuntimeError:
            pass
        return None

    # ==================== Health Check ====================

    def health_check(self) -> bool:
        """Check if NatLangChain server is reachable."""
        try:
            self._request("GET", "/health")
            return True
        except Exception:
            return False

    def get_version(self) -> str:
        """Get NatLangChain server version."""
        try:
            result = self._request("GET", "/version")
            return result.get("version", "unknown")
        except Exception:
            return "unknown"


# ==================== Memory Vault Integration Functions ====================

def anchor_memory_to_chain(
    memory_id: str,
    content_hash: str,
    classification: int,
    intent_ref: str = None,
    author: str = "memory_vault",
    api_url: str = None
) -> Optional[str]:
    """
    Anchor a memory's metadata to NatLangChain.

    This creates an immutable record of the memory's existence
    without revealing its contents.

    Args:
        memory_id: The memory's unique identifier
        content_hash: SHA-256 hash of the memory content
        classification: Memory classification level (0-5)
        intent_ref: Optional intent reference
        author: Author identifier
        api_url: Optional custom API URL

    Returns:
        Entry ID if successful, None otherwise
    """
    client = NatLangChainClient(api_url=api_url)

    # Create prose entry describing the memory anchor
    prose = f"""Memory Vault Anchor Record

A cognitive artifact has been secured in the Memory Vault.

Memory ID: {memory_id}
Content Hash: {content_hash}
Classification Level: {classification}
{"Intent Reference: " + intent_ref if intent_ref else ""}
Anchored At: {datetime.now(timezone.utc).isoformat()}Z

This record attests to the existence and integrity of the above memory
at the time of anchoring. The content remains encrypted in the vault."""

    entry = NatLangEntry(
        content=prose,
        author=author,
        intent_type="memory_vault_anchor",
        metadata={
            "memory_id": memory_id,
            "content_hash": content_hash,
            "classification": classification,
            "intent_ref": intent_ref,
            "vault_version": "1.0"
        }
    )

    try:
        result = client.add_entry(entry)
        return result.get("entry_id")
    except Exception as e:
        print(f"Failed to anchor memory to NatLangChain: {e}")
        return None


def anchor_effort_receipt(
    receipt_id: str,
    memory_id: str,
    effort_summary: str,
    time_bounds: tuple,
    signal_hashes: List[str],
    validator_info: dict,
    author: str = "memory_vault",
    api_url: str = None
) -> Optional[str]:
    """
    Anchor an MP-02 effort receipt to NatLangChain.

    This creates an immutable record of verified human effort.

    Args:
        receipt_id: The receipt's unique identifier
        memory_id: Associated memory ID
        effort_summary: Human-readable summary of effort
        time_bounds: (start, end) ISO timestamps
        signal_hashes: List of signal content hashes
        validator_info: Validator metadata (model, version)
        author: Author identifier
        api_url: Optional custom API URL

    Returns:
        Entry ID if successful, None otherwise
    """
    client = NatLangChainClient(api_url=api_url)

    start_time, end_time = time_bounds

    prose = f"""MP-02 Proof-of-Effort Receipt

An effort segment has been observed and validated.

Receipt ID: {receipt_id}
Memory ID: {memory_id}
Time Bounds: {start_time} to {end_time}
Signal Count: {len(signal_hashes)}
Validator: {validator_info.get('model', 'unknown')} v{validator_info.get('version', '0')}

Effort Summary:
{effort_summary}

This receipt attests that human intellectual effort was observed
during the specified time period, producing the referenced memory artifact.
The effort was validated for coherence and progression by the specified validator."""

    entry = NatLangEntry(
        content=prose,
        author=author,
        intent_type="effort_receipt_mp02",
        metadata={
            "receipt_id": receipt_id,
            "memory_id": memory_id,
            "time_start": start_time,
            "time_end": end_time,
            "signal_hashes": signal_hashes,
            "validator": validator_info,
            "protocol": "MP-02"
        }
    )

    try:
        result = client.add_entry(entry)
        return result.get("entry_id")
    except Exception as e:
        print(f"Failed to anchor effort receipt to NatLangChain: {e}")
        return None


def verify_memory_anchor(memory_id: str, api_url: str = None) -> Optional[dict]:
    """
    Verify that a memory has been anchored to NatLangChain.

    Args:
        memory_id: The memory ID to verify
        api_url: Optional custom API URL

    Returns:
        Anchor record if found, None otherwise
    """
    client = NatLangChainClient(api_url=api_url)

    try:
        entries = client.search_entries(
            query=memory_id,
            intent_type="memory_vault_anchor",
            limit=1
        )
        if entries:
            entry = entries[0]
            proof = client.get_inclusion_proof(entry.get("entry_id"))
            return {
                "entry_id": entry.get("entry_id"),
                "anchored_at": entry.get("timestamp"),
                "block_proof": proof.to_dict() if proof else None,
                "verified": proof is not None
            }
    except Exception as e:
        print(f"Failed to verify memory anchor: {e}")

    return None


def get_memory_chain_history(memory_id: str, api_url: str = None) -> List[dict]:
    """
    Get all NatLangChain entries related to a memory.

    Args:
        memory_id: The memory ID to look up
        api_url: Optional custom API URL

    Returns:
        List of related chain entries
    """
    client = NatLangChainClient(api_url=api_url)

    try:
        entries = client.search_entries(
            query=memory_id,
            limit=100
        )
        return entries
    except Exception as e:
        print(f"Failed to get memory chain history: {e}")
        return []
