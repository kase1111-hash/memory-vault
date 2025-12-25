# memory_vault/effort.py
"""
MP-02 Proof-of-Effort Receipt Protocol Implementation

This module implements the MP-02 protocol for observing, validating,
and recording human intellectual effort as cryptographically verifiable receipts.

MP-02 Design Principles:
- Process Over Artifact: Effort is validated as a process over time
- Continuity Matters: Temporal progression is a primary signal
- Receipts, Not Claims: Records evidence, not conclusions about value
- Model Skepticism: LLM assessments are advisory and reproducible
- Partial Observability: Uncertainty is preserved, not collapsed

Components:
- Observer: Captures raw signals of effort
- Validator: Analyzes effort segments for coherence and progression
- Receipt: Cryptographic record attesting that effort occurred
- Ledger: Append-only storage with anchoring to NatLangChain
"""

import sqlite3
import json
import hashlib
import uuid
import os
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

from .db import DB_PATH
from .crypto import load_or_create_signing_key, sign_root
from .natlangchain import anchor_effort_receipt


# ==================== Signal Types ====================

class SignalType(Enum):
    """Types of observable effort signals."""
    TEXT_EDIT = "text_edit"
    COMMAND = "command"
    TOOL_INTERACTION = "tool_interaction"
    VOICE_TRANSCRIPT = "voice_transcript"
    FILE_OPERATION = "file_operation"
    SEARCH_QUERY = "search_query"
    DECISION = "decision"
    ANNOTATION = "annotation"
    PAUSE = "pause"  # Explicit thinking pause
    MARKER = "marker"  # Explicit boundary marker


@dataclass
class Signal:
    """A raw observable trace of effort."""
    signal_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    signal_type: SignalType = SignalType.TEXT_EDIT
    content: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    metadata: Dict[str, Any] = field(default_factory=dict)
    content_hash: str = ""

    def __post_init__(self):
        if not self.content_hash:
            self.content_hash = hashlib.sha256(
                (self.content + self.timestamp).encode()
            ).hexdigest()

    def to_dict(self) -> dict:
        return {
            "signal_id": self.signal_id,
            "signal_type": self.signal_type.value,
            "timestamp": self.timestamp,
            "content_hash": self.content_hash,
            "metadata": self.metadata
            # Note: content is not included to preserve privacy
        }


@dataclass
class EffortSegment:
    """A bounded time slice of signals treated as a unit of analysis."""
    segment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    signals: List[Signal] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""
    boundary_reason: str = ""  # Why this segment was bounded
    metadata: Dict[str, Any] = field(default_factory=dict)

    def signal_count(self) -> int:
        return len(self.signals)

    def duration_seconds(self) -> float:
        if not self.start_time or not self.end_time:
            return 0
        start = datetime.fromisoformat(self.start_time.rstrip("Z"))
        end = datetime.fromisoformat(self.end_time.rstrip("Z"))
        return (end - start).total_seconds()

    def signal_hashes(self) -> List[str]:
        return [s.content_hash for s in self.signals]


@dataclass
class ValidationResult:
    """Result of LLM-assisted effort validation."""
    is_valid: bool = True
    coherence_score: float = 0.0  # 0-1, how coherent the effort appears
    progression_score: float = 0.0  # 0-1, evidence of progression over time
    effort_summary: str = ""  # Deterministic summary of the effort
    uncertainty: float = 0.0  # 0-1, validator's uncertainty
    dissent_notes: str = ""  # Any conflicting signals
    validator_id: str = ""  # Model identifier
    validator_version: str = ""  # Model version
    validation_time: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EffortReceipt:
    """Cryptographic record attesting that effort occurred."""
    receipt_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    segment_id: str = ""
    memory_id: str = ""  # Associated Memory Vault memory
    time_bounds_start: str = ""
    time_bounds_end: str = ""
    signal_count: int = 0
    signal_hashes: List[str] = field(default_factory=list)
    effort_summary: str = ""
    validation: ValidationResult = None
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    signature: str = ""  # Ed25519 signature
    ledger_entry_id: str = ""  # NatLangChain entry ID
    ledger_proof: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        result = {
            "receipt_id": self.receipt_id,
            "segment_id": self.segment_id,
            "memory_id": self.memory_id,
            "time_bounds": {
                "start": self.time_bounds_start,
                "end": self.time_bounds_end
            },
            "signal_count": self.signal_count,
            "signal_hashes": self.signal_hashes,
            "effort_summary": self.effort_summary,
            "created_at": self.created_at,
            "signature": self.signature,
            "ledger_entry_id": self.ledger_entry_id,
        }
        if self.validation:
            result["validation"] = self.validation.to_dict()
        if self.ledger_proof:
            result["ledger_proof"] = self.ledger_proof
        return result


# ==================== Observer ====================

class EffortObserver:
    """
    Observer component for capturing raw effort signals.

    Observers MUST:
    - Time-stamp all signals
    - Preserve ordering
    - Disclose capture modality

    Observers MUST NOT:
    - Alter raw signals
    - Infer intent beyond observed data
    """

    def __init__(self):
        self._active = False
        self._current_segment: Optional[EffortSegment] = None
        self._signals: List[Signal] = []
        self._segments: List[EffortSegment] = []
        self._init_db()

    def _init_db(self):
        """Initialize effort tracking tables."""
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        c.execute('''
            CREATE TABLE IF NOT EXISTS effort_signals (
                signal_id TEXT PRIMARY KEY,
                segment_id TEXT,
                signal_type TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                metadata TEXT,
                FOREIGN KEY (segment_id) REFERENCES effort_segments (segment_id)
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS effort_segments (
                segment_id TEXT PRIMARY KEY,
                start_time TEXT NOT NULL,
                end_time TEXT,
                boundary_reason TEXT,
                signal_count INTEGER DEFAULT 0,
                metadata TEXT,
                validated INTEGER DEFAULT 0
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS effort_receipts (
                receipt_id TEXT PRIMARY KEY,
                segment_id TEXT NOT NULL,
                memory_id TEXT,
                time_bounds_start TEXT NOT NULL,
                time_bounds_end TEXT NOT NULL,
                signal_count INTEGER NOT NULL,
                signal_hashes TEXT NOT NULL,
                effort_summary TEXT,
                validation_result TEXT,
                created_at TEXT NOT NULL,
                signature TEXT NOT NULL,
                ledger_entry_id TEXT,
                ledger_proof TEXT,
                FOREIGN KEY (segment_id) REFERENCES effort_segments (segment_id),
                FOREIGN KEY (memory_id) REFERENCES memories (memory_id)
            )
        ''')

        # Add effort_receipt_id to memories if not exists
        c.execute("PRAGMA table_info(memories)")
        columns = [col[1] for col in c.fetchall()]
        if 'effort_receipt_id' not in columns:
            c.execute("ALTER TABLE memories ADD COLUMN effort_receipt_id TEXT")

        conn.commit()
        conn.close()

    def start_observation(self, reason: str = "manual_start") -> str:
        """
        Start a new observation segment.

        Returns segment_id.
        """
        if self._active:
            raise RuntimeError("Observation already active. Stop current segment first.")

        segment = EffortSegment(
            start_time=datetime.utcnow().isoformat() + "Z",
            boundary_reason=f"start: {reason}"
        )
        self._current_segment = segment
        self._signals = []
        self._active = True

        # Persist segment start
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            INSERT INTO effort_segments (segment_id, start_time, boundary_reason, metadata)
            VALUES (?, ?, ?, ?)
        ''', (segment.segment_id, segment.start_time, segment.boundary_reason,
              json.dumps(segment.metadata)))
        conn.commit()
        conn.close()

        print(f"Observation started: {segment.segment_id}")
        return segment.segment_id

    def stop_observation(self, reason: str = "manual_stop") -> Optional[EffortSegment]:
        """
        Stop the current observation segment.

        Returns the completed segment.
        """
        if not self._active or not self._current_segment:
            print("No active observation to stop")
            return None

        segment = self._current_segment
        segment.signals = self._signals
        segment.end_time = datetime.utcnow().isoformat() + "Z"
        segment.boundary_reason = f"{segment.boundary_reason}; end: {reason}"

        # Persist segment end
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            UPDATE effort_segments SET
                end_time = ?,
                boundary_reason = ?,
                signal_count = ?
            WHERE segment_id = ?
        ''', (segment.end_time, segment.boundary_reason,
              len(self._signals), segment.segment_id))
        conn.commit()
        conn.close()

        self._segments.append(segment)
        self._active = False
        self._current_segment = None
        self._signals = []

        print(f"Observation stopped: {segment.segment_id} ({segment.signal_count()} signals)")
        return segment

    def record_signal(
        self,
        signal_type: SignalType,
        content: str,
        metadata: Dict[str, Any] = None
    ) -> Optional[Signal]:
        """
        Record a new effort signal.

        Args:
            signal_type: Type of signal
            content: Raw signal content
            metadata: Additional context

        Returns:
            The recorded signal, or None if not observing
        """
        if not self._active:
            print("Warning: Not observing. Signal not recorded.")
            return None

        signal = Signal(
            signal_type=signal_type,
            content=content,
            metadata=metadata or {}
        )
        self._signals.append(signal)

        # Persist signal
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            INSERT INTO effort_signals
            (signal_id, segment_id, signal_type, content_hash, timestamp, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            signal.signal_id,
            self._current_segment.segment_id,
            signal.signal_type.value,
            signal.content_hash,
            signal.timestamp,
            json.dumps(signal.metadata)
        ))
        conn.commit()
        conn.close()

        return signal

    def add_marker(self, description: str) -> Optional[Signal]:
        """Add an explicit boundary marker."""
        return self.record_signal(SignalType.MARKER, description, {"marker": True})

    def is_observing(self) -> bool:
        """Check if observation is active."""
        return self._active

    def current_segment_id(self) -> Optional[str]:
        """Get current segment ID if observing."""
        return self._current_segment.segment_id if self._current_segment else None

    def get_segment(self, segment_id: str) -> Optional[EffortSegment]:
        """Retrieve a segment by ID."""
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        c.execute('''
            SELECT segment_id, start_time, end_time, boundary_reason, metadata
            FROM effort_segments WHERE segment_id = ?
        ''', (segment_id,))
        row = c.fetchone()

        if not row:
            conn.close()
            return None

        segment = EffortSegment(
            segment_id=row[0],
            start_time=row[1],
            end_time=row[2] or "",
            boundary_reason=row[3] or "",
            metadata=json.loads(row[4]) if row[4] else {}
        )

        # Load signals
        c.execute('''
            SELECT signal_id, signal_type, content_hash, timestamp, metadata
            FROM effort_signals WHERE segment_id = ?
            ORDER BY timestamp
        ''', (segment_id,))

        for sig_row in c.fetchall():
            signal = Signal(
                signal_id=sig_row[0],
                signal_type=SignalType(sig_row[1]),
                content_hash=sig_row[2],
                timestamp=sig_row[3],
                metadata=json.loads(sig_row[4]) if sig_row[4] else {}
            )
            signal.content = ""  # Content not stored for privacy
            segment.signals.append(signal)

        conn.close()
        return segment


# ==================== Validator ====================

class EffortValidator:
    """
    Validator component for analyzing effort segments.

    Validators MAY assess:
    - Linguistic coherence
    - Conceptual progression
    - Internal consistency
    - Indicators of synthesis vs duplication

    Validators MUST:
    - Produce deterministic summaries
    - Disclose model identity and version
    - Preserve dissent and uncertainty

    Validators MUST NOT:
    - Declare effort as valuable
    - Assert originality or ownership
    - Collapse ambiguous signals into certainty
    """

    def __init__(self, model_id: str = "local_heuristic", version: str = "1.0"):
        self.model_id = model_id
        self.version = version

    def validate_segment(self, segment: EffortSegment) -> ValidationResult:
        """
        Validate an effort segment for coherence and progression.

        Uses heuristic analysis when LLM is not available.
        """
        result = ValidationResult(
            validator_id=self.model_id,
            validator_version=self.version
        )

        if not segment.signals:
            result.is_valid = False
            result.effort_summary = "No signals observed in segment"
            result.uncertainty = 1.0
            return result

        # Heuristic validation (no LLM dependency)
        signal_count = len(segment.signals)
        duration = segment.duration_seconds()
        signal_types = set(s.signal_type for s in segment.signals)

        # Coherence: More diverse signal types = more coherent effort
        type_diversity = len(signal_types) / len(SignalType)
        result.coherence_score = min(1.0, type_diversity + 0.3)

        # Progression: Check temporal distribution
        if duration > 0 and signal_count > 1:
            # Signals per minute as progression indicator
            signals_per_minute = (signal_count / duration) * 60
            if 0.5 <= signals_per_minute <= 30:
                result.progression_score = 0.8
            elif signals_per_minute < 0.5:
                result.progression_score = 0.3
                result.dissent_notes = "Sparse activity may indicate passive observation"
            else:
                result.progression_score = 0.5
                result.dissent_notes = "High activity rate may indicate automated input"
        else:
            result.progression_score = 0.5
            result.uncertainty = 0.5

        # Generate deterministic summary
        minutes = int(duration / 60)
        type_names = sorted([t.value for t in signal_types])
        result.effort_summary = (
            f"Observed {signal_count} signals over {minutes} minutes. "
            f"Signal types: {', '.join(type_names)}. "
            f"Coherence indicators suggest {'focused' if result.coherence_score > 0.6 else 'scattered'} "
            f"effort with {'clear' if result.progression_score > 0.6 else 'unclear'} progression."
        )

        result.is_valid = (
            result.coherence_score > 0.3 and
            result.progression_score > 0.2 and
            signal_count >= 3
        )

        # Overall uncertainty based on segment characteristics
        result.uncertainty = max(0.1, 1.0 - (result.coherence_score + result.progression_score) / 2)

        return result


# ==================== Receipt Generator ====================

def generate_receipt(
    segment: EffortSegment,
    validation: ValidationResult,
    memory_id: str = None,
    anchor_to_chain: bool = True
) -> EffortReceipt:
    """
    Generate an MP-02 effort receipt.

    Args:
        segment: The validated effort segment
        validation: Validation result
        memory_id: Optional associated memory ID
        anchor_to_chain: Whether to anchor to NatLangChain

    Returns:
        Signed effort receipt
    """
    receipt = EffortReceipt(
        segment_id=segment.segment_id,
        memory_id=memory_id or "",
        time_bounds_start=segment.start_time,
        time_bounds_end=segment.end_time,
        signal_count=len(segment.signals),
        signal_hashes=segment.signal_hashes(),
        effort_summary=validation.effort_summary,
        validation=validation
    )

    # Sign the receipt
    signing_key = load_or_create_signing_key()
    receipt_content = json.dumps({
        "receipt_id": receipt.receipt_id,
        "segment_id": receipt.segment_id,
        "memory_id": receipt.memory_id,
        "time_bounds": [receipt.time_bounds_start, receipt.time_bounds_end],
        "signal_hashes": receipt.signal_hashes,
        "effort_summary": receipt.effort_summary,
        "created_at": receipt.created_at
    }, sort_keys=True)

    receipt.signature = sign_root(
        signing_key,
        hashlib.sha256(receipt_content.encode()).hexdigest(),
        1,
        receipt.created_at
    )

    # Anchor to NatLangChain
    if anchor_to_chain:
        try:
            entry_id = anchor_effort_receipt(
                receipt_id=receipt.receipt_id,
                memory_id=receipt.memory_id,
                effort_summary=receipt.effort_summary,
                time_bounds=(receipt.time_bounds_start, receipt.time_bounds_end),
                signal_hashes=receipt.signal_hashes,
                validator_info={
                    "model": validation.validator_id,
                    "version": validation.validator_version
                }
            )
            if entry_id:
                receipt.ledger_entry_id = entry_id
                print(f"Receipt anchored to NatLangChain: {entry_id}")
        except Exception as e:
            print(f"Warning: Could not anchor to NatLangChain: {e}")

    # Persist receipt
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO effort_receipts (
            receipt_id, segment_id, memory_id, time_bounds_start, time_bounds_end,
            signal_count, signal_hashes, effort_summary, validation_result,
            created_at, signature, ledger_entry_id, ledger_proof
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        receipt.receipt_id,
        receipt.segment_id,
        receipt.memory_id,
        receipt.time_bounds_start,
        receipt.time_bounds_end,
        receipt.signal_count,
        json.dumps(receipt.signal_hashes),
        receipt.effort_summary,
        json.dumps(validation.to_dict()),
        receipt.created_at,
        receipt.signature,
        receipt.ledger_entry_id,
        json.dumps(receipt.ledger_proof)
    ))

    # Update segment as validated
    c.execute("UPDATE effort_segments SET validated = 1 WHERE segment_id = ?",
              (segment.segment_id,))

    conn.commit()
    conn.close()

    print(f"Receipt generated: {receipt.receipt_id}")
    return receipt


def link_receipt_to_memory(receipt_id: str, memory_id: str) -> bool:
    """Link an effort receipt to a memory."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Update receipt
    c.execute(
        "UPDATE effort_receipts SET memory_id = ? WHERE receipt_id = ?",
        (memory_id, receipt_id)
    )

    # Update memory
    c.execute(
        "UPDATE memories SET effort_receipt_id = ? WHERE memory_id = ?",
        (receipt_id, memory_id)
    )

    conn.commit()
    conn.close()
    return True


def get_receipt(receipt_id: str) -> Optional[EffortReceipt]:
    """Retrieve a receipt by ID."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''
        SELECT receipt_id, segment_id, memory_id, time_bounds_start, time_bounds_end,
               signal_count, signal_hashes, effort_summary, validation_result,
               created_at, signature, ledger_entry_id, ledger_proof
        FROM effort_receipts WHERE receipt_id = ?
    ''', (receipt_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return None

    receipt = EffortReceipt(
        receipt_id=row[0],
        segment_id=row[1],
        memory_id=row[2] or "",
        time_bounds_start=row[3],
        time_bounds_end=row[4],
        signal_count=row[5],
        signal_hashes=json.loads(row[6]),
        effort_summary=row[7] or "",
        created_at=row[9],
        signature=row[10],
        ledger_entry_id=row[11] or "",
        ledger_proof=json.loads(row[12]) if row[12] else {}
    )

    if row[8]:
        val_dict = json.loads(row[8])
        receipt.validation = ValidationResult(**val_dict)

    return receipt


def get_receipts_for_memory(memory_id: str) -> List[EffortReceipt]:
    """Get all effort receipts linked to a memory."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''
        SELECT receipt_id FROM effort_receipts WHERE memory_id = ?
        ORDER BY created_at DESC
    ''', (memory_id,))

    receipts = []
    for row in c.fetchall():
        receipt = get_receipt(row[0])
        if receipt:
            receipts.append(receipt)

    conn.close()
    return receipts


def list_pending_segments() -> List[dict]:
    """List segments that haven't been validated yet."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''
        SELECT segment_id, start_time, end_time, signal_count, boundary_reason
        FROM effort_segments
        WHERE validated = 0 AND end_time IS NOT NULL
        ORDER BY start_time DESC
    ''')

    results = []
    for row in c.fetchall():
        results.append({
            "segment_id": row[0],
            "start_time": row[1],
            "end_time": row[2],
            "signal_count": row[3],
            "boundary_reason": row[4]
        })

    conn.close()
    return results
