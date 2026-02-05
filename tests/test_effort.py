"""
Tests for effort.py - MP-02 Proof-of-Effort Protocol.

Tests data structures, signal types, validation logic, and observer.
"""
import os
import sys
import sqlite3
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from effort import (
    SignalType,
    Signal,
    EffortSegment,
    ValidationResult,
    EffortReceipt,
    EffortObserver,
    EffortValidator,
)


class TestSignalType:
    """Test SignalType enum."""

    def test_all_types_exist(self):
        expected = [
            "text_edit", "command", "tool_interaction", "voice_transcript",
            "file_operation", "search_query", "decision", "annotation",
            "pause", "marker",
        ]
        for val in expected:
            assert SignalType(val)

    def test_value_access(self):
        assert SignalType.TEXT_EDIT.value == "text_edit"
        assert SignalType.MARKER.value == "marker"


class TestSignal:
    """Test Signal dataclass."""

    def test_auto_generates_id(self):
        s = Signal(content="test")
        assert s.signal_id  # UUID should be auto-generated
        assert len(s.signal_id) == 36

    def test_auto_generates_timestamp(self):
        s = Signal(content="test")
        assert s.timestamp
        assert "T" in s.timestamp

    def test_auto_generates_content_hash(self):
        s = Signal(content="test content")
        assert s.content_hash
        assert len(s.content_hash) == 64  # SHA256 hex

    def test_content_hash_deterministic(self):
        """Same content + timestamp gives same hash."""
        ts = "2025-01-15T10:00:00Z"
        s1 = Signal(content="same", timestamp=ts)
        s2 = Signal(content="same", timestamp=ts)
        assert s1.content_hash == s2.content_hash

    def test_content_hash_differs(self):
        ts = "2025-01-15T10:00:00Z"
        s1 = Signal(content="A", timestamp=ts)
        s2 = Signal(content="B", timestamp=ts)
        assert s1.content_hash != s2.content_hash

    def test_to_dict_excludes_content(self):
        s = Signal(content="secret content", signal_type=SignalType.TEXT_EDIT)
        d = s.to_dict()
        assert "content" not in d
        assert "content_hash" in d
        assert d["signal_type"] == "text_edit"

    def test_default_type(self):
        s = Signal()
        assert s.signal_type == SignalType.TEXT_EDIT


class TestEffortSegment:
    """Test EffortSegment dataclass."""

    def test_signal_count(self):
        seg = EffortSegment()
        assert seg.signal_count() == 0

        seg.signals = [Signal(content="a"), Signal(content="b")]
        assert seg.signal_count() == 2

    def test_duration_seconds(self):
        seg = EffortSegment(
            start_time="2025-01-15T10:00:00Z",
            end_time="2025-01-15T10:05:00Z",
        )
        assert seg.duration_seconds() == 300.0

    def test_duration_empty(self):
        seg = EffortSegment()
        assert seg.duration_seconds() == 0

    def test_signal_hashes(self):
        s1 = Signal(content="a")
        s2 = Signal(content="b")
        seg = EffortSegment(signals=[s1, s2])
        hashes = seg.signal_hashes()
        assert len(hashes) == 2
        assert hashes[0] == s1.content_hash
        assert hashes[1] == s2.content_hash


class TestValidationResult:
    """Test ValidationResult dataclass."""

    def test_defaults(self):
        v = ValidationResult()
        assert v.is_valid is True
        assert v.coherence_score == 0.0
        assert v.progression_score == 0.0
        assert v.uncertainty == 0.0
        assert v.validator_id == ""

    def test_to_dict(self):
        v = ValidationResult(
            is_valid=True,
            coherence_score=0.8,
            progression_score=0.7,
            effort_summary="Good effort",
            validator_id="test_model",
        )
        d = v.to_dict()
        assert d["is_valid"] is True
        assert d["coherence_score"] == 0.8
        assert d["validator_id"] == "test_model"


class TestEffortReceipt:
    """Test EffortReceipt dataclass."""

    def test_auto_generates_id(self):
        r = EffortReceipt()
        assert r.receipt_id
        assert len(r.receipt_id) == 36

    def test_to_dict_basic(self):
        r = EffortReceipt(
            segment_id="seg-1",
            memory_id="mem-1",
            signal_count=5,
            signal_hashes=["h1", "h2"],
            effort_summary="test effort",
        )
        d = r.to_dict()
        assert d["segment_id"] == "seg-1"
        assert d["signal_count"] == 5
        assert len(d["signal_hashes"]) == 2

    def test_to_dict_with_validation(self):
        v = ValidationResult(coherence_score=0.9)
        r = EffortReceipt(validation=v)
        d = r.to_dict()
        assert "validation" in d
        assert d["validation"]["coherence_score"] == 0.9

    def test_to_dict_without_validation(self):
        r = EffortReceipt()
        d = r.to_dict()
        assert "validation" not in d


class TestEffortValidator:
    """Test EffortValidator heuristic validation."""

    def test_empty_segment_invalid(self):
        validator = EffortValidator()
        seg = EffortSegment()
        result = validator.validate_segment(seg)
        assert result.is_valid is False
        assert result.uncertainty == 1.0

    def test_valid_segment(self):
        """A segment with diverse signals over reasonable time is valid."""
        validator = EffortValidator()
        now = datetime.now(timezone.utc)
        signals = [
            Signal(content="edit", signal_type=SignalType.TEXT_EDIT,
                   timestamp=(now + timedelta(minutes=i)).isoformat() + "Z")
            for i in range(5)
        ]
        # Add diversity
        signals.append(Signal(content="cmd", signal_type=SignalType.COMMAND,
                              timestamp=(now + timedelta(minutes=5)).isoformat() + "Z"))
        signals.append(Signal(content="search", signal_type=SignalType.SEARCH_QUERY,
                              timestamp=(now + timedelta(minutes=6)).isoformat() + "Z"))

        seg = EffortSegment(
            signals=signals,
            start_time=now.isoformat() + "Z",
            end_time=(now + timedelta(minutes=7)).isoformat() + "Z",
        )
        result = validator.validate_segment(seg)
        assert result.is_valid is True
        assert result.coherence_score > 0.3
        assert result.progression_score > 0.2
        assert result.effort_summary

    def test_too_few_signals_invalid(self):
        """Fewer than 3 signals should be invalid."""
        validator = EffortValidator()
        now = datetime.now(timezone.utc)
        seg = EffortSegment(
            signals=[Signal(content="a"), Signal(content="b")],
            start_time=now.isoformat() + "Z",
            end_time=(now + timedelta(minutes=5)).isoformat() + "Z",
        )
        result = validator.validate_segment(seg)
        assert result.is_valid is False

    def test_sparse_signals_low_progression(self):
        """Very sparse signals should have lower progression score."""
        validator = EffortValidator()
        now = datetime.now(timezone.utc)
        signals = [
            Signal(content=f"s{i}", signal_type=SignalType.TEXT_EDIT,
                   timestamp=(now + timedelta(hours=i)).isoformat() + "Z")
            for i in range(4)
        ]
        seg = EffortSegment(
            signals=signals,
            start_time=now.isoformat() + "Z",
            end_time=(now + timedelta(hours=4)).isoformat() + "Z",
        )
        result = validator.validate_segment(seg)
        assert result.progression_score <= 0.5

    def test_validator_identity(self):
        validator = EffortValidator(model_id="test-model", version="2.0")
        seg = EffortSegment(signals=[Signal(content="x")])
        result = validator.validate_segment(seg)
        assert result.validator_id == "test-model"
        assert result.validator_version == "2.0"


class TestEffortObserver:
    """Test EffortObserver with temp database."""

    @pytest.fixture
    def observer(self, tmp_path, monkeypatch):
        """Create observer with temp DB."""
        db_path = str(tmp_path / "test_effort.db")
        # Monkeypatch DB_PATH in effort module
        import effort
        monkeypatch.setattr(effort, "DB_PATH", db_path)

        # Initialize base tables that the observer expects
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS memories (
                memory_id TEXT PRIMARY KEY,
                classification INTEGER DEFAULT 0,
                created_at TEXT DEFAULT '',
                content_hash TEXT DEFAULT '',
                ciphertext BLOB DEFAULT x'',
                nonce BLOB DEFAULT x'',
                encryption_profile TEXT DEFAULT '',
                created_by TEXT DEFAULT ''
            )
        """)
        conn.commit()
        conn.close()

        obs = EffortObserver()
        return obs

    def test_start_stop_observation(self, observer):
        seg_id = observer.start_observation("test start")
        assert seg_id
        assert observer.is_observing() is True
        assert observer.current_segment_id() == seg_id

        segment = observer.stop_observation("test stop")
        assert segment is not None
        assert observer.is_observing() is False
        assert observer.current_segment_id() is None

    def test_record_signal(self, observer):
        observer.start_observation("test")
        signal = observer.record_signal(SignalType.TEXT_EDIT, "typed something")
        assert signal is not None
        assert signal.signal_type == SignalType.TEXT_EDIT
        observer.stop_observation()

    def test_record_signal_without_observation(self, observer):
        result = observer.record_signal(SignalType.TEXT_EDIT, "no observation")
        assert result is None

    def test_add_marker(self, observer):
        observer.start_observation("test")
        marker = observer.add_marker("checkpoint")
        assert marker is not None
        assert marker.signal_type == SignalType.MARKER
        observer.stop_observation()

    def test_double_start_raises(self, observer):
        observer.start_observation("first")
        with pytest.raises(RuntimeError, match="already active"):
            observer.start_observation("second")
        observer.stop_observation()

    def test_stop_without_start(self, observer):
        result = observer.stop_observation()
        assert result is None

    def test_get_segment(self, observer):
        seg_id = observer.start_observation("persist test")
        observer.record_signal(SignalType.COMMAND, "ls -la")
        observer.stop_observation()

        retrieved = observer.get_segment(seg_id)
        assert retrieved is not None
        assert retrieved.segment_id == seg_id
        assert len(retrieved.signals) == 1

    def test_get_nonexistent_segment(self, observer):
        result = observer.get_segment("nonexistent-id")
        assert result is None
