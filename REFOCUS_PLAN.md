# Memory Vault Refocus Plan

**Goal:** Strip Memory Vault down to what it actually is -- an encrypted, classification-gated memory store for AI agents -- and make it trivially adoptable.

**Target state:** ~3,000 lines of focused code, zero ecosystem dependencies, clean Python package, 3-line quickstart.

---

## Phase 1: Extract Ecosystem Modules (Cut the Wrong Products)

These three modules are separate products sharing a repo. Extract them, don't just delete -- the code is well-written and belongs somewhere.

### 1.1 Remove `effort.py` (721 lines)

MP-02 Proof-of-Effort is a complete protocol with its own data model, DB schema, validation engine, and signing system. It does not support the core memory storage mission.

**Files to modify:**

| File | Action | Lines |
|------|--------|-------|
| `effort.py` | Delete file | — |
| `tests/test_effort.py` | Delete file | — |
| `__init__.py` | Remove lines 198-230 (effort imports), line 228 (`EFFORT_AVAILABLE`), lines 364-377 (`__all__` effort entries) | ~35 lines |
| `cli.py` | Remove effort subcommand parser (lines 189-215) and all effort command handlers (lines 703-864) | ~170 lines |
| `vault.py` | Remove `link_effort_receipt()` and `get_effort_receipts()` methods (lines ~1826-1870) | ~45 lines |
| `db.py` | Remove `effort_receipts` table creation if present | — |
| `pyproject.toml` | Remove `"effort"` from `py-modules` list (line 75) | 1 word |

**Risk:** Low. Effort is loosely coupled. All imports are wrapped in try/except.

### 1.2 Remove `natlangchain.py` (405 lines)

REST client for a separate blockchain project. Has an undeclared `requests` dependency.

**Files to modify:**

| File | Action | Lines |
|------|--------|-------|
| `natlangchain.py` | Delete file | — |
| `tests/test_natlangchain.py` | Delete file | — |
| `__init__.py` | Remove lines 172-196 (natlangchain imports), `NATLANGCHAIN_AVAILABLE` flag, lines 352-361 (`__all__` entries) | ~25 lines |
| `vault.py` | Remove lines 78-88 (natlangchain import block), remove `NATLANGCHAIN_AVAILABLE` flag, remove any `anchor_memory_to_chain` / `verify_memory_anchor` call sites | ~15 lines |
| `cli.py` | Remove `chain-status` command (line ~684) and its parser | ~15 lines |
| `pyproject.toml` | Remove `"natlangchain"` from `py-modules` | 1 word |

**Dependency note:** This also unblocks removing `effort.py` cleanly since effort imports `anchor_effort_receipt` from natlangchain.

**Risk:** Low. All natlangchain usage is behind `NATLANGCHAIN_AVAILABLE` guards.

### 1.3 Remove `agent_os.py` (642 lines)

Full governance SDK for Agent-OS. Belongs in `agent-os-sdk`.

**Files to modify:**

| File | Action | Lines |
|------|--------|-------|
| `agent_os.py` | Delete file | — |
| `tests/test_agent_os.py` | Delete file | — |
| `__init__.py` | Remove lines 232-264 (agent_os imports), `AGENT_OS_AVAILABLE` flag, lines 380-393 (`__all__` entries) | ~35 lines |
| `vault.py` | Remove lines 90-99 (agent_os import block), remove `AGENT_OS_AVAILABLE` flag, remove any `check_agent_permission` / `BoundaryDaemon` call sites in recall/governance methods (~lines 1777, 1817) | ~30 lines |
| `pyproject.toml` | Remove `"agent_os"` from `py-modules` | 1 word |

**Risk:** Low. All agent_os usage is behind `AGENT_OS_AVAILABLE` guards.

**Phase 1 total reduction: ~1,768 lines of source + ~600 lines of tests + ~300 lines of wiring = ~2,668 lines removed.**

---

## Phase 2: Remove SIEM Infrastructure (Cut the Distractions)

No alpha tool with zero deployments needs CEF-formatted SIEM event reporting. This is wired into every code path and adds complexity for no user benefit.

### 2.1 Remove `siem_reporter.py` (482 lines)

**Files to modify:**

| File | Action | Lines |
|------|--------|-------|
| `siem_reporter.py` | Delete file | — |
| `tests/test_siem_reporter.py` | Delete file | — |
| `__init__.py` | Remove lines 120-147 (siem imports), `SIEM_AVAILABLE` flag, lines 328-339 (`__all__` entries) | ~25 lines |
| `pyproject.toml` | Remove `"siem_reporter"` from `py-modules` | 1 word |

### 2.2 Remove SIEM wiring from `vault.py`

This is the most surgical part of the plan. SIEM is threaded through the entire `MemoryVault` class.

**vault.py changes:**

| Location | Action |
|----------|--------|
| Line 46 import | Remove `from .siem_reporter import SIEMReporter, SIEMConfig, get_reporter` |
| Lines 116-117 (`__init__` params) | Remove `siem_config: SIEMConfig = None` and `enable_siem: bool = True` params |
| Lines 132-140 (`__init__` body) | Remove SIEM reporter initialization block |
| Lines 143 | Change `BoundaryClient(siem_reporter=self._siem_reporter)` to `BoundaryClient()` |
| Lines 146-151 | Remove `_report_event("vault.init", ...)` call |
| Lines 153-176 | Delete `_report_event()` and `_report_exception()` methods entirely |
| Lines 186-191 | Remove `_report_event("vault.close", ...)` call in `close()` |
| Lines 197-201 | Simplify `shutdown()` -- just call `self.close()` |
| Lines 414, 428, 445, 470, 485, 502, 520, 553, 567, 577 | Remove all `self._report_exception(exc)` and `self._report_event(...)` calls in recall flow |

**Approach:** Find-and-delete every `self._report_event(` and `self._report_exception(` call. Remove the `self._siem_reporter` and `self._siem_enabled` instance variables.

### 2.3 Remove SIEM wiring from `boundry.py`

| Location | Action |
|----------|--------|
| Line 70 (`__init__` param) | Remove `siem_reporter=None` parameter |
| Lines 77, 189, 214, 319, 364, 378 | Remove all `self.siem_reporter.report_event()` and `report_exception()` calls |

### 2.4 Simplify `errors.py`

Keep the exception hierarchy (it's useful for structured error handling) but strip the SIEM formatting.

| Location | Action |
|----------|--------|
| Lines 67-85 | Remove `to_siem_event()` method from `MemoryVaultError` |
| Lines 402-415 | Remove `SIEMError`, `SIEMConnectionError`, `SIEMReportingError` classes |
| `Severity` enum | Keep if used for logging levels; remove if only used for SIEM severity mapping |

**Phase 2 total reduction: ~482 lines (siem_reporter) + ~200 lines of wiring + ~50 lines of tests = ~730 lines removed.**

---

## Phase 3: Fix Bugs and Code Quality Issues

These are real bugs and inconsistencies that should be fixed regardless of refocusing.

### 3.1 Fix cipher documentation mismatch

The README, SPECIFICATION.md, and models.py all claim "AES-256-GCM". The actual cipher used by PyNaCl's `SecretBox` is **XSalsa20-Poly1305**. Both are authenticated encryption, but the docs are wrong.

**Files to update:**

| File | Change |
|------|--------|
| `README.md` | Replace "AES-256-GCM" with "XSalsa20-Poly1305 (libsodium SecretBox)" in Features section |
| `SPECIFICATION.md` | Replace "AES-256-GCM" with "XSalsa20-Poly1305" in cipher references |
| `models.py` line 22 | Change `cipher: str = "AES-256-GCM"` to `cipher: str = "XSalsa20-Poly1305"` |
| `db.py` line 43 | Change `DEFAULT 'AES-256-GCM'` to `DEFAULT 'XSalsa20-Poly1305'` |

**Note:** This is a breaking change for existing databases that have profiles stored with "AES-256-GCM". Add a migration or accept both values.

### 3.2 Deduplicate `_validate_profile_id`

Currently copy-pasted identically in `vault.py`, `crypto.py`, and `escrow.py`.

**Action:** Define once in `crypto.py` (the natural home), import everywhere else.

| File | Change |
|------|--------|
| `crypto.py` | Keep the definition (lines 20-29), make it public: `validate_profile_id()` |
| `vault.py` | Remove lines 101-109, add `from .crypto import validate_profile_id` |
| `escrow.py` | Remove lines 37-44, add `from .crypto import validate_profile_id` |

### 3.3 Fix connection management in `vault.py`

`MemoryVault.__init__` stores `self._conn = init_db(self.db_path)`, but then `store_memory()`, `recall_memory()`, `list_profiles()`, and `create_profile()` all open new `sqlite3.connect()` calls.

**Action:** Use `self._conn` (or `self.conn` property) consistently throughout the class. Remove all per-method `sqlite3.connect()` calls.

**Pattern to replace:**
```python
# BEFORE (current pattern, repeated ~10 times):
conn = sqlite3.connect(self.db_path)
try:
    c = conn.cursor()
    # ... operations ...
    conn.commit()
finally:
    conn.close()

# AFTER:
c = self._conn.cursor()
# ... operations ...
self._conn.commit()
```

**Risk:** Medium. Need to verify no concurrent access patterns depend on separate connections. SQLite's default threading mode should be checked.

### 3.4 Fix the dual-import anti-pattern

Every module has:
```python
try:
    from .module import X
except ImportError:
    from module import X
```

**Action:** Pick one packaging strategy and commit to it. Recommended: proper Python package with `src/memory_vault/` layout.

```
src/
  memory_vault/
    __init__.py
    vault.py
    crypto.py
    db.py
    models.py
    ...
```

Then all imports become clean relative imports: `from .crypto import derive_key_from_passphrase`.

**Update `pyproject.toml`:**
```toml
[tool.setuptools.packages.find]
where = ["src"]
```

Remove the `py-modules` list entirely.

**Risk:** Medium. Requires moving all source files and updating all imports. Do this as a dedicated commit.

### 3.5 Rename `boundry.py` to `boundary.py`

The typo is acknowledged in SPECIFICATION.md but kept "for backwards compatibility" -- in an alpha with no external consumers. Fix it now while there are no dependents.

**Files to update:**
- Rename `boundry.py` -> `boundary.py`
- Rename `tests/test_boundry.py` -> `tests/test_boundary.py`
- Update all imports referencing `boundry` -> `boundary`
- Update `pyproject.toml` `py-modules` list

---

## Phase 4: Simplify for Adoption (Double Down on Core)

### 4.1 Simplify `errors.py`

After removing SIEM, reduce the 30+ exception types to the ones actually raised by core code:

**Keep (raised in vault.py recall flow):**
- `MemoryVaultError` (base)
- `DecryptionError`
- `LockdownError`
- `TombstoneError`
- `CooldownError`
- `ApprovalRequiredError`
- `BoundaryDeniedError`
- `MemoryNotFoundError`
- `ProfileKeyMissingError`
- `PhysicalTokenError`

**Remove (not raised by core code after Phase 1-2):**
- All SIEM errors (gone after Phase 2)
- `PolicyViolationError` (only used by agent_os)
- `ConfigurationError` (not raised anywhere in core)
- `AuditTrailError` (not raised anywhere)
- Anything else not referenced after the extraction

Simplify `MemoryVaultError` base class: keep `message`, drop `actor`, `metadata`, `cause`, `timestamp`, `to_siem_event()`. Standard Python exceptions don't carry all this baggage.

### 4.2 Simplify `__init__.py`

After Phases 1-2, the 393-line `__init__.py` should shrink to ~30 lines:

```python
"""Memory Vault - Encrypted, classification-gated storage for AI agent memories."""

__version__ = "0.1.0-alpha"

from .vault import MemoryVault
from .models import MemoryObject, EncryptionProfile, RecallRequest
from .db import init_db
from .errors import (
    MemoryVaultError,
    DecryptionError,
    LockdownError,
    MemoryNotFoundError,
    # ... core errors only
)

__all__ = [
    "MemoryVault",
    "MemoryObject",
    "EncryptionProfile",
    "RecallRequest",
    "init_db",
    "MemoryVaultError",
    # ...
]
```

### 4.3 Add framework integration example

Create a simple example showing Memory Vault as a LangChain-compatible memory backend. This is the single highest-leverage thing for adoption.

**New file:** `examples/langchain_memory.py`

The goal: show that `MemoryVault` can be instantiated in 2-3 lines and used as a drop-in memory store. No SIEM config, no boundary daemon, no NatLangChain -- just store and recall.

### 4.4 Rewrite README quickstart

Current quickstart requires creating a profile, then storing. Simplify to:

```python
from memory_vault import MemoryVault, MemoryObject

vault = MemoryVault()
vault.create_profile("default", passphrase="my-secret")

# Store
obj = MemoryObject(content_plaintext=b"The user prefers dark mode", classification=1)
vault.store_memory(obj, passphrase="my-secret")

# Recall
content = vault.recall_memory(obj.memory_id, justification="personalizing UI", passphrase="my-secret")
```

---

## Phase 5: Defer Advanced Features (Nice-to-Have Backlog)

These modules stay in the repo but are explicitly marked as experimental/deferred. No removal needed, just honesty in docs.

| Module | Lines | Status | Action |
|--------|-------|--------|--------|
| `zkproofs.py` | 342 | Deferred | Mark as experimental in README. Keep tests. |
| `deadman.py` | 252 | Deferred | Mark as experimental. Keep tests. |
| `escrow.py` | 475 | Deferred | Mark as experimental. Consider replacing custom GF(256) with library. |
| `physical_token.py` | 334 | Partial | Either finish FIDO2/HMAC or mark as proof-of-concept. |
| `intentlog.py` | 231 | Deferred | Keep as optional adapter. |

---

## Execution Order

The phases have dependencies. Execute in this order:

```
Phase 1.2 (natlangchain) ──┐
Phase 1.1 (effort)     ────┤  ← effort depends on natlangchain being gone first
Phase 1.3 (agent_os)   ────┤
                            ▼
Phase 2 (SIEM removal) ────── ← SIEM is wired into vault.py and boundry.py
                            │
                            ▼
Phase 3 (bug fixes)    ────── ← clean up after removal; fix cipher docs, dedup, etc.
                            │
                            ▼
Phase 4 (simplify)     ────── ← simplify errors, __init__, add examples
                            │
                            ▼
Phase 5 (backlog)      ────── ← documentation updates only
```

**Recommended commit sequence:**
1. `Remove natlangchain.py and all references`
2. `Remove effort.py and all references`
3. `Remove agent_os.py and all references`
4. `Remove siem_reporter.py and all SIEM wiring`
5. `Fix cipher documentation: XSalsa20-Poly1305, not AES-256-GCM`
6. `Deduplicate validate_profile_id into crypto.py`
7. `Fix vault.py connection management to use self._conn`
8. `Rename boundry.py to boundary.py`
9. `Restructure as proper Python package (src/ layout)`
10. `Simplify errors.py and __init__.py`
11. `Add framework integration examples and rewrite quickstart`
12. `Mark zkproofs, deadman, escrow, physical_token as experimental`

---

## Expected Outcome

| Metric | Before | After |
|--------|--------|-------|
| Source lines | 8,890 | ~3,500 |
| Modules | 18 | 11 |
| Required dependencies | pynacl | pynacl |
| Undeclared dependencies | requests | 0 |
| Exception classes | 30+ | ~12 |
| `__init__.py` lines | 393 | ~30 |
| Ecosystem coupling | 4 external projects | 0 |
| Time to first store/recall | Read 500-line README | 3-line example |

The core product (encrypted, classified memory with human gates) stays intact and becomes the clear focus. Advanced features (ZK proofs, dead-man switch, escrow) stay available but are honestly labeled as experimental. The ecosystem integrations live in their own packages where they belong.
