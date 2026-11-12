"""
Tests for the behaviour an AI agent depends on: correct key handling across many
memories, non-interactive operation, and finding memories without decrypting them.
"""

import builtins
import os
import sqlite3
import sys

import pytest
from nacl.pwhash import argon2id

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import crypto
import vault as vault_module
from db import build_fts_query
from errors import ApprovalRequiredError, DecryptionError, PhysicalTokenError, ProfileKeyMissingError
from models import MemoryObject
from vault import MemoryVault

PASSPHRASE = "correct horse battery staple"


@pytest.fixture
def kdf_calls(monkeypatch):
    """Swap the 1 GB Argon2id parameters for cheap ones and record every derivation."""
    calls = []

    def fast_derive(passphrase, salt=None):
        if salt is None:
            salt = os.urandom(argon2id.SALTBYTES)
        calls.append(salt)
        key = argon2id.kdf(
            32,
            passphrase.encode("utf-8"),
            salt,
            opslimit=argon2id.OPSLIMIT_MIN,
            memlimit=argon2id.MEMLIMIT_MIN,
        )
        return key, salt

    monkeypatch.setattr(vault_module, "derive_key_from_passphrase", fast_derive)
    return calls


@pytest.fixture
def no_terminal(monkeypatch):
    """Fail the test if the vault tries to read from the terminal."""

    def refuse(*args, **kwargs):
        raise AssertionError("vault tried to prompt on the terminal")

    monkeypatch.setattr(builtins, "input", refuse)
    monkeypatch.setattr(vault_module.getpass, "getpass", refuse)


@pytest.fixture
def db_path(temp_vault_dir):
    return str(temp_vault_dir / ".memory_vault" / "vault.db")


def _store(vault, text, passphrase=PASSPHRASE, **kwargs):
    obj = MemoryObject(content_plaintext=text.encode(), **kwargs)
    vault.store_memory(obj, passphrase=passphrase)
    return obj.memory_id


class TestKeyCache:
    def test_memory_stored_with_cached_key_is_recoverable(self, db_path, kdf_calls, no_terminal):
        """Regression: a store that reused the cached key saved a salt that did not
        match it, leaving the memory undecryptable with the correct passphrase."""
        vault = MemoryVault(db_path)
        first = _store(vault, "first")
        second = _store(vault, "second", passphrase=None)  # relies on the cached key
        vault.close()

        fresh = MemoryVault(db_path)  # new process: nothing cached
        assert fresh.recall_memory(first, justification="t", passphrase=PASSPHRASE) == b"first"
        assert fresh.recall_memory(second, justification="t", passphrase=PASSPHRASE) == b"second"

    def test_recall_without_passphrase_uses_cache_for_every_memory(self, db_path, kdf_calls, no_terminal):
        vault = MemoryVault(db_path)
        ids = [_store(vault, f"memory {i}") for i in range(3)]
        for i, memory_id in enumerate(ids):
            assert vault.recall_memory(memory_id, justification="t") == f"memory {i}".encode()

    def test_kdf_runs_once_per_session(self, db_path, kdf_calls):
        vault = MemoryVault(db_path)
        ids = [_store(vault, f"memory {i}") for i in range(5)]
        for memory_id in ids:
            vault.recall_memory(memory_id, justification="t", passphrase=PASSPHRASE)
        assert len(kdf_calls) == 1

    def test_wrong_passphrase_rejected_even_when_right_key_is_cached(self, db_path, kdf_calls):
        vault = MemoryVault(db_path)
        memory_id = _store(vault, "secret")
        with pytest.raises(DecryptionError):
            vault.recall_memory(memory_id, justification="t", passphrase="wrong")
        # ...and the failed attempt must not have replaced the good cached key.
        assert vault.recall_memory(memory_id, justification="t") == b"secret"

    def test_store_with_wrong_passphrase_is_refused(self, db_path, kdf_calls):
        vault = MemoryVault(db_path)
        _store(vault, "first")
        vault.close()

        fresh = MemoryVault(db_path)
        with pytest.raises(DecryptionError, match="does not match"):
            _store(fresh, "typo", passphrase="correct horse battery stapel")
        assert len(fresh.list_memories()) == 1

    def test_create_profile_passphrase_is_usable(self, db_path, kdf_calls, no_terminal):
        vault = MemoryVault(db_path)
        vault.create_profile("work", passphrase=PASSPHRASE)
        memory_id = _store(vault, "note", passphrase=None, encryption_profile="work")
        vault.close()

        fresh = MemoryVault(db_path)
        assert fresh.recall_memory(memory_id, justification="t", passphrase=PASSPHRASE) == b"note"

    def test_memories_with_their_own_salt_still_decrypt(self, db_path, kdf_calls, no_terminal):
        """Memories written before per-profile salts have one salt each."""
        vault = MemoryVault(db_path)
        legacy_salt = os.urandom(16)
        key, _ = vault_module.derive_key_from_passphrase(PASSPHRASE, legacy_salt)
        ciphertext, nonce = crypto.encrypt_memory(key, b"old memory")
        obj = MemoryObject(content_plaintext=b"old memory")
        vault.conn.execute(
            """INSERT INTO memories (memory_id, created_at, created_by, classification, encryption_profile,
               content_hash, ciphertext, nonce, salt) VALUES (?, ?, 'agent', 1, 'default-passphrase', ?, ?, ?, ?)""",
            (
                obj.memory_id,
                obj.created_at.isoformat(),
                vault_module.hashlib.sha256(b"old memory").hexdigest(),
                ciphertext,
                nonce,
                legacy_salt,
            ),
        )
        vault.conn.commit()
        new_id = _store(vault, "new memory")

        assert vault.recall_memory(obj.memory_id, justification="t", passphrase=PASSPHRASE) == b"old memory"
        assert vault.recall_memory(new_id, justification="t", passphrase=PASSPHRASE) == b"new memory"

    def test_rotation_rekeys_every_memory(self, db_path, kdf_calls, monkeypatch):
        vault = MemoryVault(db_path)
        ids = [_store(vault, f"memory {i}") for i in range(3)]
        monkeypatch.setattr(vault_module.getpass, "getpass", lambda prompt="": PASSPHRASE)
        monkeypatch.setattr(builtins, "input", lambda prompt="": "ROTATE KEY")

        assert vault.rotate_profile_key("default-passphrase", new_passphrase="a new passphrase") is True
        vault.close()

        fresh = MemoryVault(db_path)
        for i, memory_id in enumerate(ids):
            assert fresh.recall_memory(memory_id, justification="t", passphrase="a new passphrase") == (
                f"memory {i}".encode()
            )
        with pytest.raises(DecryptionError):
            fresh.recall_memory(ids[0], justification="t", passphrase=PASSPHRASE)
        # New memories join the rotated key.
        new_id = _store(fresh, "after rotation", passphrase="a new passphrase")
        assert fresh.recall_memory(new_id, justification="t") == b"after rotation"

    def test_backup_restore_into_new_vault(self, temp_vault_dir, db_path, kdf_calls):
        vault = MemoryVault(db_path)
        memory_id = _store(vault, "keep me")
        backup_file = str(temp_vault_dir / "backup.json")
        vault.backup(backup_file, passphrase="backup-pass")
        vault.close()

        restored = MemoryVault(str(temp_vault_dir / "restored.db"))
        restored.restore(backup_file, passphrase="backup-pass", skip_confirmation=True)
        assert restored.recall_memory(memory_id, justification="t", passphrase=PASSPHRASE) == b"keep me"
        new_id = _store(restored, "stored after restore")
        assert restored.recall_memory(new_id, justification="t", passphrase=PASSPHRASE) == b"stored after restore"


class TestKeyfiles:
    @pytest.mark.parametrize("edge", [b" ", b"\n", b"\t", b"\r"])
    def test_key_with_whitespace_bytes_loads_intact(self, tmp_path, edge):
        """Regression: keys were .strip()ped, corrupting ~5% of random keys."""
        key = edge + os.urandom(30) + edge
        path = tmp_path / "k.key"
        path.write_bytes(key)
        assert crypto.load_key_from_file(str(path)) == key

    def test_single_trailing_newline_is_tolerated(self, tmp_path):
        key = os.urandom(31) + b"x"
        path = tmp_path / "k.key"
        path.write_bytes(key + b"\n")
        assert crypto.load_key_from_file(str(path)) == key

    def test_generate_keyfile_never_overwrites(self, tmp_path):
        path = crypto.generate_keyfile("agent", directory=str(tmp_path))
        original = open(path, "rb").read()
        with pytest.raises(FileExistsError):
            crypto.generate_keyfile("agent", directory=str(tmp_path))
        assert open(path, "rb").read() == original

    def test_keyfile_profile_roundtrip(self, db_path, no_terminal):
        vault = MemoryVault(db_path, interactive=False)
        vault.create_profile("agent", key_source="KeyFile", generate_keyfile=True)
        memory_id = _store(vault, "no passphrase needed", passphrase=None, encryption_profile="agent")
        vault.close()
        assert MemoryVault(db_path, interactive=False).recall_memory(memory_id, justification="t") == (
            b"no passphrase needed"
        )


class TestNonInteractive:
    def test_missing_passphrase_raises_instead_of_prompting(self, db_path, kdf_calls, no_terminal):
        vault = MemoryVault(db_path, interactive=False)
        with pytest.raises(ProfileKeyMissingError):
            _store(vault, "x", passphrase=None)
        memory_id = _store(vault, "x")
        vault.close()
        with pytest.raises(ProfileKeyMissingError):
            MemoryVault(db_path, interactive=False).recall_memory(memory_id, justification="t")

    def test_level3_fails_closed_without_approver(self, db_path, kdf_calls, no_terminal):
        vault = MemoryVault(db_path, interactive=False)
        memory_id = _store(vault, "sealed", classification=3)
        with pytest.raises(ApprovalRequiredError):
            vault.recall_memory(memory_id, justification="t", passphrase=PASSPHRASE)
        row = vault.conn.execute(
            "SELECT approved, justification FROM recall_log WHERE memory_id = ?", (memory_id,)
        ).fetchone()
        assert row[0] == 0 and "no approver" in row[1]

    def test_approver_callback_decides(self, db_path, kdf_calls, no_terminal):
        seen = []
        decision = {"approve": False}

        def approver(memory_id, classification, requester, justification):
            seen.append((memory_id, classification, requester, justification))
            return decision["approve"]

        vault = MemoryVault(db_path, interactive=False, approver=approver)
        memory_id = _store(vault, "sealed", classification=3)
        with pytest.raises(ApprovalRequiredError):
            vault.recall_memory(memory_id, justification="why", requester="bot", passphrase=PASSPHRASE)
        decision["approve"] = True
        assert vault.recall_memory(memory_id, justification="why", requester="bot", passphrase=PASSPHRASE) == b"sealed"
        assert seen[0] == (memory_id, 3, "bot", "why")

    def test_approver_not_consulted_below_level3(self, db_path, kdf_calls, no_terminal):
        def approver(*args):
            raise AssertionError("approver called for an auto-recall level")

        vault = MemoryVault(db_path, interactive=False, approver=approver)
        memory_id = _store(vault, "private", classification=2)
        assert vault.recall_memory(memory_id, justification="t", passphrase=PASSPHRASE) == b"private"

    def test_level5_fails_closed(self, db_path, kdf_calls, no_terminal):
        vault = MemoryVault(db_path, interactive=False, approver=lambda *a: True)
        memory_id = _store(vault, "black", classification=5)
        with pytest.raises(PhysicalTokenError):
            vault.recall_memory(memory_id, justification="t", passphrase=PASSPHRASE)


class TestDiscovery:
    @pytest.fixture
    def vault(self, db_path, kdf_calls):
        vault = MemoryVault(db_path)
        self.editor = _store(
            vault, "dark mode, vim keys", value_metadata={"summary": "Editor preferences", "tags": ["ui", "editor"]}
        )
        self.deadline = _store(
            vault, "ship by March 15", value_metadata={"summary": "Project deadline", "tags": ["work"]}
        )
        self.bare = _store(vault, "no metadata")
        return vault

    def test_search_finds_by_summary_and_tag(self, vault):
        assert [m["memory_id"] for m in vault.search_memories("editor")] == [self.editor]
        assert [m["memory_id"] for m in vault.search_memories("work")] == [self.deadline]

    def test_search_accepts_natural_language(self, vault):
        """Model-written queries are not FTS5 syntax and must not raise."""
        results = vault.search_memories("what are the user's editor-preferences? (dark-mode)")
        assert results[0]["memory_id"] == self.editor
        for awkward in ['"', "AND", "a OR", "NEAR(", "*", "summary:", "ui -editor", "🙂", "", "   "]:
            vault.search_memories(awkward)

    def test_search_matches_word_prefixes(self, vault):
        assert [m["memory_id"] for m in vault.search_memories("prefer")] == [self.editor]

    def test_search_does_not_reach_content(self, vault):
        assert vault.search_memories("vim") == []

    def test_search_and_list_never_expose_ciphertext(self, vault):
        for info in vault.search_memories("project") + vault.list_memories():
            assert set(info) == {
                "memory_id",
                "created_at",
                "created_by",
                "classification",
                "encryption_profile",
                "intent_ref",
                "metadata",
                "tombstoned",
            }

    def test_tombstoned_memories_are_hidden_by_default(self, vault):
        vault.tombstone_memory(self.editor, "outdated", skip_confirmation=True)
        assert vault.search_memories("editor") == []
        assert self.editor not in [m["memory_id"] for m in vault.list_memories()]
        assert [m["memory_id"] for m in vault.search_memories("editor", include_tombstoned=True)] == [self.editor]

    def test_list_is_newest_first_and_filterable(self, vault):
        sealed = _store(vault, "sealed", classification=3)
        ids = [m["memory_id"] for m in vault.list_memories()]
        assert ids == [sealed, self.bare, self.deadline, self.editor]
        assert sealed not in [m["memory_id"] for m in vault.list_memories(max_classification=2)]
        assert len(vault.list_memories(limit=2)) == 2

    def test_get_memory_info(self, vault):
        info = vault.get_memory_info(self.editor)
        assert info["metadata"] == {"summary": "Editor preferences", "tags": ["ui", "editor"]}
        assert info["tombstoned"] is False
        with pytest.raises(vault_module.MemoryNotFoundError):
            vault.get_memory_info("missing")

    def test_build_fts_query(self):
        assert build_fts_query("dark-mode prefs") == 'value_metadata : ("dark"* OR "mode"* OR "prefs"*)'
        assert build_fts_query("?!") == ""
        assert build_fts_query(None) == ""


def test_init_db_is_silent(temp_vault_dir, capsys):
    """Library use must not write to stdout (it is the protocol channel for stdio servers)."""
    MemoryVault(str(temp_vault_dir / ".memory_vault" / "quiet.db")).close()
    assert capsys.readouterr().out == ""


def test_existing_database_gains_profile_salt_column(temp_vault_dir):
    """Databases created before per-profile salts are migrated in place."""
    path = str(temp_vault_dir / ".memory_vault" / "old.db")
    MemoryVault(path).close()
    conn = sqlite3.connect(path)
    conn.execute("ALTER TABLE encryption_profiles DROP COLUMN kdf_salt")
    conn.commit()
    conn.close()

    vault = MemoryVault(path)
    columns = [row[1] for row in vault.conn.execute("PRAGMA table_info(encryption_profiles)")]
    assert "kdf_salt" in columns
