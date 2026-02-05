"""
Smoke tests for Memory Vault core functionality.

These tests verify that the basic operations work correctly:
- Database initialization
- Profile creation
- Memory storage and recall
- Encryption/decryption
- Backup and restore
- Integrity verification
"""
import os
import sys
import json
import pytest
from nacl.exceptions import CryptoError as NaClCryptoError

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vault import MemoryVault
from models import MemoryObject
from db import init_db
from crypto import derive_key_from_passphrase, encrypt_memory, decrypt_memory


class TestDatabaseInitialization:
    """Test database initialization and schema."""

    def test_init_db_creates_tables(self, temp_vault_dir):
        """Verify init_db creates all required tables."""
        db_path = temp_vault_dir / ".memory_vault" / "vault.db"
        conn = init_db(str(db_path))

        cursor = conn.cursor()

        # Check core tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}

        required_tables = {
            'encryption_profiles',
            'memories',
            'recall_log',
            'backups',
            'merkle_leaves',
            'merkle_roots',
            'vault_state',
        }

        for table in required_tables:
            assert table in tables, f"Missing required table: {table}"

        conn.close()

    def test_init_db_idempotent(self, temp_vault_dir):
        """Verify init_db can be called multiple times safely."""
        db_path = temp_vault_dir / ".memory_vault" / "vault.db"

        # Initialize twice
        conn1 = init_db(str(db_path))
        conn1.close()

        conn2 = init_db(str(db_path))
        conn2.close()

        # Should not raise any errors


class TestCryptography:
    """Test cryptographic operations."""

    def test_key_derivation_deterministic(self, sample_passphrase):
        """Verify same passphrase + salt produces same key."""
        key1, salt = derive_key_from_passphrase(sample_passphrase)
        key2, _ = derive_key_from_passphrase(sample_passphrase, salt)

        assert key1 == key2

    def test_key_derivation_different_salts(self, sample_passphrase):
        """Verify different salts produce different keys."""
        key1, salt1 = derive_key_from_passphrase(sample_passphrase)
        key2, salt2 = derive_key_from_passphrase(sample_passphrase)

        # Different random salts should produce different keys
        assert salt1 != salt2
        assert key1 != key2

    def test_encrypt_decrypt_roundtrip(self, sample_passphrase, sample_content):
        """Verify content can be encrypted and decrypted."""
        key, salt = derive_key_from_passphrase(sample_passphrase)

        ciphertext, nonce = encrypt_memory(key, sample_content)
        plaintext = decrypt_memory(key, ciphertext, nonce)

        assert plaintext == sample_content

    def test_encryption_produces_different_ciphertext(self, sample_passphrase, sample_content):
        """Verify same content encrypted twice produces different ciphertext."""
        key, _ = derive_key_from_passphrase(sample_passphrase)

        ciphertext1, nonce1 = encrypt_memory(key, sample_content)
        ciphertext2, nonce2 = encrypt_memory(key, sample_content)

        # Nonces should be different (random)
        assert nonce1 != nonce2
        # Ciphertext should be different due to different nonces
        assert ciphertext1 != ciphertext2

    def test_wrong_key_fails_decryption(self, sample_passphrase, sample_content):
        """Verify decryption fails with wrong key."""
        key1, _ = derive_key_from_passphrase(sample_passphrase)
        key2, _ = derive_key_from_passphrase("wrong-passphrase")

        ciphertext, nonce = encrypt_memory(key1, sample_content)

        with pytest.raises(NaClCryptoError):
            decrypt_memory(key2, ciphertext, nonce)


class TestMemoryVault:
    """Test MemoryVault class operations."""

    def test_create_profile(self, temp_vault_dir, sample_passphrase):
        """Verify profile creation works."""
        vault = MemoryVault(str(temp_vault_dir / ".memory_vault" / "vault.db"))

        profile_id = vault.create_profile(
            profile_id="test-profile",
            cipher="AES-256-GCM",
            key_source="HumanPassphrase",
            passphrase=sample_passphrase
        )

        assert profile_id == "test-profile"

        # Verify profile exists
        profiles = vault.list_profiles()
        assert any(p['profile_id'] == 'test-profile' for p in profiles)

    def test_store_and_recall_memory(self, temp_vault_dir, sample_passphrase, sample_content):
        """Verify memory can be stored and recalled."""
        vault = MemoryVault(str(temp_vault_dir / ".memory_vault" / "vault.db"))

        # Create profile
        vault.create_profile(
            profile_id="test-profile",
            cipher="AES-256-GCM",
            key_source="HumanPassphrase",
            passphrase=sample_passphrase
        )

        # Create memory object
        memory = MemoryObject(
            memory_id="test-memory-001",
            content_plaintext=sample_content,
            classification=1,  # Working - no approval needed
            encryption_profile="test-profile",
        )

        # Store memory
        memory_id = vault.store_memory(memory, passphrase=sample_passphrase)
        assert memory_id == "test-memory-001"

        # Recall memory (classification 1 allows auto-recall)
        recalled = vault.recall_memory(
            memory_id="test-memory-001",
            justification="Unit test recall",
            passphrase=sample_passphrase,
            skip_boundary_check=True  # Skip for testing
        )

        assert recalled == sample_content

    def test_store_memory_with_metadata(self, temp_vault_dir, sample_passphrase, sample_content, sample_metadata):
        """Verify memory storage with metadata."""
        vault = MemoryVault(str(temp_vault_dir / ".memory_vault" / "vault.db"))

        vault.create_profile(
            profile_id="test-profile",
            cipher="AES-256-GCM",
            key_source="HumanPassphrase",
            passphrase=sample_passphrase
        )

        memory = MemoryObject(
            memory_id="test-memory-meta",
            content_plaintext=sample_content,
            classification=1,
            encryption_profile="test-profile",
            value_metadata=sample_metadata,
        )

        vault.store_memory(memory, passphrase=sample_passphrase)

        # Verify metadata is stored (via search)
        # Note: FTS5 treats hyphens specially, so use quotes for literal search
        from db import search_memories_metadata
        results = search_memories_metadata(vault.conn, '"unit-test"')
        assert len(results) > 0

    def test_classification_levels(self, temp_vault_dir, sample_passphrase, sample_content):
        """Verify different classification levels are stored correctly."""
        vault = MemoryVault(str(temp_vault_dir / ".memory_vault" / "vault.db"))

        vault.create_profile(
            profile_id="test-profile",
            cipher="AES-256-GCM",
            key_source="HumanPassphrase",
            passphrase=sample_passphrase
        )

        for level in range(6):  # 0-5
            memory = MemoryObject(
                memory_id=f"test-level-{level}",
                content_plaintext=f"Level {level} content".encode(),
                classification=level,
                encryption_profile="test-profile",
            )
            vault.store_memory(memory, passphrase=sample_passphrase)

        # Verify all were stored
        cursor = vault.conn.cursor()
        cursor.execute("SELECT memory_id, classification FROM memories ORDER BY classification")
        rows = cursor.fetchall()

        assert len(rows) == 6
        for i, row in enumerate(rows):
            assert row[1] == i  # Classification matches

    def test_cooldown_enforcement(self, temp_vault_dir, sample_passphrase, sample_content):
        """Verify cooldown is enforced on recall."""
        vault = MemoryVault(str(temp_vault_dir / ".memory_vault" / "vault.db"))

        vault.create_profile(
            profile_id="test-profile",
            cipher="AES-256-GCM",
            key_source="HumanPassphrase",
            passphrase=sample_passphrase
        )

        memory = MemoryObject(
            memory_id="test-cooldown",
            content_plaintext=sample_content,
            classification=1,
            encryption_profile="test-profile",
            access_policy={"cooldown_seconds": 3600},  # 1 hour cooldown
        )

        vault.store_memory(memory, passphrase=sample_passphrase)

        # First recall should work
        result1 = vault.recall_memory(
            memory_id="test-cooldown",
            justification="First recall",
            passphrase=sample_passphrase,
            skip_boundary_check=True
        )
        assert result1 == sample_content

        # Second immediate recall should fail due to cooldown
        with pytest.raises(Exception) as exc_info:
            vault.recall_memory(
                memory_id="test-cooldown",
                justification="Second recall",
                passphrase=sample_passphrase,
                skip_boundary_check=True
            )
        assert "cooldown" in str(exc_info.value).lower()


class TestBackupRestore:
    """Test backup and restore functionality."""

    def test_backup_creates_file(self, temp_vault_dir, sample_passphrase, sample_content):
        """Verify backup creates a valid file."""
        vault = MemoryVault(str(temp_vault_dir / ".memory_vault" / "vault.db"))

        vault.create_profile(
            profile_id="test-profile",
            cipher="AES-256-GCM",
            key_source="HumanPassphrase",
            passphrase=sample_passphrase
        )

        memory = MemoryObject(
            memory_id="backup-test",
            content_plaintext=sample_content,
            classification=1,
            encryption_profile="test-profile",
        )
        vault.store_memory(memory, passphrase=sample_passphrase)

        # Create backup
        backup_path = temp_vault_dir / "test-backup.json"
        vault.backup(
            output_file=str(backup_path),
            passphrase=sample_passphrase,
            description="Test backup"
        )

        assert backup_path.exists()

        # Verify backup content is valid encrypted JSON
        with open(backup_path) as f:
            backup_data = json.load(f)

        # Backup is encrypted - check for encrypted format fields
        assert "version" in backup_data
        assert "salt" in backup_data
        assert "nonce" in backup_data
        assert "ciphertext" in backup_data

    def test_restore_recovers_data(self, temp_vault_dir, sample_passphrase, sample_content):
        """Verify restore recovers backed up data."""
        db_path = temp_vault_dir / ".memory_vault" / "vault.db"
        vault = MemoryVault(str(db_path))

        vault.create_profile(
            profile_id="restore-profile",
            cipher="AES-256-GCM",
            key_source="HumanPassphrase",
            passphrase=sample_passphrase,
            exportable=True  # Required for backup/restore
        )

        memory = MemoryObject(
            memory_id="restore-test",
            content_plaintext=sample_content,
            classification=1,
            encryption_profile="restore-profile",
        )
        vault.store_memory(memory, passphrase=sample_passphrase)

        # Create backup
        backup_path = temp_vault_dir / "restore-backup.json"
        vault.backup(
            output_file=str(backup_path),
            passphrase=sample_passphrase,
            description="Restore test backup"
        )

        vault.close()

        # Delete original database
        os.remove(db_path)

        # Create new vault and restore
        vault2 = MemoryVault(str(db_path))
        vault2.restore(
            backup_file=str(backup_path),
            passphrase=sample_passphrase,
            skip_confirmation=True
        )

        # Verify data was restored
        profiles = vault2.list_profiles()
        assert any(p['profile_id'] == 'restore-profile' for p in profiles)

        # Recall should work
        recalled = vault2.recall_memory(
            memory_id="restore-test",
            justification="Post-restore recall",
            passphrase=sample_passphrase,
            skip_boundary_check=True
        )
        assert recalled == sample_content


class TestIntegrity:
    """Test integrity verification."""

    def test_verify_integrity_passes(self, temp_vault_dir, sample_passphrase, sample_content):
        """Verify integrity check passes for valid vault."""
        vault = MemoryVault(str(temp_vault_dir / ".memory_vault" / "vault.db"))

        vault.create_profile(
            profile_id="integrity-profile",
            cipher="AES-256-GCM",
            key_source="HumanPassphrase",
            passphrase=sample_passphrase
        )

        memory = MemoryObject(
            memory_id="integrity-test",
            content_plaintext=sample_content,
            classification=1,
            encryption_profile="integrity-profile",
        )
        vault.store_memory(memory, passphrase=sample_passphrase)

        # Recall to create audit trail
        vault.recall_memory(
            memory_id="integrity-test",
            justification="Create audit trail",
            passphrase=sample_passphrase,
            skip_boundary_check=True
        )

        # Verify integrity
        result = vault.verify_integrity()
        assert result is True


class TestLockdown:
    """Test lockdown mode functionality."""

    def test_lockdown_blocks_recalls(self, temp_vault_dir, sample_passphrase, sample_content):
        """Verify lockdown mode blocks all recalls."""
        vault = MemoryVault(str(temp_vault_dir / ".memory_vault" / "vault.db"))

        vault.create_profile(
            profile_id="lockdown-profile",
            cipher="AES-256-GCM",
            key_source="HumanPassphrase",
            passphrase=sample_passphrase
        )

        memory = MemoryObject(
            memory_id="lockdown-test",
            content_plaintext=sample_content,
            classification=1,
            encryption_profile="lockdown-profile",
        )
        vault.store_memory(memory, passphrase=sample_passphrase)

        # Enable lockdown
        vault.enable_lockdown(reason="Test lockdown")

        # Recall should fail
        with pytest.raises(Exception) as exc_info:
            vault.recall_memory(
                memory_id="lockdown-test",
                justification="Should fail",
                passphrase=sample_passphrase,
                skip_boundary_check=True
            )
        assert "lockdown" in str(exc_info.value).lower()

        # Disable lockdown
        vault.disable_lockdown()

        # Recall should work again
        recalled = vault.recall_memory(
            memory_id="lockdown-test",
            justification="After lockdown disabled",
            passphrase=sample_passphrase,
            skip_boundary_check=True
        )
        assert recalled == sample_content


class TestTombstones:
    """Test memory tombstone functionality."""

    def test_tombstone_blocks_recall(self, temp_vault_dir, sample_passphrase, sample_content):
        """Verify tombstoned memories cannot be recalled."""
        vault = MemoryVault(str(temp_vault_dir / ".memory_vault" / "vault.db"))

        vault.create_profile(
            profile_id="tombstone-profile",
            cipher="AES-256-GCM",
            key_source="HumanPassphrase",
            passphrase=sample_passphrase
        )

        memory = MemoryObject(
            memory_id="tombstone-test",
            content_plaintext=sample_content,
            classification=1,
            encryption_profile="tombstone-profile",
        )
        vault.store_memory(memory, passphrase=sample_passphrase)

        # Tombstone the memory
        vault.tombstone_memory(
            memory_id="tombstone-test",
            reason="Test tombstone",
            skip_confirmation=True
        )

        # Recall should fail
        with pytest.raises(Exception) as exc_info:
            vault.recall_memory(
                memory_id="tombstone-test",
                justification="Should fail",
                passphrase=sample_passphrase,
                skip_boundary_check=True
            )
        assert "tombstone" in str(exc_info.value).lower()
