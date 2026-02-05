"""
Pytest configuration and shared fixtures for Memory Vault tests.
"""
import os
import sys
import pytest

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def temp_vault_dir(tmp_path):
    """Create a temporary directory for vault data."""
    vault_dir = tmp_path / ".memory_vault"
    vault_dir.mkdir()
    keys_dir = vault_dir / "keys"
    keys_dir.mkdir()

    # Set environment to use temp directory
    old_home = os.environ.get('HOME')
    os.environ['HOME'] = str(tmp_path)

    yield tmp_path

    # Restore original HOME
    if old_home:
        os.environ['HOME'] = old_home


@pytest.fixture
def vault_db_path(temp_vault_dir):
    """Return path to temporary vault database."""
    return temp_vault_dir / ".memory_vault" / "vault.db"


@pytest.fixture
def sample_passphrase():
    """Return a sample passphrase for testing."""
    return "test-passphrase-for-unit-tests-12345"


@pytest.fixture
def sample_content():
    """Return sample content for testing."""
    return b"This is test content for Memory Vault encryption."


@pytest.fixture
def sample_metadata():
    """Return sample metadata for testing."""
    return {
        "type": "test",
        "importance": "low",
        "category": "unit-test"
    }
