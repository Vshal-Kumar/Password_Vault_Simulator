"""Unit and security tests for VaultStorage and file tampering detection."""

import base64
import json
import pytest
from password_vault.vault.storage import VaultStorage
from password_vault.vault.models import VaultPayload, Credential
from password_vault.crypto.kdf import KeyDerivation
from password_vault.config import IntegrityError, VaultNotFoundError


@pytest.fixture
def storage_setup(tmp_path):
    """Fixture providing VaultStorage in temporary test directory."""
    vault_file = tmp_path / "test_storage.enc"
    storage = VaultStorage(vault_file)
    master_password = "StorageMasterPassword123!"
    derived_key = storage.initialize_vault(master_password)
    return storage, vault_file, master_password, derived_key


def test_storage_initialization_creates_file(storage_setup):
    """Test initializing storage creates a valid JSON envelope file."""
    storage, vault_file, _, _ = storage_setup
    assert storage.exists()
    
    with open(vault_file, "r") as f:
        data = json.load(f)
        assert data["version"] == 1
        assert "kdf" in data
        assert "vault" in data
        assert "ciphertext" in data["vault"]


def test_storage_save_and_load_roundtrip(storage_setup):
    """Test saving credentials and loading them with unlock_and_load."""
    storage, _, master_password, derived_key = storage_setup
    
    # Save a payload with 2 credentials
    payload = VaultPayload()
    payload.records["github"] = Credential(service="github", username="user1", password="pass1")
    payload.records["gmail"] = Credential(service="gmail", username="user2", password="pass2")
    
    salt = KeyDerivation.generate_salt()
    kdf_params = KeyDerivation.get_default_params("Argon2id")
    key = KeyDerivation.derive_key(master_password, salt, "Argon2id", kdf_params)
    
    storage.save(payload, key, salt, kdf_params)
    
    # Load and unlock
    loaded_payload, loaded_key, _, _ = storage.unlock_and_load(master_password)
    assert len(loaded_payload.records) == 2
    assert loaded_payload.records["github"].password == "pass1"
    assert loaded_payload.records["gmail"].password == "pass2"


def test_tampered_ciphertext_detection(storage_setup):
    """Test that altering base64 ciphertext in the file causes unlock to fail."""
    storage, vault_file, master_password, _ = storage_setup
    
    # Read the envelope
    with open(vault_file, "r") as f:
        data = json.load(f)
    
    # Tamper with the ciphertext
    raw_ct = base64.b64decode(data["vault"]["ciphertext"])
    tampered_ct = bytearray(raw_ct)
    tampered_ct[5] ^= 0x55  # flip bits
    data["vault"]["ciphertext"] = base64.b64encode(bytes(tampered_ct)).decode("ascii")
    
    with open(vault_file, "w") as f:
        json.dump(data, f)
    
    # Attempting unlock must raise IntegrityError
    with pytest.raises(IntegrityError):
        storage.unlock_and_load(master_password)


def test_tampered_salt_detection(storage_setup):
    """Test that tampering with KDF salt causes decryption/auth verification to fail."""
    storage, vault_file, master_password, _ = storage_setup
    
    with open(vault_file, "r") as f:
        data = json.load(f)
    
    raw_salt = base64.b64decode(data["kdf"]["salt"])
    tampered_salt = bytearray(raw_salt)
    tampered_salt[0] ^= 0xFF
    data["kdf"]["salt"] = base64.b64encode(bytes(tampered_salt)).decode("ascii")
    
    with open(vault_file, "w") as f:
        json.dump(data, f)
        
    with pytest.raises(IntegrityError):
        storage.unlock_and_load(master_password)


def test_backup_and_restore(storage_setup, tmp_path):
    """Test creating backup and restoring from it."""
    storage, vault_file, master_password, _ = storage_setup
    backup_file = tmp_path / "backup.enc"
    
    storage.create_backup(backup_file)
    assert backup_file.exists()
    
    # Corrupt the original vault
    with open(vault_file, "w") as f:
        f.write("CORRUPTED")
        
    with pytest.raises(IntegrityError):
        storage.unlock_and_load(master_password)
        
    # Restore from backup
    storage.restore_from_backup(backup_file)
    
    # Should unlock cleanly now
    payload, _, _, _ = storage.unlock_and_load(master_password)
    assert isinstance(payload, VaultPayload)
