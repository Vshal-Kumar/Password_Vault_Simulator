"""Unit tests for cryptographic primitives (KDF and AES-256-GCM)."""

import pytest
from password_vault.crypto.kdf import KeyDerivation
from password_vault.crypto.encryption import AESGCMCipher
from password_vault.config import IntegrityError


def test_salt_generation():
    """Test cryptographically secure random salt generation."""
    salt1 = KeyDerivation.generate_salt(16)
    salt2 = KeyDerivation.generate_salt(16)
    assert len(salt1) == 16
    assert len(salt2) == 16
    assert salt1 != salt2


def test_kdf_key_derivation_determinism():
    """Test KDF derives deterministic key for same password and salt."""
    password = "MasterPassword123!"
    salt = KeyDerivation.generate_salt()
    
    key1 = KeyDerivation.derive_key(password, salt)
    key2 = KeyDerivation.derive_key(password, salt)
    
    assert len(key1) == 32
    assert key1 == key2


def test_kdf_key_derivation_different_inputs():
    """Test different passwords or salts produce distinct derived keys."""
    salt1 = KeyDerivation.generate_salt()
    salt2 = KeyDerivation.generate_salt()
    
    key_pass1 = KeyDerivation.derive_key("PasswordOne", salt1)
    key_pass2 = KeyDerivation.derive_key("PasswordTwo", salt1)
    key_salt2 = KeyDerivation.derive_key("PasswordOne", salt2)
    
    assert key_pass1 != key_pass2
    assert key_pass1 != key_salt2


def test_scrypt_key_derivation():
    """Test Scrypt key derivation fallback."""
    password = "MasterPassword123!"
    salt = KeyDerivation.generate_salt()
    
    key = KeyDerivation.derive_key(password, salt, algorithm="Scrypt")
    assert len(key) == 32


def test_argon2id_if_available():
    """Test Argon2id if supported by cryptography library."""
    if KeyDerivation.is_argon2_available():
        password = "MasterPassword123!"
        salt = KeyDerivation.generate_salt()
        key = KeyDerivation.derive_key(password, salt, algorithm="Argon2id")
        assert len(key) == 32


def test_aes_gcm_encrypt_decrypt_roundtrip():
    """Test AES-GCM encryption and decryption roundtrip."""
    key = KeyDerivation.derive_key("TestMasterKey!", KeyDerivation.generate_salt())
    plaintext = b"Sensitive secret credential payload"
    associated_data = b"version=1"
    
    ciphertext, nonce = AESGCMCipher.encrypt(plaintext, key, associated_data)
    assert len(nonce) == 12
    assert ciphertext != plaintext
    
    decrypted = AESGCMCipher.decrypt(ciphertext, key, nonce, associated_data)
    assert decrypted == plaintext


def test_aes_gcm_wrong_key_fails():
    """Test decryption with an incorrect key raises IntegrityError."""
    key1 = KeyDerivation.derive_key("CorrectPassword", KeyDerivation.generate_salt())
    key2 = KeyDerivation.derive_key("WrongPassword", KeyDerivation.generate_salt())
    
    plaintext = b"Top secret data"
    ciphertext, nonce = AESGCMCipher.encrypt(plaintext, key1)
    
    with pytest.raises(IntegrityError):
        AESGCMCipher.decrypt(ciphertext, key2, nonce)


def test_aes_gcm_ciphertext_tampering_fails():
    """Test that modifying even a single byte in ciphertext triggers integrity failure."""
    key = KeyDerivation.derive_key("TestMasterKey!", KeyDerivation.generate_salt())
    plaintext = b"Vault records data"
    
    ciphertext, nonce = AESGCMCipher.encrypt(plaintext, key)
    
    # Flip the first byte of the ciphertext
    tampered_bytes = bytearray(ciphertext)
    tampered_bytes[0] ^= 0xFF
    tampered_ciphertext = bytes(tampered_bytes)
    
    with pytest.raises(IntegrityError):
        AESGCMCipher.decrypt(tampered_ciphertext, key, nonce)


def test_aes_gcm_associated_data_tampering_fails():
    """Test that tampering with associated authenticated data triggers integrity failure."""
    key = KeyDerivation.derive_key("TestMasterKey!", KeyDerivation.generate_salt())
    plaintext = b"Vault records data"
    ad_original = b"version=1"
    ad_tampered = b"version=2"
    
    ciphertext, nonce = AESGCMCipher.encrypt(plaintext, key, associated_data=ad_original)
    
    with pytest.raises(IntegrityError):
        AESGCMCipher.decrypt(ciphertext, key, nonce, associated_data=ad_tampered)
