"""Authenticated Encryption using AES-256-GCM."""

import os
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from ..config import NONCE_BYTES, IntegrityError, AuthenticationError


class AESGCMCipher:
    """Provides authenticated encryption and decryption using AES-256-GCM."""

    @staticmethod
    def generate_nonce(length: int = NONCE_BYTES) -> bytes:
        """Generate a cryptographically secure 96-bit (12-byte) nonce."""
        return os.urandom(length)

    @classmethod
    def encrypt(
        cls,
        plaintext: bytes,
        key: bytes,
        associated_data: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-256-GCM.

        Args:
            plaintext: Raw bytes to encrypt.
            key: 256-bit (32 bytes) encryption key.
            associated_data: Optional bytes to authenticate without encrypting.

        Returns:
            Tuple of (ciphertext_with_tag, nonce).
        """
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte (256-bit) key.")

        nonce = cls.generate_nonce()
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return ciphertext, nonce

    @classmethod
    def decrypt(
        cls,
        ciphertext: bytes,
        key: bytes,
        nonce: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt and verify data using AES-256-GCM.

        Args:
            ciphertext: Encrypted ciphertext including authentication tag.
            key: 256-bit (32 bytes) encryption key.
            nonce: 12-byte nonce used during encryption.
            associated_data: Associated authenticated data matching encryption call.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            IntegrityError: If decryption/tag verification fails due to tampering or wrong key.
        """
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte (256-bit) key.")

        try:
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag:
            raise IntegrityError(
                "Vault integrity verification failed! Ciphertext is corrupted, tampered with, or master password is incorrect."
            )
        except Exception as e:
            raise IntegrityError(f"Decryption failed: {str(e)}")
