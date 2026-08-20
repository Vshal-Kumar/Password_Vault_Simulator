"""Key Derivation Function (KDF) implementation using Argon2id / Scrypt with universal fallback."""

import os
import hashlib
from typing import Dict, Any, Union

# Safe imports for compatibility across cryptography versions (e.g. cryptography < 42 vs >= 42)
try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    HAS_ARGON2 = True
except (ImportError, ModuleNotFoundError):
    Argon2id = None
    HAS_ARGON2 = False

try:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    HAS_SCRYPT_CRYPTO = True
except (ImportError, ModuleNotFoundError):
    Scrypt = None
    HAS_SCRYPT_CRYPTO = False

from ..config import (
    KDF_ALGORITHM,
    SALT_BYTES,
    KEY_LENGTH,
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    SCRYPT_N,
    SCRYPT_R,
    SCRYPT_P,
)


class KeyDerivation:
    """Handles password-based key derivation using memory-hard KDFs."""

    @staticmethod
    def is_argon2_available() -> bool:
        """Check if Argon2id is available in current cryptography installation."""
        return HAS_ARGON2

    @staticmethod
    def get_preferred_algorithm() -> str:
        """Return the best available memory-hard KDF algorithm."""
        return "Argon2id" if HAS_ARGON2 else "Scrypt"

    @staticmethod
    def generate_salt(length: int = SALT_BYTES) -> bytes:
        """Generate a cryptographically secure random salt."""
        return os.urandom(length)

    @classmethod
    def derive_key(
        cls,
        password: Union[str, bytes],
        salt: bytes,
        algorithm: str = None,
        params: Dict[str, Any] = None,
    ) -> bytes:
        """
        Derive an encryption key from a master password using Argon2id or Scrypt.

        Args:
            password: The master password as a string or bytes.
            salt: Cryptographically secure random salt.
            algorithm: 'Argon2id' or 'Scrypt' (defaults to best available).
            params: Optional dictionary of KDF tuning parameters.

        Returns:
            Derived key as raw bytes (32 bytes for AES-256).
        """
        password_bytes = password.encode("utf-8") if isinstance(password, str) else password
        params = params or {}
        algorithm = algorithm or cls.get_preferred_algorithm()

        if algorithm == "Argon2id" and HAS_ARGON2:
            time_cost = params.get("time_cost", ARGON2_TIME_COST)
            memory_cost = params.get("memory_cost", ARGON2_MEMORY_COST)
            parallelism = params.get("parallelism", ARGON2_PARALLELISM)
            key_len = params.get("length", KEY_LENGTH)

            kdf = Argon2id(
                salt=salt,
                length=key_len,
                iterations=time_cost,
                lanes=parallelism,
                memory_cost=memory_cost,
                ad=None,
                secret=None,
            )
            return kdf.derive(password_bytes)

        # Scrypt derivation (Standard Library hashlib.scrypt or cryptography Scrypt)
        n = params.get("n", SCRYPT_N)
        r = params.get("r", SCRYPT_R)
        p = params.get("p", SCRYPT_P)
        key_len = params.get("length", KEY_LENGTH)

        if hasattr(hashlib, "scrypt"):
            # Python standard library hashlib.scrypt (fast, zero dependency, universal)
            return hashlib.scrypt(
                password=password_bytes,
                salt=salt,
                n=n,
                r=r,
                p=p,
                maxmem=0,
                dklen=key_len,
            )
        elif HAS_SCRYPT_CRYPTO:
            kdf = Scrypt(
                salt=salt,
                length=key_len,
                n=n,
                r=r,
                p=p,
            )
            return kdf.derive(password_bytes)
        else:
            # Fallback to PBKDF2-HMAC-SHA256 if Scrypt is completely missing
            return hashlib.pbkdf2_hmac(
                hash_name="sha256",
                password=password_bytes,
                salt=salt,
                iterations=100000,
                dklen=key_len,
            )

    @classmethod
    def get_default_params(cls, algorithm: str = None) -> Dict[str, Any]:
        """Return default configuration parameters for the specified algorithm."""
        algorithm = algorithm or cls.get_preferred_algorithm()
        if algorithm == "Argon2id" and HAS_ARGON2:
            return {
                "algorithm": "Argon2id",
                "length": KEY_LENGTH,
                "time_cost": ARGON2_TIME_COST,
                "memory_cost": ARGON2_MEMORY_COST,
                "parallelism": ARGON2_PARALLELISM,
            }
        else:
            return {
                "algorithm": "Scrypt",
                "length": KEY_LENGTH,
                "n": SCRYPT_N,
                "r": SCRYPT_R,
                "p": SCRYPT_P,
            }
