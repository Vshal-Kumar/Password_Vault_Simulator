"""Configuration and constants for the Password Vault Simulator."""

from pathlib import Path

# Paths
DEFAULT_BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = DEFAULT_BASE_DIR / "data"
DEFAULT_VAULT_PATH = DEFAULT_DATA_DIR / "vault.enc"
DEFAULT_AUDIT_PATH = DEFAULT_DATA_DIR / "vault_audit.log"

# Cryptographic Constants
KDF_ALGORITHM = "Argon2id"
SALT_BYTES = 16
KEY_LENGTH = 32  # 256-bit key for AES-256

# Argon2id Parameters (OWASP recommended parameters for password hashing / KDF)
ARGON2_TIME_COST = 2  # Iterations
ARGON2_MEMORY_COST = 64 * 1024  # 64 MB (in KiB)
ARGON2_PARALLELISM = 2  # Lanes / Threads

# Scrypt Fallback Parameters
SCRYPT_N = 2**14  # CPU/Memory cost (16384)
SCRYPT_R = 8      # Block size
SCRYPT_P = 1      # Parallelization parameter

# Encryption Scheme
CIPHER_ALGORITHM = "AES-256-GCM"
NONCE_BYTES = 12  # 96-bit nonce for AES-GCM

# Security Policies
MIN_MASTER_PASSWORD_LENGTH = 8
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_COOLOFF_SECONDS = 30
SESSION_TIMEOUT_SECONDS = 600  # 10 minutes auto-lock


class VaultSecurityException(Exception):
    """Base exception for all vault security errors."""
    pass


class AuthenticationError(VaultSecurityException):
    """Raised when master password authentication fails."""
    pass


class IntegrityError(VaultSecurityException):
    """Raised when vault ciphertext has been tampered with or corrupted."""
    pass


class VaultLockedError(VaultSecurityException):
    """Raised when an operation is attempted while vault is locked."""
    pass


class VaultAlreadyExistsError(VaultSecurityException):
    """Raised when creating a vault that already exists."""
    pass


class VaultNotFoundError(VaultSecurityException):
    """Raised when accessing a vault that does not exist."""
    pass


class DuplicateServiceError(VaultSecurityException):
    """Raised when attempting to add a service that already exists."""
    pass


class ServiceNotFoundError(VaultSecurityException):
    """Raised when requesting a service that does not exist."""
    pass


class RateLimitExceededError(VaultSecurityException):
    """Raised when maximum failed authentication attempts are exceeded."""
    pass
