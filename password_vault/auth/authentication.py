"""Authentication controller managing login attempts, lockout, and session state."""

import time
from typing import Optional
from pathlib import Path

from ..config import (
    MAX_FAILED_ATTEMPTS,
    LOCKOUT_COOLOFF_SECONDS,
    SESSION_TIMEOUT_SECONDS,
    AuthenticationError,
    RateLimitExceededError,
    IntegrityError,
)
from ..vault.manager import VaultManager
from ..security.audit import AuditLogger
from ..security.validation import InputValidator


class Authenticator:
    """Controls authentication, rate-limiting, and session security."""

    def __init__(self, manager: VaultManager, audit_logger: Optional[AuditLogger] = None):
        self.manager = manager
        self.audit = audit_logger or AuditLogger()
        self._failed_attempts = 0
        self._lockout_until = 0.0
        self._last_active_time = 0.0

    @property
    def failed_attempts(self) -> int:
        return self._failed_attempts

    def _check_rate_limit(self) -> None:
        """Check if authentication is temporarily locked out."""
        now = time.time()
        if now < self._lockout_until:
            remaining = int(self._lockout_until - now)
            raise RateLimitExceededError(
                f"Too many failed attempts. Access is locked out for {remaining} more seconds."
            )

    def _register_failure(self) -> None:
        """Increment failed attempts and apply lockout if threshold reached."""
        self._failed_attempts += 1
        if self._failed_attempts >= MAX_FAILED_ATTEMPTS:
            self._lockout_until = time.time() + LOCKOUT_COOLOFF_SECONDS
            self.audit.log_event("AUTH_LOCKED_OUT", {"failed_attempts": self._failed_attempts})
            raise RateLimitExceededError(
                f"Authentication failed {self._failed_attempts} times. Vault is locked for {LOCKOUT_COOLOFF_SECONDS} seconds."
            )
        self.audit.log_event("AUTH_FAILURE", {"failed_attempts": self._failed_attempts})

    def _register_success(self) -> None:
        """Reset failed attempt counters on successful unlock."""
        self._failed_attempts = 0
        self._lockout_until = 0.0
        self._last_active_time = time.time()
        self.audit.log_event("AUTH_SUCCESS")

    def create_vault(
        self,
        master_password: str,
        confirm_password: str,
        kdf_algorithm: str = "Argon2id",
    ) -> None:
        """
        Create a new vault after validating password inputs.

        Args:
            master_password: New master password.
            confirm_password: Confirmation of master password.
            kdf_algorithm: Argon2id or Scrypt.
        """
        if master_password != confirm_password:
            raise AuthenticationError("Passwords do not match.")

        valid, err = InputValidator.validate_master_password(master_password)
        if not valid:
            raise AuthenticationError(err)

        self.manager.create_vault(master_password, kdf_algorithm=kdf_algorithm)
        self._register_success()
        self.audit.log_event("VAULT_CREATED", {"kdf": kdf_algorithm})

    def authenticate(self, master_password: str) -> bool:
        """
        Authenticate user and unlock vault.

        Args:
            master_password: Master password entered by user.

        Returns:
            True if unlocked successfully.

        Raises:
            RateLimitExceededError: If rate limit exceeded.
            AuthenticationError: If master password is incorrect.
        """
        self._check_rate_limit()

        try:
            self.manager.unlock(master_password)
            self._register_success()
            return True
        except IntegrityError:
            self._register_failure()
            raise AuthenticationError("Authentication failed.\nVault remains locked.")
        except Exception as e:
            self._register_failure()
            raise AuthenticationError(f"Authentication failed: {str(e)}\nVault remains locked.")

    def check_session_timeout(self) -> bool:
        """
        Check if the active session has timed out due to inactivity.

        Returns:
            True if session timed out and was locked.
        """
        if not self.manager.is_unlocked:
            return False

        if time.time() - self._last_active_time > SESSION_TIMEOUT_SECONDS:
            self.lock_vault()
            self.audit.log_event("SESSION_TIMEOUT_LOCKED")
            return True

        return False

    def touch_session(self) -> None:
        """Update last active timestamp for active session."""
        self._last_active_time = time.time()

    def lock_vault(self) -> None:
        """Lock the vault and clear session."""
        if self.manager.is_unlocked:
            self.manager.lock()
            self.audit.log_event("VAULT_LOCKED")
