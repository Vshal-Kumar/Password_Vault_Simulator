"""Unit and integration tests for Authentication and Session Security."""

import pytest
from password_vault.vault.manager import VaultManager
from password_vault.auth.authentication import Authenticator
from password_vault.security.audit import AuditLogger
from password_vault.config import (
    AuthenticationError,
    RateLimitExceededError,
    MAX_FAILED_ATTEMPTS,
)


@pytest.fixture
def temp_vault(tmp_path):
    """Fixture providing a clean VaultManager and Authenticator in temporary directory."""
    vault_file = tmp_path / "test_vault.enc"
    audit_file = tmp_path / "test_audit.log"
    manager = VaultManager(vault_file)
    audit = AuditLogger(audit_file)
    auth = Authenticator(manager, audit)
    return manager, auth, vault_file


def test_create_vault_success(temp_vault):
    """Test creating a new vault with matching valid password."""
    manager, auth, vault_file = temp_vault
    auth.create_vault("MasterPassword123!", "MasterPassword123!")
    assert manager.is_unlocked
    assert vault_file.exists()


def test_create_vault_password_mismatch(temp_vault):
    """Test vault creation fails when confirmation password does not match."""
    manager, auth, _ = temp_vault
    with pytest.raises(AuthenticationError, match="Passwords do not match"):
        auth.create_vault("PasswordOne123!", "PasswordTwo123!")


def test_create_vault_password_too_short(temp_vault):
    """Test vault creation fails with short passwords."""
    manager, auth, _ = temp_vault
    with pytest.raises(AuthenticationError, match="at least 8 characters"):
        auth.create_vault("short", "short")


def test_authentication_success_and_lock(temp_vault):
    """Test successful authentication and explicit locking."""
    manager, auth, _ = temp_vault
    password = "MasterPassword123!"
    auth.create_vault(password, password)
    
    # Lock vault
    auth.lock_vault()
    assert not manager.is_unlocked
    
    # Re-authenticate
    success = auth.authenticate(password)
    assert success
    assert manager.is_unlocked


def test_authentication_failure_wrong_password(temp_vault):
    """Test authentication fails on incorrect master password."""
    manager, auth, _ = temp_vault
    password = "CorrectPassword123!"
    auth.create_vault(password, password)
    auth.lock_vault()
    
    with pytest.raises(AuthenticationError, match="Authentication failed"):
        auth.authenticate("WrongPassword123!")
    
    assert not manager.is_unlocked
    assert auth.failed_attempts == 1


def test_rate_limiting_lockout_on_consecutive_failures(temp_vault):
    """Test rate limiting triggers after MAX_FAILED_ATTEMPTS consecutive failures."""
    manager, auth, _ = temp_vault
    password = "CorrectPassword123!"
    auth.create_vault(password, password)
    auth.lock_vault()
    
    for i in range(MAX_FAILED_ATTEMPTS - 1):
        with pytest.raises(AuthenticationError):
            auth.authenticate(f"WrongPass_{i}")
    
    assert auth.failed_attempts == MAX_FAILED_ATTEMPTS - 1
    
    # Next failure hits the rate limit threshold
    with pytest.raises(RateLimitExceededError):
        auth.authenticate("AnotherWrongPass")
    
    # Immediate subsequent calls are blocked by lockout
    with pytest.raises(RateLimitExceededError):
        auth.authenticate("AnyPassword")
