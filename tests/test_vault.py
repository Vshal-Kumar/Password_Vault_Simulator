"""Unit tests for VaultManager CRUD, search, reveal, and key rotation."""

import pytest
from password_vault.vault.manager import VaultManager
from password_vault.config import (
    VaultLockedError,
    DuplicateServiceError,
    ServiceNotFoundError,
)


@pytest.fixture
def unlocked_vault(tmp_path):
    """Fixture providing an unlocked initialized VaultManager."""
    vault_file = tmp_path / "test_vault.enc"
    manager = VaultManager(vault_file)
    manager.create_vault("MasterPassword123!")
    return manager, vault_file


def test_add_and_get_credential(unlocked_vault):
    """Test adding a credential and retrieving its masked view."""
    manager, _ = unlocked_vault
    cred = manager.add(service="github", username="user123", password="secretpassword")
    
    assert cred.service == "github"
    assert cred.username == "user123"
    
    # Retrieve masked view
    retrieved = manager.get("github")
    assert retrieved["service"] == "github"
    assert retrieved["username"] == "user123"
    assert retrieved["password"] == "********"  # Masked!


def test_reveal_credential(unlocked_vault):
    """Test explicit retrieval of plaintext password via reveal."""
    manager, _ = unlocked_vault
    manager.add(service="github", username="user123", password="secretpassword")
    
    plain = manager.reveal("github")
    assert plain == "secretpassword"


def test_add_duplicate_service_fails(unlocked_vault):
    """Test adding a duplicate service raises DuplicateServiceError."""
    manager, _ = unlocked_vault
    manager.add(service="github", username="user123", password="pass1")
    
    with pytest.raises(DuplicateServiceError, match="already exists"):
        manager.add(service="GITHUB", username="user456", password="pass2")


def test_get_nonexistent_service_fails(unlocked_vault):
    """Test retrieving nonexistent service raises ServiceNotFoundError."""
    manager, _ = unlocked_vault
    with pytest.raises(ServiceNotFoundError, match="not found"):
        manager.get("nonexistent_service")


def test_update_credential(unlocked_vault):
    """Test updating existing credential username and password."""
    manager, _ = unlocked_vault
    manager.add(service="github", username="olduser", password="oldpassword")
    
    updated = manager.update(service="github", username="newuser", password="newpassword")
    assert updated.username == "newuser"
    assert manager.reveal("github") == "newpassword"


def test_delete_credential(unlocked_vault):
    """Test deleting an existing credential."""
    manager, _ = unlocked_vault
    manager.add(service="github", username="user123", password="secret")
    
    deleted_svc = manager.delete("github")
    assert deleted_svc == "github"
    
    with pytest.raises(ServiceNotFoundError):
        manager.get("github")


def test_list_services(unlocked_vault):
    """Test listing stored services alphabetically without passwords."""
    manager, _ = unlocked_vault
    manager.add(service="linkedin", username="u1", password="p1")
    manager.add(service="github", username="u2", password="p2")
    manager.add(service="gmail", username="u3", password="p3")
    
    services = manager.list_services()
    assert services == ["github", "gmail", "linkedin"]


def test_search_services(unlocked_vault):
    """Test searching by keyword in service name, username, and category."""
    manager, _ = unlocked_vault
    manager.add(service="github-work", username="developer", password="p1", category="Dev")
    manager.add(service="gitlab-personal", username="coder", password="p2", category="Dev")
    manager.add(service="aws-console", username="admin-github", password="p3", category="Cloud")
    
    results = manager.search("git")
    matched_services = [r["service"] for r in results]
    assert "github-work" in matched_services
    assert "gitlab-personal" in matched_services
    assert "aws-console" in matched_services  # matched via username 'admin-github'


def test_locked_vault_blocks_operations(unlocked_vault):
    """Test that all CRUD operations fail when vault is locked."""
    manager, _ = unlocked_vault
    manager.add(service="github", username="user", password="pwd")
    manager.lock()
    
    assert not manager.is_unlocked
    
    with pytest.raises(VaultLockedError):
        manager.add(service="gmail", username="u", password="p")
        
    with pytest.raises(VaultLockedError):
        manager.get("github")
        
    with pytest.raises(VaultLockedError):
        manager.reveal("github")
        
    with pytest.raises(VaultLockedError):
        manager.list_services()
        
    with pytest.raises(VaultLockedError):
        manager.search("git")
        
    with pytest.raises(VaultLockedError):
        manager.update(service="github", username="new")
        
    with pytest.raises(VaultLockedError):
        manager.delete("github")


def test_change_master_password(unlocked_vault):
    """Test rotating master password and re-encrypting vault."""
    manager, vault_file = unlocked_vault
    manager.add(service="github", username="user123", password="secretpassword")
    
    # Change master password
    old_pass = "MasterPassword123!"
    new_pass = "NewMasterPassword456!"
    manager.change_master_password(new_pass)
    
    # Lock vault
    manager.lock()
    
    # Attempt unlock with old password should fail
    with pytest.raises(Exception):
        manager.unlock(old_pass)
        
    # Unlock with new password should succeed and recover data
    manager.unlock(new_pass)
    assert manager.is_unlocked
    assert manager.reveal("github") == "secretpassword"
