"""Vault Manager coordinating CRUD operations, in-memory state, and encrypted persistence."""

from pathlib import Path
from typing import List, Dict, Any, Optional

from ..config import (
    DEFAULT_VAULT_PATH,
    VaultLockedError,
    VaultAlreadyExistsError,
    VaultNotFoundError,
    DuplicateServiceError,
    ServiceNotFoundError,
)
from .models import Credential, VaultPayload, current_utc_iso
from .storage import VaultStorage
from ..crypto.kdf import KeyDerivation


class VaultManager:
    """Manages high-level credential operations and vault lifecycle."""

    def __init__(self, file_path: Optional[Path] = None):
        self.storage = VaultStorage(file_path or DEFAULT_VAULT_PATH)
        self._payload: Optional[VaultPayload] = None
        self._key: Optional[bytes] = None
        self._salt: Optional[bytes] = None
        self._kdf_params: Optional[Dict[str, Any]] = None
        self._is_unlocked: bool = False

    @property
    def is_unlocked(self) -> bool:
        """Return whether the vault is currently unlocked."""
        return self._is_unlocked

    @property
    def is_initialized(self) -> bool:
        """Check if the vault file exists on disk."""
        return self.storage.exists()

    def _ensure_unlocked(self) -> None:
        """Raise VaultLockedError if the vault is not unlocked."""
        if not self._is_unlocked or self._payload is None or self._key is None:
            raise VaultLockedError("Vault is locked. Authentication required.")

    def create_vault(
        self,
        master_password: str,
        kdf_algorithm: str = "Argon2id",
        overwrite: bool = False,
    ) -> None:
        """
        Create a new encrypted vault on disk.

        Args:
            master_password: Plaintext master password.
            kdf_algorithm: Argon2id or Scrypt.
            overwrite: Whether to overwrite existing vault file.

        Raises:
            VaultAlreadyExistsError: If vault exists and overwrite is False.
        """
        if self.storage.exists() and not overwrite:
            raise VaultAlreadyExistsError("A vault already exists. Unlock it or remove it first.")

        salt = KeyDerivation.generate_salt()
        kdf_params = KeyDerivation.get_default_params(kdf_algorithm)
        derived_key = KeyDerivation.derive_key(
            password=master_password,
            salt=salt,
            algorithm=kdf_algorithm,
            params=kdf_params,
        )

        payload = VaultPayload()
        self.storage.save(payload, derived_key, salt, kdf_params)

        self._payload = payload
        self._key = derived_key
        self._salt = salt
        self._kdf_params = kdf_params
        self._is_unlocked = True

    def unlock(self, master_password: str) -> None:
        """
        Unlock vault with master password, loading decrypted records into memory.

        Args:
            master_password: User entered master password.

        Raises:
            IntegrityError: If password is wrong or ciphertext has been altered.
        """
        payload, key, salt, kdf_params = self.storage.unlock_and_load(master_password)
        self._payload = payload
        self._key = key
        self._salt = salt
        self._kdf_params = kdf_params
        self._is_unlocked = True

    def lock(self) -> None:
        """Lock the vault and securely wipe sensitive credentials and key from memory."""
        if self._payload:
            self._payload.clear()
        self._payload = None

        if self._key:
            # Overwrite memory buffer
            self._key = b"\x00" * len(self._key)
            self._key = None

        self._salt = None
        self._kdf_params = None
        self._is_unlocked = False

    def _persist(self) -> None:
        """Encrypt and write current payload to disk."""
        self._ensure_unlocked()
        self.storage.save(self._payload, self._key, self._salt, self._kdf_params)

    def add(
        self,
        service: str,
        username: str,
        password: str,
        category: str = "General",
        notes: str = "",
    ) -> Credential:
        """
        Add a new service credential.

        Args:
            service: Service name (e.g. 'github').
            username: Account username/email.
            password: Password secret.
            category: Category or tag (e.g. 'Work', 'Personal').
            notes: Optional notes.

        Returns:
            The created Credential object.

        Raises:
            DuplicateServiceError: If service already exists.
        """
        self._ensure_unlocked()
        svc_key = service.strip().lower()
        if not svc_key:
            raise ValueError("Service name cannot be empty.")

        if svc_key in self._payload.records:
            raise DuplicateServiceError(f"Service '{service}' already exists. Use UPDATE instead.")

        cred = Credential(
            service=service.strip(),
            username=username.strip(),
            password=password,
            category=category.strip() or "General",
            notes=notes.strip(),
        )

        self._payload.records[svc_key] = cred
        self._persist()
        return cred

    def get(self, service: str) -> Dict[str, Any]:
        """
        Retrieve service details with password masked.

        Args:
            service: Service name.

        Returns:
            Dictionary with masked password (e.g. '********').

        Raises:
            ServiceNotFoundError: If service is not in vault.
        """
        self._ensure_unlocked()
        svc_key = service.strip().lower()
        if svc_key not in self._payload.records:
            raise ServiceNotFoundError(f"Service '{service}' not found in vault.")

        return self._payload.records[svc_key].masked_view()

    def reveal(self, service: str) -> str:
        """
        Retrieve the plaintext password for a service after explicit request.

        Args:
            service: Service name.

        Returns:
            Plaintext password.

        Raises:
            ServiceNotFoundError: If service is not found.
        """
        self._ensure_unlocked()
        svc_key = service.strip().lower()
        if svc_key not in self._payload.records:
            raise ServiceNotFoundError(f"Service '{service}' not found in vault.")

        return self._payload.records[svc_key].password

    def update(
        self,
        service: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        category: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Credential:
        """
        Update an existing credential.

        Args:
            service: Target service name.
            username: New username (if specified).
            password: New password (if specified).
            category: New category (if specified).
            notes: New notes (if specified).

        Returns:
            The updated Credential object.

        Raises:
            ServiceNotFoundError: If service does not exist.
        """
        self._ensure_unlocked()
        svc_key = service.strip().lower()
        if svc_key not in self._payload.records:
            raise ServiceNotFoundError(f"Service '{service}' not found. Cannot update.")

        cred = self._payload.records[svc_key]
        if username is not None and username.strip():
            cred.username = username.strip()
        if password is not None and password:
            cred.password = password
        if category is not None and category.strip():
            cred.category = category.strip()
        if notes is not None:
            cred.notes = notes.strip()

        cred.updated_at = current_utc_iso()
        self._persist()
        return cred

    def delete(self, service: str) -> str:
        """
        Delete a service credential from the vault.

        Args:
            service: Target service name.

        Returns:
            Original service name that was deleted.

        Raises:
            ServiceNotFoundError: If service does not exist.
        """
        self._ensure_unlocked()
        svc_key = service.strip().lower()
        if svc_key not in self._payload.records:
            raise ServiceNotFoundError(f"Service '{service}' not found in vault.")

        deleted_cred = self._payload.records.pop(svc_key)
        service_name = deleted_cred.service
        deleted_cred.clear()
        self._persist()
        return service_name

    def list_services(self) -> List[str]:
        """
        Return a sorted list of all stored service names.

        Returns:
            List of service names without passwords.
        """
        self._ensure_unlocked()
        return sorted([cred.service for cred in self._payload.records.values()])

    def list_detailed(self) -> List[Dict[str, Any]]:
        """
        Return list of all credentials with passwords masked.

        Returns:
            List of masked dictionaries.
        """
        self._ensure_unlocked()
        return [cred.masked_view() for cred in sorted(self._payload.records.values(), key=lambda c: c.service.lower())]

    def search(self, query: str) -> List[Dict[str, Any]]:
        """
        Search for credentials by service, username, or category keyword.

        Args:
            query: Substring search term.

        Returns:
            List of matching masked credentials.
        """
        self._ensure_unlocked()
        q = query.strip().lower()
        if not q:
            return self.list_detailed()

        matches = []
        for cred in self._payload.records.values():
            if (
                q in cred.service.lower()
                or q in cred.username.lower()
                or q in cred.category.lower()
                or q in cred.notes.lower()
            ):
                matches.append(cred.masked_view())

        return sorted(matches, key=lambda c: c["service"].lower())

    def change_master_password(self, new_password: str) -> None:
        """
        Rotate the master password and re-encrypt the entire vault under a new key.

        Args:
            new_password: The new master password.
        """
        self._ensure_unlocked()

        new_salt = KeyDerivation.generate_salt()
        new_kdf_params = KeyDerivation.get_default_params(self._kdf_params.get("algorithm", "Argon2id"))
        new_key = KeyDerivation.derive_key(
            password=new_password,
            salt=new_salt,
            algorithm=new_kdf_params["algorithm"],
            params=new_kdf_params,
        )

        self._salt = new_salt
        self._kdf_params = new_kdf_params
        self._key = new_key
        self._persist()
