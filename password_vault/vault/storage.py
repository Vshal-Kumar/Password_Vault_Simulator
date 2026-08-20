"""Storage engine for persisting and loading the encrypted vault container on disk."""

import base64
import json
import os
import shutil
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

from ..config import (
    DEFAULT_VAULT_PATH,
    VaultNotFoundError,
    IntegrityError,
)
from ..crypto.kdf import KeyDerivation
from ..crypto.encryption import AESGCMCipher
from .models import VaultPayload, current_utc_iso


class VaultStorage:
    """Manages the encrypted vault file container on disk."""

    def __init__(self, file_path: Optional[Path] = None):
        self.file_path = Path(file_path) if file_path else DEFAULT_VAULT_PATH

    def exists(self) -> bool:
        """Check if the vault file currently exists on disk."""
        return self.file_path.exists() and self.file_path.is_file()

    def initialize_vault(
        self,
        master_password: str,
        kdf_algorithm: str = "Argon2id",
    ) -> bytes:
        """
        Create a new encrypted vault file with initial empty payload.

        Args:
            master_password: Plaintext master password for key derivation.
            kdf_algorithm: Argon2id or Scrypt.

        Returns:
            The derived 32-byte encryption key for current session.
        """
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

        salt = KeyDerivation.generate_salt()
        kdf_params = KeyDerivation.get_default_params(kdf_algorithm)
        derived_key = KeyDerivation.derive_key(
            password=master_password,
            salt=salt,
            algorithm=kdf_algorithm,
            params=kdf_params,
        )

        empty_payload = VaultPayload()
        self.save(empty_payload, derived_key, salt, kdf_params)
        return derived_key

    def save(
        self,
        payload: VaultPayload,
        key: bytes,
        salt: bytes,
        kdf_params: Dict[str, Any],
    ) -> None:
        """
        Encrypt and atomically write the vault payload to disk.

        Args:
            payload: Decrypted VaultPayload instance.
            key: 32-byte derived encryption key.
            salt: Random salt used for KDF.
            kdf_params: KDF parameters dictionary.
        """
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        payload.updated_at = current_utc_iso()
        payload_bytes = payload.to_json_bytes()

        # Header metadata to bind as Associated Data for AEAD integrity
        header_metadata = {
            "version": 1,
            "kdf_algorithm": kdf_params.get("algorithm", "Argon2id"),
        }
        associated_data = json.dumps(header_metadata, sort_keys=True).encode("utf-8")

        # Encrypt the payload with AES-256-GCM
        ciphertext, nonce = AESGCMCipher.encrypt(
            plaintext=payload_bytes,
            key=key,
            associated_data=associated_data,
        )

        envelope = {
            "version": 1,
            "kdf": {
                "algorithm": kdf_params.get("algorithm", "Argon2id"),
                "salt": base64.b64encode(salt).decode("ascii"),
                "params": kdf_params,
            },
            "encryption": {
                "algorithm": "AES-256-GCM",
            },
            "vault": {
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            },
            "metadata": {
                "created_at": payload.created_at,
                "last_modified": payload.updated_at,
            },
        }

        # Write to temporary file first, then atomically replace
        temp_file = self.file_path.with_suffix(".tmp")
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(envelope, f, indent=2)
            # Secure file permissions (rw-------)
            try:
                os.chmod(temp_file, 0o600)
            except OSError:
                pass
            temp_file.replace(self.file_path)
        finally:
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except OSError:
                    pass

    def load_envelope(self) -> Dict[str, Any]:
        """Load and parse the JSON container envelope from disk without decrypting."""
        if not self.exists():
            raise VaultNotFoundError(f"Vault file not found at {self.file_path}")

        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                envelope = json.load(f)
        except json.JSONDecodeError as e:
            raise IntegrityError(f"Vault container format is corrupted: {str(e)}")

        if "kdf" not in envelope or "vault" not in envelope:
            raise IntegrityError("Invalid vault container structure: missing required envelope fields.")

        return envelope

    def unlock_and_load(self, master_password: str) -> Tuple[VaultPayload, bytes, bytes, Dict[str, Any]]:
        """
        Authenticate master password, derive key, decrypt payload, and return contents.

        Args:
            master_password: Master password provided by user.

        Returns:
            Tuple of (VaultPayload, derived_key, salt, kdf_params)

        Raises:
            VaultNotFoundError: If file does not exist.
            IntegrityError: If password is wrong or ciphertext was modified.
        """
        envelope = self.load_envelope()

        kdf_info = envelope["kdf"]
        salt = base64.b64decode(kdf_info["salt"])
        kdf_params = kdf_info.get("params", {})
        kdf_algorithm = kdf_info.get("algorithm", "Argon2id")

        derived_key = KeyDerivation.derive_key(
            password=master_password,
            salt=salt,
            algorithm=kdf_algorithm,
            params=kdf_params,
        )

        vault_info = envelope["vault"]
        nonce = base64.b64decode(vault_info["nonce"])
        ciphertext = base64.b64decode(vault_info["ciphertext"])

        header_metadata = {
            "version": envelope.get("version", 1),
            "kdf_algorithm": kdf_algorithm,
        }
        associated_data = json.dumps(header_metadata, sort_keys=True).encode("utf-8")

        # Decrypt payload bytes
        payload_bytes = AESGCMCipher.decrypt(
            ciphertext=ciphertext,
            key=derived_key,
            nonce=nonce,
            associated_data=associated_data,
        )

        try:
            payload = VaultPayload.from_json_bytes(payload_bytes)
        except Exception as e:
            raise IntegrityError(f"Failed to deserialize decrypted vault data: {str(e)}")

        return payload, derived_key, salt, kdf_params

    def create_backup(self, backup_path: Path) -> Path:
        """Create a full encrypted backup of the vault file."""
        if not self.exists():
            raise VaultNotFoundError("Cannot create backup: Vault file does not exist.")
        backup_path = Path(backup_path)
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.file_path, backup_path)
        return backup_path

    def restore_from_backup(self, backup_path: Path) -> None:
        """Restore vault file from a backup copy after checking basic validity."""
        backup_path = Path(backup_path)
        if not backup_path.exists():
            raise VaultNotFoundError(f"Backup file not found at {backup_path}")
        
        # Verify JSON structure before replacing
        try:
            with open(backup_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if "kdf" not in data or "vault" not in data:
                raise IntegrityError("Invalid backup file: Missing essential vault structures.")
        except Exception as e:
            raise IntegrityError(f"Cannot restore from invalid backup: {str(e)}")

        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup_path, self.file_path)
