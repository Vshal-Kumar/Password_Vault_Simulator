"""Data models for vault credentials and decrypted vault payloads."""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, Any, Optional


def current_utc_iso() -> str:
    """Return current UTC time in ISO format."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Credential:
    """Represents a single service credential stored securely in the vault."""

    service: str
    username: str
    password: str
    category: str = "General"
    notes: str = ""
    created_at: str = field(default_factory=current_utc_iso)
    updated_at: str = field(default_factory=current_utc_iso)

    def to_dict(self) -> Dict[str, Any]:
        """Convert credential to serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Credential":
        """Reconstruct a Credential instance from dictionary."""
        return cls(
            service=data.get("service", ""),
            username=data.get("username", ""),
            password=data.get("password", ""),
            category=data.get("category", "General"),
            notes=data.get("notes", ""),
            created_at=data.get("created_at", current_utc_iso()),
            updated_at=data.get("updated_at", current_utc_iso()),
        )

    def masked_view(self) -> Dict[str, Any]:
        """Return credential representation with the password masked."""
        return {
            "service": self.service,
            "username": self.username,
            "password": "********",
            "category": self.category,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def clear(self) -> None:
        """Overwrite sensitive fields in memory when locking or discarding."""
        self.password = "\x00" * len(self.password)
        self.username = ""
        self.notes = ""


@dataclass
class VaultPayload:
    """Container for all decrypted vault records and metadata."""

    records: Dict[str, Credential] = field(default_factory=dict)
    created_at: str = field(default_factory=current_utc_iso)
    updated_at: str = field(default_factory=current_utc_iso)

    def to_dict(self) -> Dict[str, Any]:
        """Convert entire payload to dictionary."""
        return {
            "version": 1,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "records": {svc: cred.to_dict() for svc, cred in self.records.items()},
        }

    def to_json_bytes(self) -> bytes:
        """Serialize payload to UTF-8 JSON bytes ready for encryption."""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, data_bytes: bytes) -> "VaultPayload":
        """Deserialize payload from decrypted JSON bytes."""
        data = json.loads(data_bytes.decode("utf-8"))
        records_dict = {}
        for svc_name, cred_data in data.get("records", {}).items():
            records_dict[svc_name.lower()] = Credential.from_dict(cred_data)

        return cls(
            records=records_dict,
            created_at=data.get("created_at", current_utc_iso()),
            updated_at=data.get("updated_at", current_utc_iso()),
        )

    def clear(self) -> None:
        """Clear all in-memory credentials securely."""
        for cred in self.records.values():
            cred.clear()
        self.records.clear()
