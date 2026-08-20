"""Audit logging subsystem for security events (never logs secrets)."""

import json
from pathlib import Path
from typing import Optional, List, Dict, Any

from ..config import DEFAULT_AUDIT_PATH
from ..vault.models import current_utc_iso


class AuditLogger:
    """Logs security actions and audit events without storing secrets."""

    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = Path(log_path) if log_path else DEFAULT_AUDIT_PATH

    def log_event(self, event_type: str, details: Optional[Dict[str, Any]] = None) -> None:
        """
        Append a structured security event to the audit log.

        Args:
            event_type: Name of the event (e.g. AUTH_SUCCESS, CREDENTIAL_ADDED).
            details: Non-sensitive context dictionary.
        """
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        sanitized_details = details.copy() if details else {}

        # Strip any accidental secrets
        for key in list(sanitized_details.keys()):
            if "password" in key.lower() or "secret" in key.lower() or "key" in key.lower():
                sanitized_details[key] = "[REDACTED]"

        entry = {
            "timestamp": current_utc_iso(),
            "event": event_type,
            "details": sanitized_details,
        }

        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass  # Audit logging should never crash the application

    def get_recent_entries(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieve recent audit events."""
        if not self.log_path.exists():
            return []

        entries = []
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except OSError:
            return []

        return entries[-limit:]
