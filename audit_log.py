"""
Audit logging, kept separate from the access-control logic.

Entries are appended to a JSON-lines file (one JSON object per line), by default
`access.log`. The file is only ever appended to, never rewritten.
"""

import json
import os
import threading
from datetime import datetime, timezone

DEFAULT_LOG_PATH = "access.log"


class AuditLog:
    """Append-only JSON-lines log of login and access attempts."""

    def __init__(self, path=DEFAULT_LOG_PATH):
        self.path = path
        self._lock = threading.Lock()

    def record(self, event, username, outcome, resource=None, reason=""):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event,          # LOGIN, LOGOUT or ACCESS
            "user": username,        # None if the caller could not be identified
            "resource": resource,
            "outcome": outcome,      # GRANTED or DENIED
            "reason": reason,
        }
        with self._lock, open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def entries(self):
        """Read every entry back from the log file."""
        if not os.path.exists(self.path):
            return []
        with open(self.path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]
