"""Structured append-only audit logging."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from .models import Operation


class AuditLogger:
    """Write one JSON event per line without confidential file content."""

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path

    def record(self, username: str, operation: Operation | str, target: str, result: str, reason: str) -> None:
        event = {
            "timestamp": datetime.now(UTC).isoformat(),
            "username": username,
            "operation": operation.value if isinstance(operation, Operation) else operation,
            "target": target,
            "result": result,
            "reason": reason,
        }
        with self.log_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True) + "\n")
        try:
            self.log_path.chmod(0o600)
        except OSError:
            pass
