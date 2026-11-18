"""Application configuration with secure production defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AppConfig:
    data_root: Path
    database_path: Path
    log_path: Path
    allow_sidecar_metadata: bool = False

    @classmethod
    def from_environment(cls) -> "AppConfig":
        base = Path(os.environ.get("SECURITY_ACCESS_HOME", "/var/lib/security-access"))
        return cls(
            data_root=Path(os.environ.get("SECURITY_ACCESS_DATA_ROOT", base / "confidential-data")),
            database_path=Path(os.environ.get("SECURITY_ACCESS_DATABASE", base / "authorization.db")),
            log_path=Path(os.environ.get("SECURITY_ACCESS_LOG", "/var/log/security-access/audit.jsonl")),
            allow_sidecar_metadata=os.environ.get("SECURITY_ACCESS_TEST_SIDECAR") == "1",
        )

    def ensure_directories(self) -> None:
        self.data_root.mkdir(parents=True, exist_ok=True)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.data_root.chmod(0o700)
            self.database_path.parent.chmod(0o700)
            self.log_path.parent.chmod(0o700)
        except OSError:
            # The deployment account must enforce equivalent permissions if the filesystem forbids chmod.
            pass
