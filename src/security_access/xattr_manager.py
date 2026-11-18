"""Linux xattr metadata storage with an explicitly test-only fallback."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .errors import NotFoundError, ValidationError
from .models import ConfidentialityLevel, FileMetadata

_OWNER_ATTRIBUTE = "user.security_access.owner"
_LABEL_ATTRIBUTE = "user.security_access.label"


class XAttrManager:
    """Store owner and confidentiality label in Linux extended attributes."""

    def __init__(self, data_root: Path, allow_sidecar_metadata: bool = False) -> None:
        self.data_root = data_root
        self.allow_sidecar_metadata = allow_sidecar_metadata
        self.sidecar_path = data_root / ".security_access_test_metadata.json"

    def set_metadata(self, path: Path, metadata: FileMetadata) -> None:
        try:
            os.setxattr(path, _OWNER_ATTRIBUTE, metadata.owner.encode(), follow_symlinks=False)
            os.setxattr(path, _LABEL_ATTRIBUTE, metadata.confidentiality_level.value.encode(), follow_symlinks=False)
        except (AttributeError, OSError) as error:
            if not self.allow_sidecar_metadata:
                raise ValidationError("Linux extended attributes are required for file metadata.") from error
            records = self._load_sidecar()
            records[str(path.relative_to(self.data_root))] = {
                "owner": metadata.owner,
                "label": metadata.confidentiality_level.value,
            }
            self._write_sidecar(records)

    def get_metadata(self, path: Path) -> FileMetadata:
        try:
            owner = os.getxattr(path, _OWNER_ATTRIBUTE, follow_symlinks=False).decode()
            label = os.getxattr(path, _LABEL_ATTRIBUTE, follow_symlinks=False).decode()
            return FileMetadata(owner=owner, confidentiality_level=ConfidentialityLevel(label))
        except (AttributeError, OSError, ValueError) as error:
            if not self.allow_sidecar_metadata:
                raise NotFoundError("File metadata is missing or invalid.") from error
            record = self._load_sidecar().get(str(path.relative_to(self.data_root)))
            if record is None:
                raise NotFoundError("File metadata is missing.") from error
            return FileMetadata(owner=record["owner"], confidentiality_level=ConfidentialityLevel(record["label"]))

    def remove_metadata(self, path: Path) -> None:
        try:
            os.removexattr(path, _OWNER_ATTRIBUTE, follow_symlinks=False)
            os.removexattr(path, _LABEL_ATTRIBUTE, follow_symlinks=False)
        except (AttributeError, OSError):
            if self.allow_sidecar_metadata:
                records = self._load_sidecar()
                records.pop(str(path.relative_to(self.data_root)), None)
                self._write_sidecar(records)

    def _load_sidecar(self) -> dict[str, dict[str, str]]:
        if not self.sidecar_path.exists():
            return {}
        return json.loads(self.sidecar_path.read_text(encoding="utf-8"))

    def _write_sidecar(self, records: dict[str, dict[str, str]]) -> None:
        temporary = self.sidecar_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(records, sort_keys=True), encoding="utf-8")
        os.replace(temporary, self.sidecar_path)
