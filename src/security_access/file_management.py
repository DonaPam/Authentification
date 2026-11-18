"""Authorized and path-safe confidential file operations."""

from __future__ import annotations

import os
from pathlib import Path

from .authorization import AuthorizationEngine
from .errors import AuthorizationError, NotFoundError, ValidationError
from .models import ConfidentialityLevel, FileMetadata, Operation, User
from .path_guard import PathGuard
from .xattr_manager import XAttrManager


class FileManager:
    """Enforce path safety and authorize each filesystem operation before execution."""

    def __init__(self, data_root: Path, authorizer: AuthorizationEngine, metadata: XAttrManager) -> None:
        self.path_guard = PathGuard(data_root)
        self.authorizer = authorizer
        self.metadata = metadata

    def create(self, user: User, relative_path: str, content: str, label: ConfidentialityLevel) -> None:
        path = self.path_guard.resolve(relative_path)
        if path.exists():
            raise ValidationError("A file already exists at that path.")
        self._enforce(user, Operation.CREATE, None)
        if label != user.confidentiality_level:
            raise ValidationError("New files must use the creator's confidentiality level.")
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path_guard._reject_symlinks(path)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
            self.metadata.set_metadata(path, FileMetadata(owner=user.username, confidentiality_level=label))
        except Exception:
            path.unlink(missing_ok=True)
            raise

    def read(self, user: User, relative_path: str) -> str:
        path, metadata = self._existing(relative_path)
        self._enforce(user, Operation.READ, metadata)
        return path.read_text(encoding="utf-8")

    def write(self, user: User, relative_path: str, content: str) -> None:
        path, metadata = self._existing(relative_path)
        self._enforce(user, Operation.WRITE, metadata)
        descriptor = os.open(path, os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)

    def delete(self, user: User, relative_path: str) -> None:
        path, metadata = self._existing(relative_path)
        self._enforce(user, Operation.DELETE, metadata)
        self.metadata.remove_metadata(path)
        path.unlink()

    def list_files(self, user: User) -> list[str]:
        paths: list[str] = []
        for path in self.path_guard.data_root.rglob("*"):
            if path.is_file() and path != self.metadata.sidecar_path:
                try:
                    metadata = self.metadata.get_metadata(path)
                    if self.authorizer.authorize_file(user, Operation.LIST, metadata).allowed:
                        paths.append(str(path.relative_to(self.path_guard.data_root)))
                except (NotFoundError, ValidationError):
                    continue
        return sorted(paths)

    def attributes(self, user: User, relative_path: str) -> FileMetadata:
        _, metadata = self._existing(relative_path)
        self._enforce(user, Operation.SHOW_ATTRIBUTES, metadata)
        return metadata

    def _existing(self, relative_path: str) -> tuple[Path, FileMetadata]:
        path = self.path_guard.resolve(relative_path, must_exist=True)
        return path, self.metadata.get_metadata(path)

    def _enforce(self, user: User, operation: Operation, metadata: FileMetadata | None) -> None:
        decision = self.authorizer.authorize_file(user, operation, metadata)
        if not decision.allowed:
            raise AuthorizationError(decision.reason)
