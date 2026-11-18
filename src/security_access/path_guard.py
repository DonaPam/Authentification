"""Path validation that keeps every file operation inside the data root."""

from __future__ import annotations

import os
from pathlib import Path, PurePath

from .errors import ValidationError


class PathGuard:
    """Reject traversal, absolute paths, and every symlink component."""

    def __init__(self, data_root: Path) -> None:
        self.data_root = data_root.resolve()

    def resolve(self, requested_path: str, *, must_exist: bool = False) -> Path:
        candidate = PurePath(requested_path)
        if not requested_path or candidate.is_absolute() or ".." in candidate.parts:
            raise ValidationError("Path must be a non-empty relative path without traversal.")
        if any(part in {"", "."} for part in candidate.parts):
            raise ValidationError("Path contains an invalid component.")
        path = self.data_root.joinpath(*candidate.parts)
        self._reject_symlinks(path)
        try:
            path.relative_to(self.data_root)
        except ValueError as error:
            raise ValidationError("Path escapes the confidential-data directory.") from error
        if must_exist and not path.is_file():
            raise ValidationError("Requested file does not exist.")
        return path

    def _reject_symlinks(self, path: Path) -> None:
        current = self.data_root
        for part in path.relative_to(self.data_root).parts:
            current = current / part
            if current.exists() and current.is_symlink():
                raise ValidationError("Symlinks are not allowed in confidential file paths.")
            if current.exists() and not os.path.realpath(current).startswith(str(self.data_root)):
                raise ValidationError("Path escapes the confidential-data directory.")
