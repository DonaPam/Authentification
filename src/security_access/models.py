"""Domain models and controlled vocabulary for the security system."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ConfidentialityLevel(str, Enum):
    LOW_SECRET = "low_secret"
    SECRET = "secret"
    TOP_SECRET = "top_secret"

    @property
    def rank(self) -> int:
        return {
            ConfidentialityLevel.LOW_SECRET: 0,
            ConfidentialityLevel.SECRET: 1,
            ConfidentialityLevel.TOP_SECRET: 2,
        }[self]


class Permission(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    CREATE = "CREATE"
    DELETE = "DELETE"
    MANAGE_USERS = "MANAGE_USERS"


class Operation(str, Enum):
    CREATE = "CREATE"
    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    LIST = "LIST"
    SHOW_ATTRIBUTES = "SHOW_ATTRIBUTES"
    USER_CREATE = "USER_CREATE"
    USER_EDIT = "USER_EDIT"
    USER_DELETE = "USER_DELETE"
    USER_LIST = "USER_LIST"


@dataclass(frozen=True)
class User:
    username: str
    linux_uid: int | None
    confidentiality_level: ConfidentialityLevel
    permissions: frozenset[Permission]
    active: bool = True


@dataclass(frozen=True)
class FileMetadata:
    owner: str
    confidentiality_level: ConfidentialityLevel


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
