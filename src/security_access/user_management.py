"""User-administration operations separated from credential persistence."""

from __future__ import annotations

from .errors import AuthorizationError
from .models import ConfidentialityLevel, Permission, User
from .user_repository import UserRepository


class UserManager:
    """Apply management authorization before changing authorization records."""

    def __init__(self, repository: UserRepository) -> None:
        self.repository = repository

    @staticmethod
    def require_administrator(actor: User) -> None:
        if not actor.active or Permission.MANAGE_USERS not in actor.permissions:
            raise AuthorizationError("DAC_PERMISSION_MISSING")

    def create(
        self,
        actor: User,
        username: str,
        password: str,
        level: ConfidentialityLevel,
        permissions: set[Permission],
        linux_uid: int | None,
    ) -> User:
        self.require_administrator(actor)
        return self.repository.create_user(username, password, level, permissions, linux_uid)

    def update(self, actor: User, username: str, **changes: object) -> User:
        self.require_administrator(actor)
        return self.repository.update_user(username, **changes)

    def delete(self, actor: User, username: str) -> None:
        self.require_administrator(actor)
        self.repository.delete_user(username)

    def list(self, actor: User) -> list[User]:
        self.require_administrator(actor)
        return self.repository.list_users()
