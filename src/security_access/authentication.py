"""Operating-system and application credential authentication adapters."""

from __future__ import annotations

import os

from .errors import AuthenticationError
from .models import User
from .user_repository import UserRepository


class AuthenticationManager:
    """Separates OS session identity from optional application credential checks."""

    def __init__(self, users: UserRepository) -> None:
        self.users = users

    def authenticate_current_os_session(self) -> User:
        """Map the already PAM-authenticated process UID to an active application user."""
        try:
            uid = os.getuid()
        except AttributeError as error:
            raise AuthenticationError("Operating-system session authentication requires Linux or another POSIX system.") from error
        user = self.users.get_user_by_uid(uid)
        if not user.active:
            raise AuthenticationError("This user account is inactive.")
        return user

    def authenticate_password(self, username: str, password: str) -> User:
        """Verify a protected application credential for provisioning and automated tests."""
        return self.users.authenticate_password(username, password)
