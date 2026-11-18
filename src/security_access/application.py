"""Application service coordinating authentication, authorization, files, and audit events."""

from __future__ import annotations

from collections.abc import Callable

from .audit_log import AuditLogger
from .authentication import AuthenticationManager
from .authorization import AuthorizationEngine
from .configuration import AppConfig
from .errors import AuthorizationError
from .file_management import FileManager
from .models import ConfidentialityLevel, Operation, Permission, User
from .user_management import UserManager
from .user_repository import UserRepository
from .xattr_manager import XAttrManager


class SecurityAccessSystem:
    """The public application API used by the command shell and tests."""

    def __init__(self, config: AppConfig) -> None:
        config.ensure_directories()
        self.config = config
        self.users = UserRepository(config.database_path)
        self.users.initialize()
        self.user_management = UserManager(self.users)
        self.authentication = AuthenticationManager(self.users)
        self.authorizer = AuthorizationEngine()
        self.audit = AuditLogger(config.log_path)
        self.files = FileManager(
            config.data_root,
            self.authorizer,
            XAttrManager(config.data_root, config.allow_sidecar_metadata),
        )

    def authenticate_os_session(self) -> User:
        return self._logged("system", "LOGIN", "os-session", lambda: self.authentication.authenticate_current_os_session())

    def authenticate_password(self, username: str, password: str) -> User:
        return self._logged(username, "LOGIN", "application-password", lambda: self.authentication.authenticate_password(username, password))

    def create_file(self, user: User, path: str, content: str, label: ConfidentialityLevel) -> None:
        self._logged(user.username, Operation.CREATE, path, lambda: self.files.create(user, path, content, label))

    def read_file(self, user: User, path: str) -> str:
        return self._logged(user.username, Operation.READ, path, lambda: self.files.read(user, path))

    def write_file(self, user: User, path: str, content: str) -> None:
        self._logged(user.username, Operation.WRITE, path, lambda: self.files.write(user, path, content))

    def delete_file(self, user: User, path: str) -> None:
        self._logged(user.username, Operation.DELETE, path, lambda: self.files.delete(user, path))

    def list_files(self, user: User) -> list[str]:
        return self._logged(user.username, Operation.LIST, ".", lambda: self.files.list_files(user))

    def file_attributes(self, user: User, path: str):
        return self._logged(user.username, Operation.SHOW_ATTRIBUTES, path, lambda: self.files.attributes(user, path))

    def create_user(
        self, actor: User, username: str, password: str, level: ConfidentialityLevel, permissions: set[Permission], linux_uid: int | None = None
    ) -> User:
        return self._manage(actor, Operation.USER_CREATE, username, lambda: self.user_management.create(actor, username, password, level, permissions, linux_uid))

    def update_user(self, actor: User, username: str, **changes: object) -> User:
        return self._manage(actor, Operation.USER_EDIT, username, lambda: self.user_management.update(actor, username, **changes))

    def delete_user(self, actor: User, username: str) -> None:
        self._manage(actor, Operation.USER_DELETE, username, lambda: self.user_management.delete(actor, username))

    def list_users(self, actor: User) -> list[User]:
        return self._manage(actor, Operation.USER_LIST, "users", lambda: self.user_management.list(actor))

    def bootstrap_admin(
        self, username: str, password: str, linux_uid: int | None = None
    ) -> User:
        """Create the first administrator only when the database is empty."""
        if self.users.list_users():
            raise AuthorizationError("Bootstrap is available only when no users exist.")
        user = self.users.create_user(
            username,
            password,
            ConfidentialityLevel.TOP_SECRET,
            set(Permission),
            linux_uid,
        )
        self.audit.record(username, Operation.USER_CREATE, username, "SUCCESS", "BOOTSTRAP")
        return user

    def logout(self, user: User) -> None:
        self.audit.record(user.username, "LOGOUT", "shell", "SUCCESS", "LOGOUT")

    def _manage(self, actor: User, operation: Operation, target: str, action: Callable[[], object]):
        decision = self.authorizer.authorize_user_management(actor)
        if not decision.allowed:
            self.audit.record(actor.username, operation, target, "DENIED", decision.reason)
            raise AuthorizationError(decision.reason)
        return self._logged(actor.username, operation, target, action)

    def _logged(self, username: str, operation: Operation | str, target: str, action: Callable[[], object]):
        try:
            result = action()
        except Exception as error:
            self.audit.record(username, operation, target, "DENIED", self._reason(error))
            raise
        self.audit.record(username, operation, target, "SUCCESS", "OK")
        return result

    @staticmethod
    def _reason(error: Exception) -> str:
        return str(error).splitlines()[0][:200] or error.__class__.__name__
