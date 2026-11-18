"""Exact DAC/MAC decision logic required by the assignment."""

from __future__ import annotations

from .models import Decision, FileMetadata, Operation, Permission, User


class AuthorizationEngine:
    """Apply DAC to equal labels and MAC to different labels without mixing rules."""

    _DAC_PERMISSIONS = {
        Operation.READ: Permission.READ,
        Operation.LIST: Permission.READ,
        Operation.SHOW_ATTRIBUTES: Permission.READ,
        Operation.WRITE: Permission.WRITE,
        Operation.DELETE: Permission.DELETE,
        Operation.CREATE: Permission.CREATE,
    }

    def authorize_file(self, user: User, operation: Operation, metadata: FileMetadata | None) -> Decision:
        if not user.active:
            return Decision(False, "USER_INACTIVE")
        if metadata is None:
            return self._dac(user, Permission.CREATE)
        if user.confidentiality_level == metadata.confidentiality_level:
            return self._dac(user, self._DAC_PERMISSIONS[operation])
        return self._mac(user, metadata, operation)

    @staticmethod
    def authorize_user_management(user: User) -> Decision:
        if not user.active:
            return Decision(False, "USER_INACTIVE")
        return AuthorizationEngine._dac(user, Permission.MANAGE_USERS)

    @staticmethod
    def _dac(user: User, permission: Permission) -> Decision:
        return Decision(permission in user.permissions, "DAC_ALLOWED" if permission in user.permissions else "DAC_PERMISSION_MISSING")

    @staticmethod
    def _mac(user: User, metadata: FileMetadata, operation: Operation) -> Decision:
        user_rank = user.confidentiality_level.rank
        file_rank = metadata.confidentiality_level.rank
        if operation in {Operation.READ, Operation.LIST, Operation.SHOW_ATTRIBUTES} and user_rank < file_rank:
            return Decision(False, "MAC_NO_READ_UP")
        if operation in {Operation.WRITE, Operation.DELETE} and user_rank > file_rank:
            return Decision(False, "MAC_NO_WRITE_DOWN")
        return Decision(True, "MAC_ALLOWED")
