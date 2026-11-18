"""Application-specific exceptions safe to render in the command shell."""


class SecurityAccessError(Exception):
    """Base error raised for expected operational failures."""


class AuthenticationError(SecurityAccessError):
    """Raised when an identity cannot be authenticated."""


class AuthorizationError(SecurityAccessError):
    """Raised when a policy decision denies an operation."""


class ValidationError(SecurityAccessError):
    """Raised when supplied input is invalid."""


class NotFoundError(SecurityAccessError):
    """Raised when a requested resource does not exist."""
