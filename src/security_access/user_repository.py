"""Protected SQLite repository for users, permissions, and password hashes."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import sqlite3
from pathlib import Path

from .errors import AuthenticationError, NotFoundError, ValidationError
from .models import ConfidentialityLevel, Permission, User

_USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_PBKDF2_ITERATIONS = 600_000


class UserRepository:
    """Persist authorization records; passwords are stored only as PBKDF2 hashes."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    linux_uid INTEGER UNIQUE,
                    password_hash TEXT NOT NULL,
                    confidentiality_level TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS permissions (
                    username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
                    permission TEXT NOT NULL,
                    PRIMARY KEY (username, permission)
                );
                """
            )
        try:
            self.database_path.chmod(0o600)
        except OSError:
            pass

    def create_user(
        self,
        username: str,
        password: str,
        confidentiality_level: ConfidentialityLevel,
        permissions: set[Permission],
        linux_uid: int | None = None,
    ) -> User:
        self._validate_username(username)
        self._validate_password(password)
        with self._connect() as connection:
            try:
                connection.execute(
                    "INSERT INTO users(username, linux_uid, password_hash, confidentiality_level) VALUES (?, ?, ?, ?)",
                    (username, linux_uid, self._hash_password(password), confidentiality_level.value),
                )
            except sqlite3.IntegrityError as error:
                raise ValidationError("A user with that username or Linux UID already exists.") from error
            self._replace_permissions(connection, username, permissions)
        return self.get_user(username)

    def get_user(self, username: str) -> User:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if row is None:
                raise NotFoundError("User not found.")
            return self._row_to_user(connection, row)

    def get_user_by_uid(self, linux_uid: int) -> User:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM users WHERE linux_uid = ?", (linux_uid,)).fetchone()
            if row is None:
                raise NotFoundError("No application user is mapped to this Linux account.")
            return self._row_to_user(connection, row)

    def list_users(self) -> list[User]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM users ORDER BY username").fetchall()
            return [self._row_to_user(connection, row) for row in rows]

    def update_user(
        self,
        username: str,
        *,
        confidentiality_level: ConfidentialityLevel | None = None,
        permissions: set[Permission] | None = None,
        active: bool | None = None,
        linux_uid: int | None = None,
    ) -> User:
        self.get_user(username)
        assignments: list[str] = []
        values: list[object] = []
        if confidentiality_level is not None:
            assignments.append("confidentiality_level = ?")
            values.append(confidentiality_level.value)
        if active is not None:
            assignments.append("active = ?")
            values.append(int(active))
        if linux_uid is not None:
            assignments.append("linux_uid = ?")
            values.append(linux_uid)
        with self._connect() as connection:
            if assignments:
                try:
                    connection.execute(
                        f"UPDATE users SET {', '.join(assignments)}, updated_at = CURRENT_TIMESTAMP WHERE username = ?",
                        (*values, username),
                    )
                except sqlite3.IntegrityError as error:
                    raise ValidationError("That Linux UID is already mapped to another user.") from error
            if permissions is not None:
                self._replace_permissions(connection, username, permissions)
        return self.get_user(username)

    def delete_user(self, username: str) -> None:
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM users WHERE username = ?", (username,))
            if cursor.rowcount == 0:
                raise NotFoundError("User not found.")

    def authenticate_password(self, username: str, password: str) -> User:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if row is None or not self._verify_password(password, row["password_hash"]):
                raise AuthenticationError("Invalid username or password.")
            user = self._row_to_user(connection, row)
            if not user.active:
                raise AuthenticationError("This user account is inactive.")
            return user

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _validate_username(username: str) -> None:
        if not _USERNAME.fullmatch(username):
            raise ValidationError("Username must contain 1 to 32 lowercase letters, digits, underscores, or hyphens.")

    @staticmethod
    def _validate_password(password: str) -> None:
        if len(password) < 12:
            raise ValidationError("Password must contain at least 12 characters.")

    @staticmethod
    def _hash_password(password: str) -> str:
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
        return "pbkdf2_sha256${}${}${}".format(
            _PBKDF2_ITERATIONS,
            base64.b64encode(salt).decode(),
            base64.b64encode(digest).decode(),
        )

    @staticmethod
    def _verify_password(password: str, encoded: str) -> bool:
        try:
            algorithm, iterations, encoded_salt, encoded_digest = encoded.split("$")
            if algorithm != "pbkdf2_sha256":
                return False
            digest = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), base64.b64decode(encoded_salt), int(iterations)
            )
            return hmac.compare_digest(digest, base64.b64decode(encoded_digest))
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _replace_permissions(connection: sqlite3.Connection, username: str, permissions: set[Permission]) -> None:
        connection.execute("DELETE FROM permissions WHERE username = ?", (username,))
        connection.executemany(
            "INSERT INTO permissions(username, permission) VALUES (?, ?)",
            [(username, permission.value) for permission in permissions],
        )

    @staticmethod
    def _row_to_user(connection: sqlite3.Connection, row: sqlite3.Row) -> User:
        permissions = connection.execute(
            "SELECT permission FROM permissions WHERE username = ?", (row["username"],)
        ).fetchall()
        return User(
            username=row["username"],
            linux_uid=row["linux_uid"],
            confidentiality_level=ConfidentialityLevel(row["confidentiality_level"]),
            permissions=frozenset(Permission(item["permission"]) for item in permissions),
            active=bool(row["active"]),
        )
