"""Interactive command-line shell for authenticated users."""

from __future__ import annotations

import argparse
import getpass
import shlex
from typing import Callable

from .application import SecurityAccessSystem
from .configuration import AppConfig
from .errors import SecurityAccessError, ValidationError
from .models import ConfidentialityLevel, Permission, User


class SecurityShell:
    """A small command shell that delegates every protected operation to the application service."""

    def __init__(self, system: SecurityAccessSystem, user: User) -> None:
        self.system = system
        self.user = user
        self.running = True

    def run(self) -> None:
        print(f"Authenticated as {self.user.username}. Type 'help' for commands.")
        while self.running:
            try:
                raw = input("security-access> ")
            except EOFError:
                raw = "exit"
            if not raw.strip():
                continue
            try:
                self.execute(raw)
            except SecurityAccessError as error:
                print(f"Error: {error}")
            except ValueError as error:
                print(f"Error: {error}")

    def execute(self, raw: str) -> None:
        parts = shlex.split(raw)
        command = parts[0]
        arguments = parts[1:]
        handlers: dict[str, Callable[[list[str]], None]] = {
            "help": self._help,
            "whoami": self._whoami,
            "files": self._files,
            "users": self._users,
            "logout": self._logout,
            "exit": self._logout,
        }
        if command not in handlers:
            raise ValidationError("Unknown command. Type 'help' for commands.")
        handlers[command](arguments)

    def _help(self, _: list[str]) -> None:
        print("""Commands:
  whoami
  files list
  files create <path> <low_secret|secret|top_secret> <content>
  files read <path>
  files write <path> <content>
  files delete <path>
  files attrs <path>
  users list
  users add <username> <password> <level> <permissions_csv> [linux_uid]
  users level <username> <level>
  users permissions <username> <permissions_csv>
  users disable <username>
  users enable <username>
  users delete <username>
  logout | exit""")

    def _whoami(self, arguments: list[str]) -> None:
        self._require_count(arguments, 0)
        print(f"username={self.user.username} level={self.user.confidentiality_level.value} permissions={','.join(sorted(p.value for p in self.user.permissions))}")

    def _files(self, arguments: list[str]) -> None:
        if not arguments:
            raise ValidationError("A files subcommand is required.")
        subcommand, *values = arguments
        if subcommand == "list":
            self._require_count(values, 0)
            for path in self.system.list_files(self.user):
                print(path)
        elif subcommand == "create":
            self._require_count(values, 3)
            self.system.create_file(self.user, values[0], values[2], ConfidentialityLevel(values[1]))
            print("File created.")
        elif subcommand == "read":
            self._require_count(values, 1)
            print(self.system.read_file(self.user, values[0]))
        elif subcommand == "write":
            self._require_count(values, 2)
            self.system.write_file(self.user, values[0], values[1])
            print("File updated.")
        elif subcommand == "delete":
            self._require_count(values, 1)
            self.system.delete_file(self.user, values[0])
            print("File deleted.")
        elif subcommand == "attrs":
            self._require_count(values, 1)
            metadata = self.system.file_attributes(self.user, values[0])
            print(f"owner={metadata.owner} label={metadata.confidentiality_level.value}")
        else:
            raise ValidationError("Unknown files subcommand.")

    def _users(self, arguments: list[str]) -> None:
        if not arguments:
            raise ValidationError("A users subcommand is required.")
        subcommand, *values = arguments
        if subcommand == "list":
            self._require_count(values, 0)
            for user in self.system.list_users(self.user):
                print(f"{user.username} level={user.confidentiality_level.value} active={user.active} permissions={','.join(sorted(p.value for p in user.permissions))}")
        elif subcommand == "add":
            if len(values) not in {4, 5}:
                raise ValidationError("Usage: users add <username> <password> <level> <permissions_csv> [linux_uid]")
            uid = int(values[4]) if len(values) == 5 else None
            self.system.create_user(self.user, values[0], values[1], ConfidentialityLevel(values[2]), self._permissions(values[3]), uid)
            print("User created.")
        elif subcommand == "level":
            self._require_count(values, 2)
            self.system.update_user(self.user, values[0], confidentiality_level=ConfidentialityLevel(values[1]))
            print("User updated.")
        elif subcommand == "permissions":
            self._require_count(values, 2)
            self.system.update_user(self.user, values[0], permissions=self._permissions(values[1]))
            print("User updated.")
        elif subcommand in {"enable", "disable"}:
            self._require_count(values, 1)
            self.system.update_user(self.user, values[0], active=subcommand == "enable")
            print("User updated.")
        elif subcommand == "delete":
            self._require_count(values, 1)
            self.system.delete_user(self.user, values[0])
            print("User deleted.")
        else:
            raise ValidationError("Unknown users subcommand.")

    def _logout(self, arguments: list[str]) -> None:
        self._require_count(arguments, 0)
        self.system.logout(self.user)
        self.running = False
        print("Logged out.")

    @staticmethod
    def _permissions(raw: str) -> set[Permission]:
        return {Permission(item.strip()) for item in raw.split(",") if item.strip()}

    @staticmethod
    def _require_count(values: list[str], count: int) -> None:
        if len(values) != count:
            raise ValidationError("Invalid number of arguments. Type 'help' for command usage.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Security Access System shell")
    parser.add_argument("--bootstrap-admin", metavar="USERNAME", help="Create the first administrator; only available for an empty database.")
    parser.add_argument("--linux-uid", type=int, help="Linux UID to map when bootstrapping an administrator.")
    parser.add_argument("--password-login", metavar="USERNAME", help="Use application password login for development or testing only.")
    args = parser.parse_args()
    system = SecurityAccessSystem(AppConfig.from_environment())
    if args.bootstrap_admin:
        password = getpass.getpass("New administrator password: ")
        confirmation = getpass.getpass("Confirm administrator password: ")
        if password != confirmation:
            raise SystemExit("Passwords do not match.")
        user = system.bootstrap_admin(args.bootstrap_admin, password, args.linux_uid)
        print(f"Administrator {user.username} created.")
        return
    if args.password_login:
        user = system.authenticate_password(args.password_login, getpass.getpass("Password: "))
    else:
        user = system.authenticate_os_session()
    SecurityShell(system, user).run()


if __name__ == "__main__":
    main()
