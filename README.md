# Security Access System

Security Access System is a Python 3 application for Ubuntu that protects a
dedicated confidential-data directory with discretionary access control (DAC) and
mandatory access control (MAC). It supplies user management, a custom interactive
shell, Linux xattr file labels, structured audit logging, and pytest coverage.

## Requirements

- Python 3.11 or later
- Ubuntu or another Linux distribution with filesystem extended attributes enabled
- A dedicated service account and protected data directory for production use

Windows is supported only for automated development tests through an explicitly
test-only metadata sidecar. Production execution requires Linux xattrs.

## Installation

```bash
git clone https://github.com/DonaPam/Authentification.git
cd Authentification
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Create service-owned storage before production use:

```bash
sudo install -d -o securityaccess -g securityaccess -m 0700 /var/lib/security-access/confidential-data
sudo install -d -o securityaccess -g securityaccess -m 0700 /var/log/security-access
```

The database and logs must be readable and writable only by the service account.
The protected directory must not be directly accessible by application users.

## Configuration

The application reads these environment variables. Their defaults are appropriate
for a service installation.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECURITY_ACCESS_HOME` | `/var/lib/security-access` | Base directory |
| `SECURITY_ACCESS_DATA_ROOT` | `$SECURITY_ACCESS_HOME/confidential-data` | Protected file root |
| `SECURITY_ACCESS_DATABASE` | `$SECURITY_ACCESS_HOME/authorization.db` | Authorization database |
| `SECURITY_ACCESS_LOG` | `/var/log/security-access/audit.jsonl` | Audit log |
| `SECURITY_ACCESS_TEST_SIDECAR` | unset | Test-only fallback for systems without xattrs |

Never set `SECURITY_ACCESS_TEST_SIDECAR` in production. The production system
refuses to operate on file metadata without Linux xattrs.

## Authentication

The production design uses normal Linux PAM authentication through local login or
SSH. Configure each authorized Linux account to start the custom shell after PAM
has authenticated it, then map that account UID to an application user through
`linux_uid`. The application reads the process UID; it does not trust a username
typed into the shell.

Create the first administrator once, while logged in as a system administrator:

```bash
python3 -m security_access --bootstrap-admin admin --linux-uid 1001
```

The command prompts for a strong password and stores a PBKDF2-SHA256 hash. The
hash supports controlled provisioning and tests. PAM remains the authentication
authority for normal production sessions.

To start an OS-authenticated shell, run it from the mapped Linux account:

```bash
python3 -m security_access
```

For development only, an application-password login is available:

```bash
python3 -m security_access --password-login admin
```

## Shell commands

```text
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
users enable <username>
users disable <username>
users delete <username>
logout
exit
```

Example:

```text
security-access> files create plan.txt top_secret "Project plan"
File created.
security-access> files attrs plan.txt
owner=admin label=top_secret
security-access> files read plan.txt
Project plan
```

## Access-control rules

Confidentiality labels are ordered as `low_secret < secret < top_secret`.

- When a user's label and a file's label are equal, the system applies DAC and
  requires the operation's matching permission.
- When the labels differ, the system applies MAC: no read up and no write down.
- When a target file is absent, the system applies DAC and requires `CREATE`.

The implementation deliberately follows this prescribed selection rule. A new
file must use its creator's label; this explicit creation-label policy prevents an
unprivileged user from assigning a higher or lower label at creation time.

## Testing

Run the full test suite with:

```bash
python -m pytest
```

Tests cover user lifecycle, password authentication, DAC, MAC no-read-up and
no-write-down, creation and deletion, path traversal, symlink escape, and audit
events. They set the test-only sidecar option because the current test environment
may not provide Linux xattrs.

## Security limitations and assumptions

- Python checks do not protect files that users can modify directly. Production
  filesystem permissions must ensure that only the service account can access the
  data root and its xattrs.
- The supplied `systemd/security-access.service` is a deployment starting point;
  review account names and paths before installation.
- PAM/login-shell configuration is an operating-system responsibility and varies
  by university environment. The application enforces UID mapping after PAM has
  authenticated the user.
- The local SQLite database is suitable for a small single-host assignment. It is
  not a multi-host identity service.

See [the architecture proposal](docs/ARCHITECTURE.md) for module boundaries,
threat model, and development rationale.
