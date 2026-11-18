"""Shared pytest fixtures for the Security Access System."""

from __future__ import annotations

import pytest

from security_access.application import SecurityAccessSystem
from security_access.configuration import AppConfig
from security_access.models import ConfidentialityLevel, Permission


@pytest.fixture()
def system(tmp_path):
    config = AppConfig(
        data_root=tmp_path / "confidential-data",
        database_path=tmp_path / "state" / "authorization.db",
        log_path=tmp_path / "log" / "audit.jsonl",
        allow_sidecar_metadata=True,
    )
    application = SecurityAccessSystem(config)
    admin = application.bootstrap_admin("admin", "CorrectHorseBattery1", linux_uid=1000)
    return application, admin


def add_user(system, admin, username, level, permissions):
    return system.create_user(
        admin,
        username,
        "CorrectHorseBattery1",
        level,
        set(permissions),
    )
