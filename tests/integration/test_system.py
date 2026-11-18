"""Integration tests for users, file operations, path defense, and audit logs."""

from __future__ import annotations

import json
import os

import pytest

import security_access.authentication as authentication_module
from security_access.errors import AuthenticationError, AuthorizationError, ValidationError
from security_access.models import ConfidentialityLevel, Permission

from conftest import add_user


def test_user_creation_update_and_deletion(system):
    app, admin = system
    created = add_user(app, admin, "alice", ConfidentialityLevel.SECRET, [Permission.READ])
    assert created.username == "alice"
    changed = app.update_user(admin, "alice", permissions={Permission.WRITE})
    assert changed.permissions == frozenset({Permission.WRITE})
    app.delete_user(admin, "alice")
    assert [user.username for user in app.list_users(admin)] == ["admin"]


def test_password_authentication_success_and_failure(system):
    app, admin = system
    assert app.authenticate_password("admin", "CorrectHorseBattery1") == admin
    with pytest.raises(AuthenticationError):
        app.authenticate_password("admin", "wrong-password")


def test_operating_system_session_identity_mapping(system, monkeypatch):
    app, admin = system
    monkeypatch.setattr(authentication_module.os, "getuid", lambda: 1000, raising=False)
    assert app.authenticate_os_session() == admin


def test_file_creation_read_and_deletion(system):
    app, admin = system
    app.create_file(admin, "report.txt", "classified", ConfidentialityLevel.TOP_SECRET)
    assert app.read_file(admin, "report.txt") == "classified"
    metadata = app.file_attributes(admin, "report.txt")
    assert metadata.owner == "admin"
    assert metadata.confidentiality_level is ConfidentialityLevel.TOP_SECRET
    app.delete_file(admin, "report.txt")
    assert app.list_files(admin) == []


def test_authorized_file_modification(system):
    app, admin = system
    app.create_file(admin, "editable.txt", "before", ConfidentialityLevel.TOP_SECRET)
    app.write_file(admin, "editable.txt", "after")
    assert app.read_file(admin, "editable.txt") == "after"


def test_dac_denies_equal_label_without_permission(system):
    app, admin = system
    reader = add_user(app, admin, "reader", ConfidentialityLevel.SECRET, [])
    owner = add_user(app, admin, "owner", ConfidentialityLevel.SECRET, [Permission.CREATE])
    app.create_file(owner, "same.txt", "same", ConfidentialityLevel.SECRET)
    with pytest.raises(AuthorizationError, match="DAC_PERMISSION_MISSING"):
        app.read_file(reader, "same.txt")


def test_mac_no_read_up_and_no_write_down(system):
    app, admin = system
    low = add_user(app, admin, "low", ConfidentialityLevel.LOW_SECRET, [Permission.CREATE])
    top = add_user(app, admin, "top", ConfidentialityLevel.TOP_SECRET, [Permission.CREATE])
    app.create_file(top, "top.txt", "top", ConfidentialityLevel.TOP_SECRET)
    app.create_file(low, "low.txt", "low", ConfidentialityLevel.LOW_SECRET)
    with pytest.raises(AuthorizationError, match="MAC_NO_READ_UP"):
        app.read_file(low, "top.txt")
    with pytest.raises(AuthorizationError, match="MAC_NO_WRITE_DOWN"):
        app.write_file(top, "low.txt", "changed")


def test_different_labels_use_mac_not_dac(system):
    app, admin = system
    low = add_user(app, admin, "low", ConfidentialityLevel.LOW_SECRET, [Permission.CREATE])
    top = add_user(app, admin, "top", ConfidentialityLevel.TOP_SECRET, [Permission.CREATE])
    app.create_file(low, "low.txt", "visible", ConfidentialityLevel.LOW_SECRET)
    assert app.read_file(top, "low.txt") == "visible"


def test_create_requires_dac_and_matching_creator_label(system):
    app, admin = system
    creator = add_user(app, admin, "creator", ConfidentialityLevel.SECRET, [])
    with pytest.raises(AuthorizationError, match="DAC_PERMISSION_MISSING"):
        app.create_file(creator, "no.txt", "x", ConfidentialityLevel.SECRET)
    creator = app.update_user(admin, "creator", permissions={Permission.CREATE})
    with pytest.raises(ValidationError, match="creator's confidentiality level"):
        app.create_file(creator, "wrong-label.txt", "x", ConfidentialityLevel.LOW_SECRET)


def test_path_traversal_and_symlink_escape_are_rejected(system, tmp_path):
    app, admin = system
    with pytest.raises(ValidationError, match="without traversal"):
        app.create_file(admin, "../escape.txt", "x", ConfidentialityLevel.TOP_SECRET)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = app.config.data_root / "link.txt"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("Symlink creation is unavailable in this test environment.")
    with pytest.raises(ValidationError, match="Symlinks are not allowed"):
        app.read_file(admin, "link.txt")


def test_audit_log_records_success_and_denied_operations(system):
    app, admin = system
    low = add_user(app, admin, "low", ConfidentialityLevel.LOW_SECRET, [Permission.CREATE])
    app.create_file(admin, "audit.txt", "secret", ConfidentialityLevel.TOP_SECRET)
    with pytest.raises(AuthorizationError):
        app.read_file(low, "audit.txt")
    events = [json.loads(line) for line in app.config.log_path.read_text(encoding="utf-8").splitlines()]
    assert any(event["operation"] == "CREATE" and event["result"] == "SUCCESS" for event in events)
    assert any(event["operation"] == "READ" and event["result"] == "DENIED" and event["username"] == "low" for event in events)
