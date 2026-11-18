"""Unit tests for exact DAC/MAC selection rules."""

from security_access.authorization import AuthorizationEngine
from security_access.models import ConfidentialityLevel, FileMetadata, Operation, Permission, User


def user(level, permissions=()):
    return User("alice", None, level, frozenset(permissions))


def test_equal_label_uses_dac_and_denies_without_permission():
    decision = AuthorizationEngine().authorize_file(
        user(ConfidentialityLevel.SECRET),
        Operation.READ,
        FileMetadata("owner", ConfidentialityLevel.SECRET),
    )
    assert not decision.allowed
    assert decision.reason == "DAC_PERMISSION_MISSING"


def test_equal_label_uses_dac_and_allows_with_permission():
    decision = AuthorizationEngine().authorize_file(
        user(ConfidentialityLevel.SECRET, [Permission.READ]),
        Operation.READ,
        FileMetadata("owner", ConfidentialityLevel.SECRET),
    )
    assert decision.allowed
    assert decision.reason == "DAC_ALLOWED"


def test_different_label_applies_no_read_up_without_dac():
    decision = AuthorizationEngine().authorize_file(
        user(ConfidentialityLevel.LOW_SECRET),
        Operation.READ,
        FileMetadata("owner", ConfidentialityLevel.TOP_SECRET),
    )
    assert not decision.allowed
    assert decision.reason == "MAC_NO_READ_UP"


def test_different_label_applies_no_write_down_without_dac():
    decision = AuthorizationEngine().authorize_file(
        user(ConfidentialityLevel.TOP_SECRET),
        Operation.WRITE,
        FileMetadata("owner", ConfidentialityLevel.LOW_SECRET),
    )
    assert not decision.allowed
    assert decision.reason == "MAC_NO_WRITE_DOWN"


def test_different_label_allows_mac_safe_read_without_dac_permission():
    decision = AuthorizationEngine().authorize_file(
        user(ConfidentialityLevel.TOP_SECRET),
        Operation.READ,
        FileMetadata("owner", ConfidentialityLevel.LOW_SECRET),
    )
    assert decision.allowed
    assert decision.reason == "MAC_ALLOWED"


def test_missing_target_uses_dac_create_permission():
    assert AuthorizationEngine().authorize_file(user(ConfidentialityLevel.SECRET), Operation.CREATE, None).allowed is False
    assert AuthorizationEngine().authorize_file(
        user(ConfidentialityLevel.SECRET, [Permission.CREATE]), Operation.CREATE, None
    ).allowed is True
