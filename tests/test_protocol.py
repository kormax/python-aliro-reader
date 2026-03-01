import pytest

from aliro.protocol import ProtocolError, resolve_protocol_version


def test_resolve_protocol_version_prefers_1_0_when_no_preference_configured():
    supported = [b"\x01\x01", b"\x01\x00", b"\x00\x09"]

    assert resolve_protocol_version(supported, preferred_versions=None) == b"\x01\x00"
    assert resolve_protocol_version(supported, preferred_versions=[]) == b"\x01\x00"


def test_resolve_protocol_version_defaults_to_highest_when_1_0_not_supported():
    supported = [b"\x01\x01", b"\x00\x09"]

    assert resolve_protocol_version(supported, preferred_versions=None) == b"\x01\x01"


def test_resolve_protocol_version_uses_configured_priority_order():
    supported = [b"\x01\x01", b"\x01\x00", b"\x00\x09"]
    preferred = [b"\x00\x09", b"\x01\x00"]

    assert resolve_protocol_version(supported, preferred_versions=preferred) == b"\x00\x09"


def test_resolve_protocol_version_falls_back_to_highest_when_configured_versions_are_unavailable():
    supported = [b"\x01\x01", b"\x01\x00"]
    preferred = [b"\x00\x09"]

    assert resolve_protocol_version(supported, preferred_versions=preferred) == b"\x01\x01"


def test_resolve_protocol_version_rejects_invalid_preferred_version_length():
    with pytest.raises(ProtocolError):
        resolve_protocol_version([b"\x01\x00"], preferred_versions=[b"\x01"])


def test_resolve_protocol_version_rejects_empty_supported_version_list():
    with pytest.raises(ProtocolError):
        resolve_protocol_version([], preferred_versions=None)
