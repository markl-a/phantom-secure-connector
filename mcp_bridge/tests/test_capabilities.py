import pytest
from mcp_bridge.capabilities import (
    Capability, CapabilityPolicy, parse_capability, DEFAULT_GRANTED,
)


def test_six_capabilities_exist():
    assert {c.value for c in Capability} == {
        "network", "filesystem", "subprocess", "write", "phi-reverse", "pure",
    }


def test_parse_capability_value_and_alias():
    assert parse_capability("network") is Capability.NETWORK
    assert parse_capability(" NET ") is Capability.NETWORK
    assert parse_capability("phi_reverse") is Capability.PHI_REVERSE
    with pytest.raises(ValueError):
        parse_capability("teleport")


def test_default_granted_is_least_privilege():
    assert DEFAULT_GRANTED == frozenset({Capability.PURE, Capability.FILESYSTEM})


def test_policy_permits_and_missing():
    pol = CapabilityPolicy()
    assert pol.permits([Capability.PURE]) is True
    assert pol.permits([Capability.NETWORK]) is False
    assert pol.missing([Capability.NETWORK, Capability.PURE]) == {Capability.NETWORK}


def test_policy_from_grants_widens():
    pol = CapabilityPolicy.from_grants(["net", "subprocess"])
    assert pol.permits([Capability.NETWORK]) is True
    assert pol.permits([Capability.SUBPROCESS]) is True
    assert pol.permits([Capability.PURE]) is True


def test_parse_capability_fs_proc_subproc_aliases():
    assert parse_capability("fs") is Capability.FILESYSTEM
    assert parse_capability("proc") is Capability.SUBPROCESS
    assert parse_capability("subproc") is Capability.SUBPROCESS


def test_from_grants_ignores_blank_tokens_and_grants_write():
    pol = CapabilityPolicy.from_grants(["", "  ", "write"])
    assert pol.permits([Capability.WRITE]) is True
    # blanks contribute nothing beyond the least-privilege base + write
    assert pol.granted == frozenset(DEFAULT_GRANTED | {Capability.WRITE})


def test_missing_is_empty_when_all_required_granted():
    pol = CapabilityPolicy.from_grants(["write"])
    required = [Capability.PURE, Capability.FILESYSTEM, Capability.WRITE]
    assert pol.missing(required) == set()
