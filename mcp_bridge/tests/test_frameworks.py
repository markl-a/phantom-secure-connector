from mcp_bridge.capabilities import Capability
from mcp_bridge.frameworks import (
    frameworks_for_capabilities, frameworks_for_finding_family, DISCLAIMER,
)


def test_capability_refs_are_deduped_and_sorted():
    refs = frameworks_for_capabilities([Capability.SUBPROCESS, Capability.WRITE])
    assert isinstance(refs, list) and refs == sorted(set(refs))
    assert any("OWASP-AGENTIC-2026" in r for r in refs)
    assert any("PDPA" in r for r in refs)


def test_pure_capability_has_no_refs():
    assert frameworks_for_capabilities([Capability.PURE]) == []


def test_phi_reverse_maps_to_special_category():
    refs = frameworks_for_capabilities([Capability.PHI_REVERSE])
    assert any("special category" in r.lower() or "minimum-necessary" in r.lower() for r in refs)


def test_known_injection_family_maps():
    refs = frameworks_for_finding_family("instruction-override")
    assert any("Prompt Injection" in r for r in refs)
    assert any("LLM01" in r for r in refs)


def test_unknown_family_falls_back_generic():
    refs = frameworks_for_finding_family("brand-new-family")
    assert refs and any("OWASP" in r for r in refs)


def test_disclaimer_says_not_a_certification():
    assert "not a" in DISCLAIMER.lower() and "certification" in DISCLAIMER.lower()
