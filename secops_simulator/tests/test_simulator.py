"""Tests for the secops simulator wrapper. Dry-run only — never executes
phantom-secops in CI."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_unavailable_when_path_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("PHANTOM_SECOPS_PATH", str(tmp_path / "does_not_exist"))
    # Force module re-import so the env var takes effect.
    for mod in list(sys.modules):
        if mod.startswith("secops_simulator"):
            del sys.modules[mod]
    from secops_simulator.simulator import secops_available, run_simulation

    assert secops_available() is False
    res = run_simulation(target="phantom-mesh")
    assert res.available is False
    assert "secops not configured" in res.message


def test_dry_run_when_available(monkeypatch, tmp_path):
    fake = tmp_path / "secops"
    fake.mkdir()
    (fake / "Makefile").write_text("simulate:\n\t@echo ok\n")
    monkeypatch.setenv("PHANTOM_SECOPS_PATH", str(fake))
    for mod in list(sys.modules):
        if mod.startswith("secops_simulator"):
            del sys.modules[mod]
    from secops_simulator.simulator import secops_available, run_simulation

    assert secops_available() is True
    res = run_simulation(target="phantom-mesh", dry_run=True)
    assert res.available is True
    assert res.returncode == 0
    assert "dry-run:" in res.message
    assert "TARGET=phantom-mesh" in res.message
