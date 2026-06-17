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


def test_dry_run_previews_make_without_make_installed(monkeypatch, tmp_path):
    """A dry-run is a *preview*: it must not depend on `make` being on PATH.

    Regression for the cross-platform (P1) bug where the Makefile branch was
    gated on ``shutil.which("make")``, so on a host without ``make`` (e.g.
    Windows CI) a dry-run could not even report what command *would* run.
    """
    import secops_simulator.simulator as sim_mod

    fake = tmp_path / "secops"
    fake.mkdir()
    (fake / "Makefile").write_text("simulate:\n\t@echo ok\n")
    monkeypatch.setenv("PHANTOM_SECOPS_PATH", str(fake))
    for mod in list(sys.modules):
        if mod.startswith("secops_simulator"):
            del sys.modules[mod]
    from secops_simulator import simulator as sim_mod
    # Force "make is NOT installed" regardless of the host running the suite.
    monkeypatch.setattr(sim_mod.shutil, "which", lambda _name: None)

    res = sim_mod.run_simulation(target="phantom-mesh", scenario="injection", dry_run=True)
    assert res.available is True
    assert res.returncode == 0
    assert "dry-run:" in res.message
    # The preview reflects the intended make invocation, not a degraded fallback.
    assert "make" in res.message
    assert "TARGET=phantom-mesh" in res.message
    assert "SCENARIO=injection" in res.message


def _reload_sim(monkeypatch, path):
    monkeypatch.setenv("PHANTOM_SECOPS_PATH", str(path))
    for mod in list(sys.modules):
        if mod.startswith("secops_simulator"):
            del sys.modules[mod]
    from secops_simulator import simulator as sim_mod
    return sim_mod


def test_dry_run_uses_run_sh_when_no_makefile(monkeypatch, tmp_path):
    """When there's no Makefile but a scripts/run.sh exists, the dry-run
    preview must reflect the run.sh runner invocation."""
    fake = tmp_path / "secops"
    (fake / "scripts").mkdir(parents=True)
    (fake / "scripts" / "run.sh").write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    sim_mod = _reload_sim(monkeypatch, fake)
    assert sim_mod.secops_available() is True
    res = sim_mod.run_simulation(target="phantom-mesh", scenario="leak", dry_run=True)
    assert res.available is True
    assert res.returncode == 0
    assert "run.sh" in res.message
    assert "--target phantom-mesh" in res.message
    assert "--scenario leak" in res.message


def test_available_but_no_entrypoint_reports_clearly(monkeypatch, tmp_path):
    """A recognisable secops dir (has scenarios/) but with neither a Makefile
    nor scripts/run.sh must report a clear 'no entry point' message, available
    True, returncode -1 — not crash."""
    fake = tmp_path / "secops"
    (fake / "scenarios").mkdir(parents=True)
    sim_mod = _reload_sim(monkeypatch, fake)
    assert sim_mod.secops_available() is True
    res = sim_mod.run_simulation(target="phantom-mesh", dry_run=True)
    assert res.available is True
    assert res.returncode == -1
    assert "no Makefile or" in res.message


def test_extra_args_passed_through_in_dry_run(monkeypatch, tmp_path):
    fake = tmp_path / "secops"
    fake.mkdir()
    (fake / "Makefile").write_text("simulate:\n\t@echo ok\n", encoding="utf-8")
    sim_mod = _reload_sim(monkeypatch, fake)
    res = sim_mod.run_simulation(
        target="phantom-mesh", extra_args=["--verbose", "--seed=42"], dry_run=True
    )
    assert "--verbose" in res.message
    assert "--seed=42" in res.message
