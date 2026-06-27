from __future__ import annotations

import subprocess
import sys
import tomllib
from importlib import resources
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_pyproject_metadata_matches_public_release_gate() -> None:
    project = _pyproject()["project"]

    assert project["name"] == "phantom-secure-connector"
    assert project["version"] == "0.1.0a0"
    assert project["license"] == "Apache-2.0"
    assert project["requires-python"] == ">=3.10"
    assert project["authors"]
    assert "Topic :: Security" in project["classifiers"]
    assert "Homepage" in project["urls"]
    assert "Repository" in project["urls"]
    assert project["dependencies"] == []


def test_console_entrypoints_cover_public_demo_surface() -> None:
    scripts = _pyproject()["project"]["scripts"]

    assert scripts["phantom-secure-connector"] == "mcp_bridge.client:main"
    assert scripts["secure-mcp"] == "mcp_bridge.client:main"
    assert scripts["phantom-secure-demo-loop"] == "readiness.demo_loop:main"
    assert scripts["phantom-secure-transform"] == "readiness.transform_pipeline:main"
    assert scripts["phantom-secure-guard-scenario"] == "readiness.guard_scenario:main"


def test_compliance_rule_files_are_package_data() -> None:
    package_data = _pyproject()["tool"]["setuptools"]["package-data"]

    assert package_data["compliance_checker"] == ["rules/*.toml"]
    rules = resources.files("compliance_checker").joinpath("rules")
    assert rules.joinpath("hipaa.toml").is_file()
    assert rules.joinpath("gdpr.toml").is_file()
    assert rules.joinpath("pci-dss.toml").is_file()
    assert rules.joinpath("tw-pii.toml").is_file()


def test_public_module_help_is_available_without_external_services() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "readiness.demo_loop", "--help"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    assert "--standard" in result.stdout
    assert "--out" in result.stdout
