"""Thin wrapper around the existing ``phantom-secops`` simulator.

Tier 1 scope: if the user has a local clone of
``~/Documents/GitHub/hailmary/phantom-secops``, dispatch into its Makefile or
``scripts/`` runner via subprocess. Otherwise print a configuration hint.

Tier 2 will replace this with a first-class OWASP LLM Top 10 harness owned by
phantom-secure-connector and a phantom-mesh provider-trait adapter, so the
simulator does not require a sibling repo clone.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

SECOPS_PATH = Path(
    os.environ.get(
        "PHANTOM_SECOPS_PATH",
        str(Path.home() / "Documents" / "GitHub" / "hailmary" / "phantom-secops"),
    )
)


@dataclass
class SimulationResult:
    available: bool
    returncode: int
    message: str
    stdout: str = ""
    stderr: str = ""


def secops_available() -> bool:
    """True iff a recognisable phantom-secops repo is present."""
    if not SECOPS_PATH.exists():
        return False
    # Look for any well-known entry point.
    candidates = [
        SECOPS_PATH / "Makefile",
        SECOPS_PATH / "scripts",
        SECOPS_PATH / "scenarios",
    ]
    return any(c.exists() for c in candidates)


def run_simulation(
    target: str = "phantom-mesh",
    scenario: Optional[str] = None,
    extra_args: Sequence[str] = (),
    dry_run: bool = False,
) -> SimulationResult:
    """Dispatch a red/blue-team run.

    Parameters
    ----------
    target : str
        Logical target tag (passed through to phantom-secops).
    scenario : optional str
        Name of a scenario file under ``phantom-secops/scenarios/`` if any.
    extra_args : sequence of str
        Pass-through CLI args.
    dry_run : bool
        If True, don't actually invoke subprocess — just return what would run.
    """
    if not secops_available():
        return SimulationResult(
            available=False,
            returncode=-1,
            message=(
                "secops not configured. "
                f"Expected phantom-secops at {SECOPS_PATH}. "
                "Set PHANTOM_SECOPS_PATH or clone the repo."
            ),
        )

    # Prefer ``make`` if a Makefile exists; else look for run.sh.
    #
    # A ``dry_run`` is a *preview* of the intended command, so it must NOT be
    # gated on ``make`` actually being installed (that gate broke the preview on
    # hosts without make, e.g. Windows). The ``which`` check only matters when
    # we are about to really execute the subprocess below.
    cmd: list[str]
    makefile = SECOPS_PATH / "Makefile"
    run_sh = SECOPS_PATH / "scripts" / "run.sh"
    if makefile.exists() and (dry_run or shutil.which("make")):
        cmd = ["make", "-C", str(SECOPS_PATH), "simulate",
               f"TARGET={target}"]
        if scenario:
            cmd.append(f"SCENARIO={scenario}")
    elif run_sh.exists():
        cmd = [str(run_sh), "--target", target]
        if scenario:
            cmd += ["--scenario", scenario]
    else:
        return SimulationResult(
            available=True,
            returncode=-1,
            message=(
                f"phantom-secops at {SECOPS_PATH} found but no Makefile or "
                "scripts/run.sh entry point. Update simulator.py to point at "
                "the correct runner."
            ),
        )
    cmd.extend(extra_args)

    if dry_run:
        return SimulationResult(
            available=True,
            returncode=0,
            message="dry-run: " + " ".join(cmd),
        )

    proc = subprocess.run(
        cmd, capture_output=True, text=True, check=False
    )
    return SimulationResult(
        available=True,
        returncode=proc.returncode,
        message=f"ran: {' '.join(cmd)}",
        stdout=proc.stdout,
        stderr=proc.stderr,
    )
