"""Red/blue team simulator — Tier 1 stub that wraps phantom-secops if present."""
from .simulator import run_simulation, secops_available, SECOPS_PATH

__all__ = ["run_simulation", "secops_available", "SECOPS_PATH"]
