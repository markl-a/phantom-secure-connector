"""Red/blue team simulator — native OWASP-LLM01 prompt-injection detector."""
from .detector import SIGNATURES, Finding, scan
from .simulator import SECOPS_PATH, run_simulation, secops_available

__all__ = [
    "run_simulation",
    "secops_available",
    "SECOPS_PATH",
    "scan",
    "Finding",
    "SIGNATURES",
]
