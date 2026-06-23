"""Per-tool capability vocabulary + a least-privilege policy for the MCP bridge.

A tool declares the capabilities it needs; a CapabilityPolicy declares what is
granted. The server denies (never runs) a tool whose required capabilities are
not all granted. Pure stdlib, deterministic, no LLM."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, Iterable, Set


class Capability(Enum):
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    SUBPROCESS = "subprocess"
    WRITE = "write"
    PHI_REVERSE = "phi-reverse"
    PURE = "pure"


_ALIASES = {
    "net": Capability.NETWORK,
    "fs": Capability.FILESYSTEM,
    "proc": Capability.SUBPROCESS,
    "subproc": Capability.SUBPROCESS,
    "phi_reverse": Capability.PHI_REVERSE,
}

DEFAULT_GRANTED: FrozenSet[Capability] = frozenset({Capability.PURE, Capability.FILESYSTEM})


def parse_capability(token: str) -> Capability:
    """Parse a capability from its value or a short alias (case/space-insensitive)."""
    t = token.strip().lower()
    for c in Capability:
        if c.value == t:
            return c
    if t in _ALIASES:
        return _ALIASES[t]
    raise ValueError(f"unknown capability: {token!r}")


@dataclass(frozen=True)
class CapabilityPolicy:
    """The set of granted capabilities. Default = least privilege."""

    granted: FrozenSet[Capability] = DEFAULT_GRANTED

    @classmethod
    def from_grants(cls, tokens: Iterable[str]) -> "CapabilityPolicy":
        """Build a policy = least-privilege base ∪ the parsed grant tokens."""
        extra = {parse_capability(t) for t in tokens if str(t).strip()}
        return cls(granted=frozenset(DEFAULT_GRANTED | extra))

    def permits(self, required: Iterable[Capability]) -> bool:
        return set(required) <= set(self.granted)

    def missing(self, required: Iterable[Capability]) -> Set[Capability]:
        return set(required) - set(self.granted)
