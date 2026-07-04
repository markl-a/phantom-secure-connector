"""Bounded anomaly detector MVP.

The detector intentionally implements one explainable rule: compare each
numeric record value against a rolling baseline of the previous ``window``
values and flag it when the absolute z-score crosses ``threshold``.
"""
from __future__ import annotations

import statistics
from collections.abc import Iterable, Mapping
from numbers import Real
from typing import Dict, List


class AnomalyDetector:
    """Detect spikes in a stream of mapping records using rolling z-score."""

    def __init__(
        self,
        field: str = "value",
        window: int = 5,
        threshold: float = 3.0,
    ) -> None:
        if isinstance(window, bool) or not isinstance(window, int):
            raise TypeError("window must be an int")
        if window < 2:
            raise ValueError("window must be at least 2")
        if threshold <= 0:
            raise ValueError("threshold must be positive")
        self.field = field
        self.window = window
        self.threshold = float(threshold)

    def scan(self, records: Iterable[Mapping[str, object]]) -> List[Dict[str, object]]:
        """Return structured anomaly findings for ``records``.

        Findings contain the zero-based ``index``, original ``record``,
        human-readable ``reason``, and numeric ``score``.
        """
        findings: List[Dict[str, object]] = []
        history: List[float] = []

        for index, record in enumerate(records):
            value = self._value(record)
            if len(history) >= self.window:
                baseline = history[-self.window :]
                finding = self._finding(index, record, value, baseline)
                if finding is not None:
                    findings.append(finding)
            history.append(value)

        return findings

    def _value(self, record: Mapping[str, object]) -> float:
        try:
            value = record[self.field]
        except KeyError as exc:
            raise KeyError(f"record is missing numeric field {self.field!r}") from exc
        if isinstance(value, bool) or not isinstance(value, Real):
            raise TypeError(f"record field {self.field!r} must be numeric")
        return float(value)

    def _finding(
        self,
        index: int,
        record: Mapping[str, object],
        value: float,
        baseline: List[float],
    ) -> Dict[str, object] | None:
        mean = statistics.mean(baseline)
        stdev = statistics.pstdev(baseline)
        deviation = abs(value - mean)
        if stdev == 0:
            if deviation == 0:
                return None
            return {
                "index": index,
                "record": record,
                "reason": (
                    f"{self.field} value deviates from a constant baseline "
                    f"by {deviation:.2f} (baseline {mean:.2f})"
                ),
                "score": deviation,
            }

        score = deviation / stdev
        if score < self.threshold:
            return None
        return {
            "index": index,
            "record": record,
            "reason": (
                f"{self.field} rolling z-score {score:.2f} "
                f"exceeds threshold {self.threshold:.2f}"
            ),
            "score": score,
        }
