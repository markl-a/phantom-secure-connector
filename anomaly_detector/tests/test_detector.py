"""Tests for the bounded anomaly detector MVP."""
from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path so `import anomaly_detector` works when pytest is
# run from any cwd.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from anomaly_detector import AnomalyDetector  # noqa: E402


def test_normal_stream_yields_no_findings():
    records = [
        {"timestamp": "2026-07-05T00:00:00Z", "latency_ms": value}
        for value in (100, 102, 99, 101, 100, 103, 98, 102)
    ]

    detector = AnomalyDetector(field="latency_ms", window=4, threshold=3.0)

    assert detector.scan(records) == []


def test_spike_stream_flags_the_spike():
    records = [
        {"timestamp": "2026-07-05T00:00:00Z", "latency_ms": 100},
        {"timestamp": "2026-07-05T00:01:00Z", "latency_ms": 101},
        {"timestamp": "2026-07-05T00:02:00Z", "latency_ms": 99},
        {"timestamp": "2026-07-05T00:03:00Z", "latency_ms": 100},
        {"timestamp": "2026-07-05T00:04:00Z", "latency_ms": 250},
        {"timestamp": "2026-07-05T00:05:00Z", "latency_ms": 102},
    ]

    detector = AnomalyDetector(field="latency_ms", window=4, threshold=3.0)
    findings = detector.scan(records)

    assert len(findings) == 1
    assert findings[0]["index"] == 4
    assert findings[0]["record"] == records[4]
    assert findings[0]["score"] >= 3.0
    assert "rolling z-score" in findings[0]["reason"]
    assert "latency_ms" in findings[0]["reason"]
