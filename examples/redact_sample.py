#!/usr/bin/env python3
"""Run the PHI redactor over examples/sample_phi.csv and print the result.

This regenerates examples/sample_redaction_output.txt. The CSV is fully
synthetic (no real patient data). Run from the repo root:

    python3 examples/redact_sample.py
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

# Make phi_redactor importable when run from the repo root.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from phi_redactor.redactor import redact  # noqa: E402

CSV_PATH = ROOT / "examples" / "sample_phi.csv"


def row_text(r: dict) -> str:
    return (
        f"Patient {r['patient_name']} {r['dob']} born; {r['mrn']}; "
        f"mobile {r['phone']}; email {r['email']}; {r['note']}"
    )


def main() -> int:
    print("phantom-secure-connector — sample PHI-redaction output")
    print("======================================================\n")
    print("Generated from examples/sample_phi.csv (fully synthetic — no real "
          "patient data).")
    print("Reproduce with:  python3 examples/redact_sample.py\n")

    with CSV_PATH.open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    for r in rows:
        text = row_text(r)
        clean, mapping = redact(text, mode="replace")
        masked, _ = redact(text, mode="mask")
        print(f"--- record_id={r['record_id']} ---")
        print(f"  input         : {text}")
        print(f"  replace mode  : {clean}")
        print(f"  mask mode     : {masked}")
        if mapping.items:
            print("  reversible map:")
            for tok, orig in mapping.items.items():
                print(f"      {tok} -> {orig}")
        else:
            print("  reversible map: (none)")
        print()

    print("Note (honest scope): personal NAMES are NOT redacted by the regex "
          "pass — that needs NER and is documented Tier 2 work. Structured PHI "
          "(DOB, MRN, phone, email, SSN, TW national ID / NHI, IPv4, "
          "credit-card) is covered.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
