# Open Source Readiness

Project: `phantom-secure-connector`
Current phase: P3 synthetic data-plane guard scenario verified
Master plan: `../../PHANTOM-SATELLITES-OPEN-SOURCE-MASTER-PLAN.md`

## Shipped Features

- Stdlib-first PHI redaction, compliance checking, secops simulation, and MCP bridge package set.
- CLI entrypoints: `secure-mcp` and `phantom-secure-connector`, both mapped to `mcp_bridge.client:main`.
- CLI entrypoint: `phantom-secure-demo-loop`, mapped to `readiness.demo_loop:main`.
- Help surface verified with `python -m mcp_bridge.client --help`.
- Root README points to `docs/phantom-secure-connector.md`.
- Root README now includes safe synthetic compliance/readiness smoke.
- Root README now includes a deterministic synthetic guardrail loop that writes a public artifact bundle.
- Security boundary, no-certification claim, and MCP allowlist/PHI gate policy are documented in `docs/SECURITY_BOUNDARY.md`.
- P2 bundle contract is documented in `docs/SYNTHETIC_GUARDRAIL_LOOP.md`.
- P2 transform pipeline contract is documented in `docs/TRANSFORM_PIPELINE.md`.
- CLI entrypoint: `phantom-secure-transform`, mapped to `readiness.transform_pipeline:main`.
- P3 data-plane guard scenario contract is documented in `docs/DATA_PLANE_GUARD_SCENARIO.md`.
- CLI entrypoint: `phantom-secure-guard-scenario`, mapped to `readiness.guard_scenario:main`.
- Test suite baseline is green after fixing an invalid Taiwan national ID test fixture and adding public contract tests.

## Planned Or Deferred Features

- Broader privacy and compliance data gateway: bridge contract hardening and synthetic multi-record policies.
- Production ingest pipeline, real regulated-data connectors, and claims of legal certification are out of initial release scope.

## Install And Test Commands

```powershell
python -m pip install -e .[dev]
python -m pytest -q
python -m mcp_bridge.client --help
python -m compliance_checker.checker --standard hipaa --json <synthetic-patients.csv>
python -m readiness <synthetic-patients.csv> --standards hipaa --html-out <temp>\readiness.html
python -m readiness.demo_loop --out <bundle-dir> --standard hipaa
python -m readiness.transform_pipeline --source <synthetic-source.csv> --out <bundle-dir>
python -m readiness.guard_scenario --source <transform-bundle-dir> --out <scenario-bundle-dir>
```

Initial P0 result on 2026-06-26:

```text
1 failed, 182 passed, 2 skipped
```

Failing test:

```text
compliance_checker/tests/test_validators.py::test_tw_id_letter_table_is_not_alphabetical
```

Root cause and fix:

```text
The test fixture values for I/O/W used invalid check digits. They were replaced
with checksum-valid values: I229999974, O100000013, W100000029.
```

Verified result after fix:

```text
185 passed, 2 skipped in 6.99s
```

P2 synthetic guardrail loop result:

```text
Targeted: 36 passed in 0.55s
Full: 190 passed, 2 skipped in 8.41s
CLI smoke: python -m readiness.demo_loop --out <temp> --standard hipaa wrote manifest.json
```

P2 transform pipeline result:

```text
Targeted: 92 passed in 2.59s
Full: 194 passed, 2 skipped in 6.97s
Collect-only: 196 tests collected
Packaging: python -m pip install -e . --dry-run --no-deps would install phantom-secure-connector-0.1.0
CLI help: python -m readiness.transform_pipeline --help OK
CLI smoke: python -m readiness.transform_pipeline --source <csv> --out <temp> wrote manifest.json
```

P3 synthetic data-plane guard scenario result:

```text
Targeted: 12 passed in 0.17s
Full: 198 passed, 2 skipped in 9.59s
CLI smoke: python -m readiness.guard_scenario --source <transform-bundle> --out <temp> wrote manifest.json
Agy review: NO BLOCKERS
```

## Fixture And Data Policy

- Public fixtures must be synthetic and must not contain raw PHI or private records.
- Redaction/compliance rule examples must avoid real identifiers unless they are known public test identifiers.
- Audit logs must not preserve raw sensitive payloads.
- Demo-loop public artifacts other than `source-records.csv` must not retain raw synthetic identifiers or reversible redaction maps.
- Transform pipeline public artifacts must not retain raw synthetic identifiers, full source rows, or reversible redaction maps.
- Data-plane guard scenario public artifacts must remain metadata-only and must not retain raw synthetic identifiers, input hashes, full source rows, reversible maps, external-network activity, or live bridge claims.

## Safety And Privacy Risks

- Redaction false negatives are high impact because sensitive data could leak.
- Compliance output can be misread as legal certification; docs must state it is a developer guard, not legal advice or certification.
- MCP bridge tool calls require strict allowlist and injection gates by default.

## Blockers To Next Phase

- None for P3 synthetic data-plane guard scenario. Next slice should harden bridge/readiness policy enforcement beyond the synthetic scenario without claiming legal certification.

## Evidence

- `pyproject.toml` declares packages `phi_redactor`, `mcp_bridge`, `compliance_checker`, `secops_simulator`, and `readiness`.
- `pyproject.toml` declares scripts `secure-mcp`, `phantom-secure-connector`, `phantom-secure-demo-loop`, and `phantom-secure-transform`.
- `pyproject.toml` declares script `phantom-secure-guard-scenario`.
- `README.md` points to `docs/phantom-secure-connector.md`.
- `README.md` includes synthetic compliance/readiness smoke.
- `README.md` includes deterministic synthetic guardrail loop quickstart.
- `README.md` includes deterministic synthetic transform pipeline quickstart.
- `README.md` includes deterministic synthetic data-plane guard scenario quickstart.
- `docs/SECURITY_BOUNDARY.md` documents no legal/compliance certification, no raw PHI fixtures, MCP allowlist, PHI redaction, and injection scanning.
- `docs/SYNTHETIC_GUARDRAIL_LOOP.md` documents the bundle artifact and no-raw-retention contract.
- `docs/TRANSFORM_PIPELINE.md` documents the transform action and metadata-only audit-log contract.
- `docs/DATA_PLANE_GUARD_SCENARIO.md` documents the data-plane guard scenario and metadata-only bridge boundary.
- Initial `python -m pytest -q`: 1 failed, 182 passed, 2 skipped.
- `python -m pytest compliance_checker/tests/test_validators.py::test_tw_id_letter_table_is_not_alphabetical -q`: 1 passed.
- `python -m pytest readiness/tests/test_open_source_contract.py compliance_checker/tests/test_checker.py mcp_bridge/tests/test_client.py phi_redactor/tests/test_redactor.py -q`: 73 passed.
- Final `python -m pytest -q`: 185 passed, 2 skipped.
- P2 targeted `python -m pytest readiness/tests/test_demo_loop_contract.py readiness/tests/test_open_source_contract.py readiness/tests/test_cli.py compliance_checker/tests/test_checker.py secops_simulator/tests/test_detector.py -q`: 36 passed.
- P2 final `python -m pytest -q`: 190 passed, 2 skipped.
- P2 transform targeted `python -m pytest readiness/tests/test_transform_pipeline_contract.py readiness/tests/test_demo_loop_contract.py readiness/tests/test_open_source_contract.py readiness/tests/test_cli.py compliance_checker/tests/test_checker.py phi_redactor/tests/test_redactor.py mcp_bridge/tests/test_client.py secops_simulator/tests/test_detector.py -q`: 92 passed.
- P2 transform final `python -m pytest -q`: 194 passed, 2 skipped.
- P2 transform collect-only `python -m pytest --collect-only -q`: 196 tests collected.
- P2 transform packaging `python -m pip install -e . --dry-run --no-deps`: would install `phantom-secure-connector-0.1.0`.
- `python -m mcp_bridge.client --help`: help OK.
- `python -m readiness.demo_loop --out <temp> --standard hipaa`: wrote deterministic artifact bundle manifest.
- `python -m readiness.transform_pipeline --help`: help OK.
- `python -m readiness.transform_pipeline --source <csv> --out <temp>`: wrote deterministic transform pipeline bundle manifest with `raw_phi_in_public_artifacts=false`, `audit_log_retention=metadata_only`, and `external_network=false`.
- P3 guard scenario targeted `python -m pytest readiness/tests/test_guard_scenario_contract.py readiness/tests/test_open_source_contract.py readiness/tests/test_transform_pipeline_contract.py -q`: 12 passed.
- P3 guard scenario final `python -m pytest -q`: 198 passed, 2 skipped.
- `python -m readiness.guard_scenario --source <transform-bundle> --out <temp>`: wrote deterministic data-plane guard scenario manifest with `mode=synthetic_data_plane_guard_scenario`, `source_mode=synthetic_transform_pipeline`, `raw_phi_in_public_artifacts=false`, `legal_certification=false`, `mcp_live_bridge=false`, and policy actions `allow,drop,hash,redact`.
- `agy` P3 guard scenario reviewer result: `NO BLOCKERS` for raw identifier leakage, input hash leakage, reversible map leakage, legal/compliance certification claims, live/external bridge claims, path traversal, nondeterminism, docs/CLI/test mismatch, or transform regression.
- `agy` reviewer result: no P2 demo-loop blockers for raw synthetic identifier retention, legal certification claims, network/live MCP claims, nondeterminism, or missing tests/docs.
- `agy` P2 transform pipeline reviewer result: `NO BLOCKERS` for raw synthetic identifier retention, reversible map leakage, legal/compliance certification claims, external network/live MCP implication, nondeterminism, docs/tests/CLI mismatch, pyproject script mismatch, or guardrail-loop regression.
- Synthetic smoke:
  - `python -m compliance_checker.checker --standard hipaa --json <csv>` returned masked findings by default.
  - `python -m readiness <csv> --standards hipaa --html-out <temp>\readiness.html` wrote local HTML report.
  - `python -m mcp_bridge.client --help` showed outbound MCP allowlist/redaction surface without spawning a server.

## P4 Release-Prep Slice 1

Status: governance baseline added; this does not mark the project release-ready.

Evidence:
- `CONTRIBUTING.md` defines the contribution workflow, required test command, readiness-doc update rule, and no-private-data/no-credentials boundary.
- `SECURITY.md` defines private vulnerability reporting, supported version scope, 7-day acknowledgement target, and safe report contents.
- `python -m pytest readiness/tests/test_release_prep_contract.py -q`: 1 passed.
- `python -m pytest -q`: 199 passed, 2 skipped.

Remaining P4 work: full release gate, final docs audit, package metadata audit, release notes, tag plan, and maintainer sign-off.

## P4 Release-Prep Slice 2

Status: final release gate checklist added; this does not mark the project release-ready.

Evidence:
- `CHANGELOG.md` records the unreleased governance/release-checklist work and points back to readiness evidence.
- `docs/RELEASE_CHECKLIST.md` documents final tests, dependency/license review, secret/private-data scan, known limitations, and manual maintainer approval.
- `python -m pytest readiness/tests/test_release_prep_contract.py -q`: 2 passed.
- `python -m pytest -q`: 200 passed, 2 skipped.

Remaining P4 work: execute final scans, complete dependency/license review, finalize release notes, and record manual maintainer approval.

## P4 Release-Prep Slice 3

Status: final scan and direct dependency/license audit recorded; not release-ready.

Evidence:
- `docs/FINAL_RELEASE_AUDIT.md` records scan scope, `high_conf_secret_hits=0`, direct dependency/license review, and remaining release blockers.
- Default release-scope dependency review: no runtime dependencies beyond Python stdlib.
- Optional MCP SDK metadata reviewed: `mcp==1.28.1` MIT.
- `python -m pytest readiness/tests/test_release_prep_contract.py -q`: 3 passed.
- `python -m pytest -q`: 201 passed, 2 skipped.

Remaining P4 work: release notes finalization, tag plan, final maintainer approval, and separate review for any live MCP bridge path.

## P4 Release-Prep Slice 4

Status: maintainer approval recorded, conductor sign-off complete, and local tag created; remote publication pending.

Evidence:
- `docs/RELEASE_NOTES.md` records public release-candidate notes, known limitations, and verification pointers.
- `docs/TAG_PLAN.md` records proposed tag `v0.1.0-alpha.0`, required approval-before-tag sequence, and rollback steps.
- `docs/PUBLIC_RELEASE_APPROVAL.md` records `Status: approved` with approver, approval date, and approved tag.
- Conductor root approval packet `PHANTOM-SATELLITES-PUBLIC-RELEASE-APPROVAL.md` records all ten candidate tags as approved.
- `.github/workflows/ci.yml` runs an explicit `release-prep gate` against `readiness/tests/test_release_prep_contract.py`.
- `python -m pytest readiness/tests/test_release_prep_contract.py -q`: 5 passed.
- `python -m pytest -q`: 203 passed, 2 skipped.

Remaining publication work: confirm target remote and repository visibility before pushing tags or publishing release pages.
