# Changelog
## Hermes Control Graph — AI-Assisted Multi-Framework Control and Evidence Lab

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.1] — 2026-09-19

### Fixed
- `detectors/telemetry-detector.py` — added split-field detection logic
  to `HermesMock.detect()` to intercept SSN patterns split across two
  JSON fields
- All 7 canary patterns now pass — false negative rate reduced from
  0.1429 to 0.0000
- Detector version bumped from 1.0.0 to 1.0.1

### Evidence
- Fail receipt: `rcpt-f7fe7f0fb754` — 6/7 cases, false negative rate 0.1429
- Pass receipt: `rcpt-7992ed268c4f` — 7/7 cases, false negative rate 0.0000
- Hash chain intact from failure through remediation to verified closure
- POA&M record: `exceptions/sample-poam.json` — POAM-HCG-2026-001

### Remediation
- Finding ID: `finding-a946f454`
- Root cause: split-field edge case not handled in mock detection logic
- Deployment blocked on fail result — no telemetry transmitted during gap
- Fail-closed gateway remained active throughout
- Human review: Andrew Rogers — 2026-09-19 — approve-remediation

---

## [1.0.0] — 2026-09-19

### Added

#### Documentation
- `README.md` — project overview, problem statement, repo structure,
  framework table, AI workflow, and related projects
- `docs/prd.md` — product requirements document covering problem
  statement, users, jobs-to-be-done, scope, success criteria,
  constraints, AI workflow stages, and open questions
- `docs/common-control.md` — canonical control definition for
  HCG-DP-001 including objective, risk, control type, applicability,
  sensitive information scope, implementation guidance, test methods,
  required evidence, exceptions, and framework mapping summary

#### Controls
- `controls/common-control.yaml` — machine-readable canonical control
  record for HCG-DP-001 with full attribute set including test methods,
  required evidence, exception requirements, and framework mappings

#### Mappings
- `mappings/crosswalk.csv` — 14 bidirectional framework mapping records
  covering HIPAA, SOC 2, ISO 27001, NIST CSF 2.0, and NIST SP 800-53
  Rev 5 — each record includes source identifier, source URL, mapping
  direction, confidence score, human-written rationale, reviewer,
  approval status, and version

#### Evidence
- `evidence/evidence-dictionary.yaml` — four evidence records defined
  for HCG-DP-001: PHI detection test results, telemetry gateway
  configuration, canary interception receipt, and coverage review log —
  each with required fields, types, examples, collection method,
  pass/fail conditions, and fail actions

#### Detectors
- `detectors/telemetry-detector-spec.md` — full detector specification
  covering purpose, data sources, trigger conditions, pass conditions,
  fail conditions, fail behavior, edge cases, evidence output
  specification, privacy requirements, human review requirements,
  and Hermes Relay integration
- `detectors/telemetry-detector.py` — Python detector harness
  implementing canary interception testing, gateway configuration
  audit, hash-chained evidence receipts, HMAC signing, exception
  workflow, and Slack alert stub

#### Evaluations
- `evaluations/gold-set.jsonl` — 25 evaluation cases across four
  categories: correct mappings (8), partially correct mappings (6),
  unsupported mappings (7), and PHI privacy boundary cases (5) —
  each with expected output, AI-proposed output, result, accuracy
  score, source support status, and human approval status
- `evaluations/results.csv` — scored results: 17 pass, 6 partial,
  2 fail, 0.854 average accuracy, 23/25 source supported,
  17/25 human approved

#### Policies
- `policies/ai-safe-use.md` — AI safe-use policy covering tools in
  scope, permitted and prohibited AI actions, required fields,
  mapping status labels, human review requirements, privacy boundaries,
  confidence score definitions, evaluation and regression rules,
  release threshold, and prohibited outputs

#### Exceptions
- `exceptions/sample-poam.json` — sanitized POA&M record for
  POAM-HCG-2026-001 documenting the split-field detection gap,
  root cause, five remediation steps, compensating controls,
  before and after evidence receipts, chain integrity verification,
  lessons learned, recurrence prevention, and framework impact

### Framework coverage
- HIPAA 45 CFR Parts 160 and 164
- SOC 2 AICPA TSC 2017
- ISO/IEC 27001:2022
- NIST CSF 2.0
- NIST SP 800-53 Revision 5

### Evaluation results — v1.0.0
| Metric | Value |
|---|---|
| Total cases | 25 |
| Pass | 17 |
| Partial | 6 |
| Fail | 2 |
| Average accuracy | 0.854 |
| Source supported | 23/25 |
| Human approved | 17/25 |
| Privacy boundary pass rate | 5/5 |
| False negative rate on privacy cases | 0.000 |