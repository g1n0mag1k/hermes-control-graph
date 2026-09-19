# Hermes Control Graph
### AI-Assisted Multi-Framework Control and Evidence Lab

---

## What this is

A Product GRC proof-of-work artifact demonstrating how to translate
regulatory source authorities into reusable controls, bidirectional
framework mappings, evidence specifications, automated detectors,
exception workflows, and measurable AI-assisted compliance content.

This is not a compliance dashboard. It is a single control — implemented
end-to-end — from source authority through mapping, evidence collection,
automated testing, failure, remediation, and verified closure.

---

## The problem

Sensitive healthcare information leaks through application logs, telemetry
pipelines, and observability platforms. Most organizations do not detect
this until an audit finding, a breach, or a regulator asks for evidence
that never existed.

This lab demonstrates how a Product GRC team would:

- Define a canonical control independent of any single framework
- Map that control bidirectionally across HIPAA, SOC 2, ISO 27001, and NIST
- Specify exactly what evidence proves the control is operating
- Run automated detection against real telemetry behavior
- Handle failures through a structured exception and remediation workflow
- Evaluate AI-assisted mapping outputs against a gold-standard dataset

---

## The control

**HCG-DP-001 — Sensitive Information Telemetry Boundary**

Sensitive information must be detected and prevented from entering
unauthorized logs, telemetry systems, or external processing services.

---

## Repository structure

hermes-control-graph/
├── README.md # This file
├── CHANGELOG.md # Version history
├── docs/
│ ├── prd.md # Product requirements document
│ ├── common-control.md # Canonical control definition
│ ├── evidence-dictionary.md # Evidence fields and formats
│ └── detector-spec.md # Detector requirements and edge cases
├── controls/
│ └── common-control.yaml # Machine-readable control record
├── mappings/
│ └── crosswalk.csv # Bidirectional framework mappings
├── evidence/
│ └── evidence-dictionary.yaml # Required evidence schemas
├── detectors/
│ ├── telemetry-detector-spec.md # Detector specification
│ └── telemetry-detector.py # Python detection harness
├── evaluations/
│ ├── gold-set.jsonl # AI evaluation test cases
│ └── results.csv # Measured evaluation results
├── policies/
│ └── ai-safe-use.md # AI guardrails and human-review rules
├── exceptions/
│ └── sample-poam.json # Sanitized remediation record
└── integrations/
└── hermes/ # Hermes Relay interface (sanitized)


---

## Frameworks covered

| Framework | Version | Scope |
|---|---|---|
| HIPAA | 45 CFR Parts 160 and 164 | Technical safeguards, minimum necessary |
| SOC 2 | AICPA TSC 2017 | Security and confidentiality criteria |
| ISO 27001 | ISO/IEC 27001:2022 | Information classification, logging, monitoring |
| NIST CSF | Version 2.0 | Protect and Detect functions |
| NIST SP 800-53 | Revision 5 | Access control, audit, system monitoring |

---

## AI workflow

This lab uses a four-stage AI-assisted mapping workflow with deterministic
gates at every handoff:

1. **Perplexity Pro** — locate official source authorities and regulatory materials
2. **Claude** — draft proposed control mappings and rationale
3. **Gemini** — challenge mappings, identify missing conditions, flag unsupported conclusions
4. **Deterministic validator** — require source URL, control identifier, version, rationale,
   and confidence score before accepting any record
5. **Human review** — approve, reject, or revise
6. **Version control** — commit approved mapping with reviewer decision and change log
7. **Hermes attestation** — hash-chained receipt proving what was reviewed and approved

Every mapping record is labeled as one of: `ai-proposed` | `validated` | `human-approved` | `released` | `superseded`

---

## What this is not

- This is not a certified SOC 2, ISO 27001, or HIPAA compliance program
- This is not a production deployment of any framework
- All crosswalk mappings are illustrative and require qualified assessor review
- No proprietary framework text is reproduced in this repository

---

## Related projects

- **Hermes Relay** — the zero-egress PHI telemetry audit platform this lab integrates with (private)
- **Bureau483** — FDA enforcement intelligence platform (bureau483.com)

---

## Author

Andrew Rogers — Founder & Product GRC Engineer  
hermesrelay.dev | bureau483.com | linkedin.com/in/andrewrogerscompliance
