# Product Requirements Document
## Hermes Control Graph — AI-Assisted Multi-Framework Control and Evidence Lab

**Version:** 1.0.0  
**Status:** Draft  
**Author:** Andrew Rogers  
**Last Updated:** September 19, 2026  

---

## Problem statement

Sensitive healthcare information leaks through application logs, telemetry
pipelines, and observability platforms. Most organizations discover this
during an audit finding, a breach notification, or a regulator request for
evidence that was never collected.

GRC teams face three compounding problems:

1. **Framework fragmentation** — the same control requirement appears under
   different identifiers across HIPAA, SOC 2, ISO 27001, and NIST, forcing
   teams to maintain parallel control sets that drift out of sync.

2. **Evidence ambiguity** — policies exist but nobody has specified exactly
   what artifact, in what format, collected at what frequency, proves the
   control is actually operating.

3. **AI-assisted content risk** — teams are using AI to draft control
   mappings and compliance content without evaluation datasets, accuracy
   thresholds, or human-review gates, producing outputs that cannot be
   audited or trusted.

---

## Who this is for

| User | Job to be done |
|---|---|
| Product GRC SME | Define canonical controls and map them across frameworks without duplicating effort |
| Compliance Engineer | Know exactly what evidence to collect and what format it must be in |
| Security Auditor | Inspect a complete chain from source authority to evidence receipt |
| AI Governance Lead | Evaluate AI-assisted mapping outputs against a gold standard before release |
| Engineering Team | Receive unambiguous acceptance criteria and detector specifications |

---

## Jobs to be done

1. Translate a regulatory source requirement into a canonical, framework-independent control
2. Map that control bidirectionally across multiple frameworks with confidence scores and rationale
3. Specify exactly what evidence proves the control is operating — format, frequency, required fields
4. Run automated detection and produce a signed, hash-chained evidence receipt
5. Handle control failures through a structured exception and remediation workflow
6. Evaluate AI-assisted mapping outputs against a gold-standard dataset before approving them
7. Maintain a complete version history of every control, mapping, and evidence decision

---

## Scope

### In scope
- One canonical control: HCG-DP-001 — Sensitive Information Telemetry Boundary
- Framework mappings: HIPAA, SOC 2, ISO 27001, NIST CSF 2.0, NIST SP 800-53 Rev 5
- Evidence dictionary for HCG-DP-001
- Automated detector specification and Python harness
- AI evaluation dataset: 25–50 cases with gold-standard answers and scored results
- Exception workflow and sample POA&M record
- AI safe-use policy covering this lab's workflow

### Out of scope
- Certification or attestation under any framework
- Coverage of more than one control in this version
- Production deployment or customer data
- Reproduction of proprietary framework text

---

## Success criteria

| Metric | Target |
|---|---|
| Frameworks mapped | 5 |
| Mapping confidence documented | 100% of records |
| Evidence fields specified | All required fields named, typed, and sourced |
| Detector pass/fail defined | Pass condition, fail condition, and edge cases documented |
| AI evaluation cases | Minimum 25 |
| Gold-standard accuracy | Measured and published, including weaknesses |
| Human-review gate | Required before any mapping reaches `released` status |
| Version history | Every record carries version, reviewer, and change log |

---

## Constraints

- No proprietary framework control text may be reproduced
- No real PHI or personal data may appear in any file in this repository
- All AI-proposed content must be labeled as such until human-approved
- Hermes Relay core implementation remains private
- All crosswalk mappings must carry a disclaimer that they are illustrative
  and require qualified assessor review before operational use

---

## AI workflow stages

| Stage | Tool | Role |
|---|---|---|
| 1 | Perplexity Pro | Locate official source authorities |
| 2 | Claude | Draft proposed mapping and rationale |
| 3 | Gemini | Challenge mapping, flag unsupported conclusions |
| 4 | Deterministic validator | Enforce required fields before acceptance |
| 5 | Human review | Approve, reject, or revise |
| 6 | Version control | Commit with reviewer decision and change log |
| 7 | Hermes attestation | Hash-chained receipt of approved record |

---

## Open questions

- [ ] Will the detector harness call Hermes Relay via API or use a local mock?
- [ ] Which Slack workspace will receive exception notifications in the demo?
- [ ] Will the Notion remediation database be public or access-restricted?

---

## Version history

| Version | Date | Author | Notes |
|---|---|---|---|
| 1.0.0 | 2026-09-19 | Andrew Rogers | Initial draft |