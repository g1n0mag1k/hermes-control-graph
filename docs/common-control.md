# Common Control Definition
## HCG-DP-001 — Sensitive Information Telemetry Boundary

**Version:** 1.0.0  
**Status:** Human-Approved  
**Author:** Andrew Rogers  
**Reviewer:** Andrew Rogers  
**Last Updated:** September 19, 2026  

---

## Control identifier

`HCG-DP-001`

---

## Control name

Sensitive Information Telemetry Boundary

---

## Control objective

Sensitive information must be detected and prevented from entering
unauthorized logs, telemetry systems, or external processing services
at all times — including during development, testing, staging, and
production operations.

---

## Risk addressed

Application telemetry, observability pipelines, and log aggregation
services routinely capture full request and response payloads. Without
an active boundary control, protected health information, personally
identifiable information, and other sensitive identifiers can be
transmitted to external processors, retained in plaintext logs, and
exposed during vendor access, audit, or breach investigation.

---

## Control type

| Attribute | Value |
|---|---|
| Control family | Data protection |
| Control type | Preventive + Detective |
| Control method | Automated |
| Control owner | Product GRC / Engineering |
| Review frequency | Per release + quarterly |

---

## Applicability

This control applies to any system that:

- Processes, transmits, or stores sensitive information as defined below
- Emits logs, traces, metrics, or telemetry to an external destination
- Integrates with a third-party observability, monitoring, or analytics platform

---

## Sensitive information in scope

- Protected health information (PHI) as defined under HIPAA 45 CFR § 164.304
- Personally identifiable information (PII) including names, addresses,
  dates of birth, Social Security numbers, financial account numbers,
  and government-issued identifiers
- Authentication credentials including passwords, tokens, and API keys
- Any identifier that could be used alone or in combination to identify
  an individual

---

## Implementation guidance

1. Deploy a deterministic detection layer at every telemetry egress point
   before data leaves the application boundary
2. Configure the detection layer to operate fail-closed — if detection
   is unavailable, telemetry must be blocked, not passed through
3. Run synthetic canary identifiers through the pipeline on every
   deployment to verify the boundary is active
4. Produce a signed, hash-chained evidence receipt for every detection
   run confirming pass or fail status
5. Log all detection events locally without transmitting sensitive
   content to external systems
6. Review detection coverage against the full identifier category list
   on every release

---

## Test method

| Test type | Description | Frequency |
|---|---|---|
| Synthetic canary | Inject known PHI patterns and verify interception before external transmission | Per deployment |
| Configuration audit | Verify fail-closed setting is active and destination is authorized | Daily |
| Coverage review | Confirm detection covers all identifier categories in scope | Per release |
| Adversarial probe | Attempt bypass using encoded, split, and malformed identifiers | Quarterly |

---

## Required evidence

| Evidence ID | Name | Format | Frequency |
|---|---|---|---|
| EVD-001 | PHI detection test results | JSON | Per release |
| EVD-002 | Telemetry gateway configuration | JSON | Daily |
| EVD-003 | Canary interception receipt | JSON (hash-chained) | Per deployment |
| EVD-004 | Coverage review log | Markdown | Per release |

Full evidence specifications are defined in `evidence/evidence-dictionary.yaml`.

---

## Exceptions

Any exception to this control requires:

1. A documented business justification
2. Approval from the control owner
3. A compensating control or time-bound remediation plan
4. A POA&M record created in the exceptions workflow
5. Re-evaluation within 30 days or at the next release cycle

Exceptions are never permanent. Every exception record carries an
expiration date and a remediation owner.

---

## Framework mappings

Full bidirectional mappings are maintained in `mappings/crosswalk.csv`.
Summary:

| Framework | Identifier | Mapping confidence |
|---|---|---|
| HIPAA | 45 CFR § 164.312(a)(2)(iv), § 164.312(e)(2)(ii) | High |
| SOC 2 | CC6.1, CC6.7, CC7.2 | Medium-High |
| ISO 27001 | A.8.12, A.8.15, A.8.16 | Medium-High |
| NIST CSF 2.0 | PR.DS-1, PR.DS-2, DE.CM-1 | High |
| NIST SP 800-53 Rev 5 | AC-4, AU-3, SI-12 | Medium-High |

> These mappings are illustrative. They require qualified assessor
> review before use in a certification or audit program.

---

## Version history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0.0 | 2026-09-19 | Andrew Rogers | Initial definition |