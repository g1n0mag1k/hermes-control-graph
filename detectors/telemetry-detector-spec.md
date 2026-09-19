# Telemetry Detector Specification
## HCG-DP-001 — Sensitive Information Telemetry Boundary

**Version:** 1.0.0  
**Status:** Human-Approved  
**Author:** Andrew Rogers  
**Last Updated:** September 19, 2026  

---

## Purpose

This document specifies the requirements, behavior, data sources,
pass/fail criteria, and edge cases for the automated detector that
enforces HCG-DP-001 at the telemetry egress boundary.

The detector is implemented in `detectors/telemetry-detector.py`
and integrates with Hermes Relay for production detection behavior.

---

## What the detector must do

1. Inject a synthetic PHI canary into the telemetry pipeline
2. Confirm the canary is intercepted before reaching any external destination
3. Confirm the gateway is operating in fail-closed mode
4. Produce a signed, hash-chained evidence receipt for every run
5. Return a structured pass or fail result with all required evidence fields
6. Trigger the exception workflow on any fail condition
7. Never transmit real PHI or the canary value itself to any external system

---

## Data sources

| Source | Type | Purpose |
|---|---|---|
| Hermes Relay API | Internal API | PHI detection and canary interception |
| Azure Configuration API | External API | Gateway configuration state |
| Local test runner | Internal | Synthetic PHI pattern test suite |
| Evidence store | Local file | Hash-chained receipt chain |

---

## Trigger conditions

| Trigger | Action |
|---|---|
| New deployment | Run full canary interception test |
| Configuration change | Run gateway configuration audit |
| Scheduled daily run | Run configuration audit and log result |
| Scheduled per-release | Run full detection coverage review |
| Scheduled quarterly | Run adversarial probe suite |
| Manual invocation | Run specified test type |

---

## Pass conditions

All of the following must be true for a pass result:

- `interception_confirmed == true`
- `external_transmission_confirmed == false`
- `fail_closed_enabled == true`
- `false_negative_rate == 0.00`
- `unauthorized_destinations == []`
- Evidence receipt produced with valid artifact hash and HMAC signature
- Prior record hash matches the previous receipt in the chain

---

## Fail conditions

Any one of the following produces a fail result:

- `interception_confirmed == false` — canary reached external destination
- `external_transmission_confirmed == true` — confirmed boundary breach
- `fail_closed_enabled == false` — gateway not in fail-closed mode
- `false_negative_rate > 0.00` — at least one sensitive pattern not intercepted
- `unauthorized_destinations != []` — unauthorized endpoint reachable
- Evidence receipt cannot be produced — treat as fail
- Prior record hash does not match — chain integrity failure

---

## Fail behavior

On any fail condition the detector must:

1. Immediately return a fail result — never suppress or retry silently
2. Block the deployment or release that triggered the run
3. Produce a fail evidence receipt recording the failure details
4. Open an exception record in the POA&M workflow
5. Send a sanitized Slack alert containing only the finding ID
   — never include PHI, canary values, or sensitive configuration details
6. Require human review before the next deployment proceeds

---

## Edge cases

| Edge case | Expected behavior |
|---|---|
| Detection service unavailable | Fail closed — block telemetry and return fail result |
| Canary encoded as Base64 | Detector must intercept encoded form — pass only if intercepted |
| Canary split across two fields | Detector must intercept split form — pass only if intercepted |
| Canary in a nested JSON payload | Detector must inspect nested structures — pass only if intercepted |
| Canary in a URL query parameter | Detector must inspect query strings — pass only if intercepted |
| Malformed payload | Detector must flag for human review — do not pass |
| Gateway configuration API unavailable | Fail closed — return fail result for configuration audit |
| Hash chain broken | Return chain integrity failure — escalate to human review immediately |
| Prior receipt missing | Treat as first record — document in receipt and flag for review |
| Canary value accidentally matches real data | Canary patterns must be synthetic and non-realistic by design |

---

## Evidence output specification

Every detector run must produce a JSON receipt containing at minimum:

```json
{
  "receipt_id": "rcpt-2026-09-19-deploy-001",
  "deployment_id": "deploy-2026-09-19-001",
  "timestamp": "2026-09-19T15:00:00Z",
  "test_type": "canary-interception",
  "detector_version": "1.0.0",
  "passed": true,
  "interception_confirmed": true,
  "external_transmission_confirmed": false,
  "fail_closed_enabled": true,
  "false_positive_rate": 0.02,
  "false_negative_rate": 0.00,
  "canary_pattern": "ssn-pattern-type-3",
  "interception_point": "hermes-relay-gateway-v1.4.2",
  "unauthorized_destinations": [],
  "artifact_hash": "sha256:a3f9c2...",
  "prior_record_hash": "sha256:b7e1d4...",
  "hmac_signature": "hmac-sha256:g9e4c2..."
}
```

---

## Privacy requirements

- Canary values must be synthetic and non-realistic
- No real PHI may appear in any detector input, output, or log
- Slack alerts must contain only the finding ID — no sensitive details
- Evidence receipts must not contain the canary value itself
- All receipts are stored locally — never transmitted to external systems

---

## Human review requirements

Human review is required before closing any of the following:

- A fail result on any test type
- A chain integrity failure
- A malformed payload finding
- An adversarial probe finding
- Any exception record opened by the detector

Human review is logged in the POA&M record and required before
the next deployment is approved.

---

## Integration with Hermes Relay

The detector calls Hermes Relay for:

- PHI detection on synthetic canary payloads
- HMAC signing of evidence receipts
- SHA-256 hash chaining of the evidence record chain

Hermes Relay core implementation is private. The detector integrates
via a sanitized API interface defined in `integrations/hermes/`.

In environments where Hermes Relay is unavailable the detector falls
back to a local mock interface that simulates detection behavior for
demonstration purposes.

---

## Version history

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0.0 | 2026-09-19 | Andrew Rogers | Initial specification |