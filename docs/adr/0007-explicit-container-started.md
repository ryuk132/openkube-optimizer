# ADR 0007: Require explicit container startup confirmation

- Status: Accepted
- Date: 2026-09-29
- Accepted: 2026-09-29
- Policy approval: User decision B on 2026-09-29; explicit user approval of ADR 0007 and Milestone 2 on 2026-09-29.
- Scope: Clarifies/tightens startup eligibility in the initial unreleased evidence specification; does not replace the broader decisions in Accepted ADRs 0002 or 0004.

## Context

The frozen evidence contract said `started` must be "not false", which could permit a missing value. The reference [Kubernetes v1.36.4 ContainerStatus](https://github.com/kubernetes/api/blob/v0.36.4/core/v1/types.go) says a null `started` value must be treated as false. OpenKube must not infer successful startup from uncertainty or SDK field loss.

## Decision approved for implementation

Future utilization eligibility requires `container_started` to be explicitly true in both inventory reads. False, ABSENT, INVALID, and UNAVAILABLE do not establish startup eligibility. Preserve these states in the domain instead of converting uncertainty to true or erasing it into false. All other lifecycle, timing, and evidence gates remain unchanged. Milestone 2 implements only state preservation, not eligibility evaluation.

## Alternatives and consequences

Keeping "not false" permits an optimistic interpretation of missing evidence. Converting all unknown states to false loses diagnostic distinctions. Explicit confirmation gives conservative behavior while retaining those distinctions; it may reduce usable evidence when required fields are missing.

The user explicitly approved this tightening. This narrow ADR records the reviewed policy change without rewriting earlier Accepted ADR history. The [evidence contract](../evidence-eligibility.md) and [review ledger](../consistency-review.md#milestone-2-approved-clarifications) record the dated amendment. Keep the initial unreleased `evidence-v1` identifier: no prior implementation or emitted report exists, and all numeric gates remain unchanged. This does not authorize silent changes to a released policy. The user explicitly accepted this ADR and Milestone 2 on 2026-09-29; acceptance does not authorize Milestone 3.
