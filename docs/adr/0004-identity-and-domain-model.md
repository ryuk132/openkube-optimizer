# ADR 0004: Typed records and UID-based workload ownership

- Status: Accepted
- Date: 2026-09-28
- Accepted: 2026-09-28
- Authority: Explicit user approval of D1–D3 and authorization to accept ADRs after final architecture review; Milestone 1 is not authorized.

## Context

Pods are replaceable, names can be reused, and Deployment rollouts create multiple ReplicaSets. Incorrect association can generate recommendations for the wrong workload or allocation.

## Decision

Keep normalized, typed container records independent of the Kubernetes SDK. Map controller owner references by UID through Pod → ReplicaSet → Deployment within one namespace. Keep observed Pod allocations separate from Deployment template allocations. Attach metric source, timestamp, window, and evidence quality to samples; reject uncertain joins.

Use the [exact projection/report allowlists](../data-and-egress.md), not arbitrary SDK serialization. Raw objects stay transient inside retrieval/projection; domain and analysis modules never import the Kubernetes client. Fingerprints cover only allowlisted allocation/template fields. Resource-version changes trigger relevant-field comparisons rather than blanket evidence invalidation.

Bracket metrics with complete inventory checks. Segment container execution by Pod UID/container name, restart count, and running start time; validate the full CPU measurement interval. Apply the [evidence contract](../evidence-eligibility.md) for startup, newly created Pods, restarts, rollouts, allocation changes, stale/missing/duplicate samples, ambiguity, and shortened runs. Do not combine incompatible execution segments or infer absent metrics as zero.

An inventory-only observation baseline is distinct from a per-slot bracket. Coverage is per subject/resource and present even without findings; repeated triggers aggregate only within the same execution/allocation segment. Duplicate conflicts invalidate affected previous evidence. Keep internal UIDs, identity maps, fingerprints, and resource versions out of output. D3 permits necessary human-readable names and creation-time evidence in reports, never UIDs or UID-derived IDs. UID correlation/counting remains memory-only; release references after required analysis and never persist/log them. Finding IDs are run-local sequence identifiers, not resource pseudonyms. No pseudonymization is introduced.

## Alternatives

Name prefixes and labels are convenient but are not authoritative ownership. Passing SDK objects throughout the engine couples tests to the API and spreads sensitive fields. Summing all replicas before analysis hides heterogeneous allocation and replica-specific risk.

## Consequences

ReplicaSet list access is required. Orphans and unsupported owners produce explicit skipped outcomes. Inventory checks around metrics reduce name-reuse risk but cannot provide a transactional cluster snapshot; abstention remains necessary. The additional domain types make security review and synthetic testing more precise.

Per-subject findings remain separate even when grouped under a Deployment; never merge distinct internal subjects merely because their output names match. Report policy versions, actual thresholds, coverage and abstention reasons. Required lifecycle/resize fields must be verified against pinned SDK/API versions; unknown semantics fail eligibility. This ADR is Accepted; UID-free output does not weaken UID-based internal ownership checks.
