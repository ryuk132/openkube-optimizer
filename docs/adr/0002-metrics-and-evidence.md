# ADR 0002: Recent metrics first; historical sizing deferred

- Status: Accepted
- Date: 2026-09-28
- Accepted: 2026-09-28
- Authority: Explicit user approval of D1–D3 and authorization to accept ADRs after final architecture review; Milestone 1 is not authorized.

## Context

Observed utilization is necessary for useful comparisons. Metrics Server is a small starting dependency, but recent measurements do not establish long-term workload demand.

## Decision

Use the Metrics API through a provider boundary, with optional bounded in-memory polling. Produce explainable findings and investigation candidates. Defer Prometheus integration, P95 sizing, numerical resource targets, and HIGH confidence optimization recommendations until a historical methodology is reviewed.

Adopt the accepted [evidence-v1 contract](../evidence-eligibility.md): explicit startup and full-window checks, internal memory-only UID/lifecycle/allocation stability, source freshness, missing/duplicate handling, rollout checks, and abstention. Snapshot findings require individually eligible evidence. Overprovisioning requires a completed 30–60 minute run with the declared coverage/gap requirements; shortened runs never qualify.

Use one inventory-only baseline followed by global 60-second slots and a separate final inventory. Default 30 minutes means 30 slots and at least 27 distinct valid observations per resource (60 minutes: 54 of 60), not a counted baseline sample. Startup gate, freshness ceiling, CPU-window ceiling, and accepted-receipt gap are each 120 seconds but have different meanings. Snapshot is one bracket cycle and needs one eligible observation. Source collection failure and insufficient applicable evidence are incomplete outcomes; tolerated sample rejections can coexist with sufficient coverage. See the exact timing/counter definitions rather than redefining them here.

The initial 30% overprovisioning and 90% memory-limit-headroom ratios are hypotheses, not best practices. Make the three heuristic ratios independently configurable, range-validated, documented, versioned with their rules, and tested. Report every effective threshold and rule version. Changes to thresholds never weaken eligibility floors. See [recommendations](../recommendations.md#threshold-configuration).

Approved D1 fixes and versions evidence bounds instead of optional stricter per-run overrides, as recorded in [ADR 0005](0005-cli-and-report-contract.md). Changes to the frozen policy require documented review.

Never claim production-safe values, monetary savings, reclaimable infrastructure capacity, or reliability improvements. Every result is an investigation candidate with human review required.

## Alternatives

Prometheus in v0.1 offers historical evidence but also requires query contracts, identity continuity, metric availability, authentication, and coverage semantics. Allocation-only analysis cannot meet the utilization requirement. Claiming confidence from a few recent samples creates unsupported advice.

## Consequences

v0.1 validates the collection-to-report pipeline without promising safe resizing. It cannot reproduce the aspirational `1000m → 350m` recommendation. Missing or ambiguous evidence leads to abstention; it must not become a zero usage value. The provider abstraction must expose source limitations, not pretend all sources are interchangeable.

Strict startup/rollout gates may reduce available findings; expose that coverage rather than guessing. Evidence policy and threshold calibration require synthetic boundary tests and representative validation. This ADR is Accepted; acceptance establishes the methodology contract, not calibrated production guidance or implementation correctness.
