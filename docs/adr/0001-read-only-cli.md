# ADR 0001: Read-only Python CLI with modular internals

- Status: Accepted
- Date: 2026-09-28
- Accepted: 2026-09-28
- Authority: Explicit user approval of D1–D3 and authorization to accept ADRs after final architecture review; Milestone 1 is not authorized.

## Context

The project needs a testable Kubernetes analysis path and a small operational footprint. The user must remain responsible for workload changes.

## Decision

Use one **local-only** Python CLI process, the official Kubernetes client, isolated I/O adapters, pure analysis rules, and local terminal/JSON reports. Require an explicit trusted kubeconfig context and one or more explicit namespaces. No current-context/namespace inference, namespace discovery, all-namespaces endpoint, in-cluster authentication loader, or fallback. Expose no mutation operation and provide no automatic remediation. Follow the accepted [CLI contract](../cli-contract.md) for bounded execution and output.

The complete accepted configuration selects one kubeconfig file (explicit path or `~/.kube/config`), with no implicit `KUBECONFIG` merging. Client/helper transport inputs remain trusted external dependencies. Approved D1 is recorded in [ADR 0005](0005-cli-and-report-contract.md); no configuration framework is introduced.

## Alternatives

A set of microservices adds deployment and authentication boundaries before they solve a concrete problem. An operator or controller introduces continuous reconciliation machinery we do not need. A notebook or single script is useful for exploration but makes reusable contracts and regression testing harder.

Supporting local and in-cluster execution together adds identity, packaging, token, egress, and retention decisions. Defer in-cluster execution to a separate future ADR. Optional namespace discovery adds cluster-wide permission without being necessary for explicit scope.

## Consequences

The first release has no always-on API/dashboard, collector Job/image, telemetry, or analytics, and only one cluster per run. Future interfaces can call the same coordinator after review. Read-only RBAC is a second protection layer; it does not make arbitrary input or broad local credentials safe. This decision is Accepted as part of the v0.1 freeze; Milestone 1 still requires separate explicit user authorization.

## Dated clarification — 2026-09-30

Accepted [ADR 0008](0008-restricted-kubeconfig-and-bounded-transport.md) refines official-client use: generated request construction/dispatch sits behind controlled bounded wire handling, bypassing stock REST errors and generic generated deserialization as boundaries. One synchronous local process, explicit context/namespaces and permissions remain unchanged. Its Ubuntu resolved/procfs profile and native setup cancellation qualification govern current implementation intent. M3 design is complete; implementation still needs separate authorization.
