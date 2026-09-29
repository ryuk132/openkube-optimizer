# ADR 0003: Namespace-scoped access and data minimization

- Status: Accepted
- Date: 2026-09-28
- Accepted: 2026-09-28
- Authority: Explicit user approval of D1–D3 and authorization to accept ADRs after final architecture review; Milestone 1 is not authorized.

## Context

Discovery needs Pod and workload specifications. These responses may include sensitive inline fields even though Secret objects are never requested. Kubernetes RBAC grants resource access, not a projection of selected fields.

## Decision

Require explicit namespaces and only namespace-scoped `list` permissions for core Pods, apps Deployments/ReplicaSets, and `metrics.k8s.io` Pods. Remove automatic namespace discovery from v0.1: no Namespace requests or cluster-wide analysis grant. Recommend a dedicated least-privilege local analysis identity. OpenKube cannot protect users from broader privileges already held by supplied credentials.

The user permits transient full-response objects in process memory **only when technically required by the official Kubernetes client**. Immediately project responses/pages into the [exact internal allowlist](../data-and-egress.md#exact-projection-allowlist), then release raw references as soon as technically possible. Raw objects must never be persisted, logged, exposed through exceptions, or included in reports. Reports have a separate closed allowlist. Sanitize SDK errors without copying response bodies, headers, raw object representations, or traceback chains.

Never request Secrets, ConfigMaps, application logs, nodes, events, or other unlisted resources. Prohibit mutation, exec, attach, port-forward, Kubernetes proxy functionality, token creation, impersonation, and RBAC administration. Authentication material is transport-only, never analysis/report data. No OpenKube telemetry or analytics. The [egress contract](../data-and-egress.md) discloses API/authentication traffic, DNS, credential helpers, transport proxies, and operator-controlled output capture.

Projection reduces retention and exposure; it does not guarantee sensitive fields never temporarily exist in process memory, secure erasure, or protection against a compromised collector/host.

**D3 approved:** allow only necessary namespace, Deployment, Pod, and regular container names in reports. Names can contain sensitive organizational information, so reports are potentially sensitive artifacts despite excluding raw objects, credentials, Secrets, annotations, logs, environment values, endpoints, and other prohibited content. ReplicaSet names are not needed in v0.1 output.

Kubernetes UIDs may be used internally for identity, ownership correlation, and deduplication only in memory for the duration needed by analysis. Never emit, log, persist, cache on disk, or encode/hash UIDs into output IDs. Release UID references when no longer required and on failed/interrupted teardown. The report projection strips all UID fields before serialization, temporary/saved file writes, or error rendering. No pseudonymization in v0.1; privacy-enhanced reporting requires a future ADR and a real use case. See the [resolved decisions](../consistency-review.md#resolved-decisions-and-acceptance).

## Alternatives

A broad read role exposes unnecessary resources. Label/field selectors constrain objects, not sensitive fields within them. A trusted upstream projection service or sanitized-input-only mode would change the trust boundary/product scope; neither is necessary under the user-permitted transient exposure and neither is proposed for v0.1. Optional namespace discovery adds cluster-wide disclosure and is removed.

## Consequences

Both the transient-exposure interpretation and report-identifier policy are resolved by explicit user decisions. This ADR is Accepted; implementation is not authorized. Small grants reduce blast radius but do not eliminate sensitive reads within allowed objects or broader supplied credentials. Verify credential/UID canaries, report projection, restricted RBAC, raw/UID reference lifetime, and transport bounds before collection acceptance. See the complete [security model](../security.md).
