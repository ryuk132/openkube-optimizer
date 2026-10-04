# Milestone 2 domain model

Status: **Milestone 2 complete and accepted on 2026-09-29.** The user approved eleven immutable records and pure quantity conversion. The M2 domain layer remains stdlib-only and does not import `yaml`, `kubernetes` or `h11`. The OpenKube project now has the three approved M3 runtime dependencies, `kubernetes==36.0.3`, `h11==0.16.0` and `PyYAML==6.0.3`; none is used by the domain layer. No SDK integration, collection, ownership adapter, polling, eligibility calculation, analysis rule, recommendation, CLI, or reporting behavior is implemented. `AnalysisSettings` is explicitly deferred until analysis/configuration code needs it. Milestone 3 architecture/design is complete under Accepted [ADR 0008](adr/0008-restricted-kubeconfig-and-bounded-transport.md), dated 2026-09-30; M3.1 and restricted kubeconfig document loading (M3.2A) are implemented; selection, authentication and all later behavior require separate authorization.

The [data contract](data-and-egress.md#exact-projection-allowlist) remains the field authority. This document explains the implemented subset and its boundaries, not an additional collection or report allowlist. Source is in [models.py](../src/openkube_optimizer/domain/models.py) and [quantities.py](../src/openkube_optimizer/domain/quantities.py).

## Representation and field states

All eleven records use standard-library dataclasses with `frozen=True`, `slots=True`, `kw_only=True`, and `repr=False`. Nested records and tuples are immutable; constructors reject arbitrary mappings, SDK-like objects, mutable container lists, and unexpected runtime types. Every field must be supplied explicitly. There are no implicit healthy defaults or generic `eligible` flags.

`Field[T]` is only a type alias for `T | FieldState`, not a wrapper or validation framework. A supplied valid value, including zero or false, is distinct from:

| State | Meaning |
| --- | --- |
| `ABSENT` | The applicable field was inspected and was not present |
| `INVALID` | The supplied value was rejected; its raw content is not retained |
| `UNAVAILABLE` | The fact could not be established, including unverified field visibility/interpretation |

Accepted [ADR 0008 D1/D3](adr/0008-restricted-kubeconfig-and-bounded-transport.md) requires bounded strict wire projection before domain construction, not generated SDK deserialization. Unprojectable mandatory identity/ownership or list structure invalidates the affected namespace inventory pass; complete independent namespaces remain usable. Do not silently drop malformed objects and claim completeness. Well-formed unsupported/unresolved ownership and non-identity uncertainty remain representable; no domain record or quantity change is required. M3 supplies inventory; M4 supplies PodMetrics.

Collection failure is not a field state. Later collection code must report it separately and must not manufacture empty inventory. A Kubernetes condition's `Unknown` value is also distinct from these three states. Known absence in a presence/count projection becomes false/zero; uncertainty does not.

`UID` is an opaque string `NewType`, not a UUID parser. `UtcNs`, `MonotonicNs`, and `DurationNs` distinguish integer units statically; runtime checks separately reject booleans and non-integers. UTC values cover years 1–9999 in integer epoch nanoseconds; monotonic readings have an arbitrary origin and are not UTC; durations are nonnegative. No timestamp parsing or clock access is implemented.

## Implemented fields

Notation: `F[T]` below means `Field[T]`. Every field is a required constructor argument; `None` is permitted only where explicitly listed.

| Record | Fields / types |
| --- | --- |
| `ContainerIdentity` | `namespace: str`, `pod_uid: UID`, `container_name: str` |
| `DeploymentIdentity` | `namespace: str`, `uid: UID` |
| `Ownership` | `state: OwnershipState`, `replicaset_uid: UID or None`, `deployment: DeploymentIdentity or None` |
| `ResourceAllocation` | `cpu_request_cores`, `cpu_limit_cores`: `F[Decimal]`; `memory_request_bytes`, `memory_limit_bytes`: `F[int]` |
| `SupportFacts` | `pod_resources_present`, `restartable_init_present`, `overhead_present`: `F[bool]`; `init_container_count`, `ephemeral_container_count`: `F[int]` |
| `ContainerLifecycle` | `pod_phase: F[PodPhase]`, `pod_deleting: F[bool]`, `pod_ready: F[ConditionStatus]`, `pod_ready_transition_at: F[UtcNs]`, `container_ready: F[bool]`, `container_started: F[bool]`, `container_state: F[ContainerState]`, `restart_count: F[int]`, `running_started_at: F[UtcNs]` |
| `AllocationStatus` | `allocated_cpu_cores: F[Decimal]`, `allocated_memory_bytes: F[int]`, `reported_allocation: F[ResourceAllocation]`, `resize_status: F[ResizeStatus]`, `resize_pending`, `resize_in_progress`: `F[ConditionStatus]`; `resource_status_present: F[bool]` |
| `ContainerInventory` | `identity: ContainerIdentity`, `pod_name: str`, `pod_created_at: UtcNs`, `pod_resource_version: F[str]`, `observed_at: UtcNs`, `ownership: Ownership`, `pod_allocation: ResourceAllocation`, `lifecycle: ContainerLifecycle`, `support: SupportFacts`, `allocation_status: AllocationStatus` |
| `TemplateContainer` | `name: str`, `allocation: ResourceAllocation` |
| `DeploymentInventory` | `identity: DeploymentIdentity`, `name: str`, `created_at: UtcNs`, `resource_version: F[str]`, `observed_at: UtcNs`, `deleting: F[bool]`; `generation`, `observed_generation`, `desired_replicas`, `status_replicas`, `updated_replicas`, `available_replicas`, `unavailable_replicas`: `F[int]`; `template_containers: F[tuple[TemplateContainer, ...]]`, `template_support: SupportFacts` |
| `MetricObservation` | `namespace`, `pod_name`, `container_name`: `str`; `corroborating_pod_uid: F[UID]`, `source: Literal["pod_metrics"]`, `source_timestamp: F[UtcNs]`, `cpu_window: F[DurationNs]`, `received_at: UtcNs`, `received_monotonic_at: MonotonicNs`, `cpu_cores: F[Decimal]`, `memory_bytes: F[int]` |

Enums are closed: ownership resolved/unsupported/unresolved; Pod Pending/Running/Succeeded/Failed/Unknown; condition True/False/Unknown; container running/waiting/terminated; resize InProgress/Deferred/Infeasible. Future projection must translate unrecognized source values to `INVALID` without retaining arbitrary strings. Required identity/name/creation-time failures cannot produce a resolved inventory record; their sanitized diagnostic outcome belongs to the later projection boundary.

Fixed constants name `data-v1`, `evidence-v1`, and the six rule/version pairs (all initially `1.0.0`). They contain no rule logic, configuration object, or registry. Future result records will identify the policy actually applied. The approved ten-input configuration remains unchanged.

## Identity, invariants, and data boundary

- Container identity is exactly namespace + Pod UID + regular container name. Deployment identity is namespace + Deployment UID. Names/creation times remain inventory facts, not substitutes for UID identity.
- Resolved ownership requires a ReplicaSet UID and Deployment identity in the subject's namespace. Unsupported/unresolved ownership cannot claim a verified Deployment. This validates record coherence, not the real controller chain; traversal requires the future complete inventory adapter.
- Restart count and running start time preserve execution-segment facts. Relevant allocations/status/support facts preserve allocation-change evidence. No segment builder, fingerprint calculator, or identity join is implemented.
- Resource versions are opaque equality tokens. An updated inventory record may differ while retaining the same identity. Later comparison must inspect relevant facts rather than invalidate every resource-version change.
- Requests/limits and Pod/template values remain separate. Explicit zero is not absence. Deployment counter mismatches remain representable; absent counters are not defaulted to zero. Template container names must be unique.
- CPU and memory validity are independent. A metric observation is unjoined evidence, not a claim of eligibility; the optional UID is corroboration only. A representable zero or long CPU window remains a fact for later rejection by the evidence policy.
- Constructors enforce field types, finite/nonnegative quantity bounds, count bounds, name syntax, identifier byte bounds, and coherent ownership. They do not calculate health, eligibility, startup age, rollout stability, deduplication, or findings.

UIDs may exist only in necessary in-memory identities, ownership, and metric corroboration. No UID may be logged, reported, persisted, or encoded/hashed into public identifiers. No logging, serializer, persistence, or public-ID generator is implemented. `repr=False` prevents automatic field printing but does not make these objects safe to serialize. Do not use `asdict`, pickle, or generic record dumps for output. Future report projection must construct its separate closed allowlist before any serialization or file write. Only selected allowlisted names, normalized values, timestamps, and derived summaries are eligible for later reporting; entire domain records are never directly reportable.

Names themselves can be sensitive and are also excluded from automatic representations and validation messages. Error messages are fixed tool-authored text; invalid values are not interpolated. Future adapters must handle exceptions without raw tracebacks/locals. Frozen dataclasses are not an isolation boundary, and releasing references is not secure erasure. UID lifetime across a complete run and output exclusion remain future integration obligations.

## Exact quantity conversion

`parse_cpu` returns exact `Decimal` cores. `parse_memory` returns integer bytes, rounding any valid nonnegative fractional byte **upward** after exact parsing: `0.4` or `400m` becomes 1 byte, `1.0` becomes 1, and `1.2` becomes 2. Zero stays zero. Negative nonzero values are rejected. Bounds are checked on the normalized result; values above the memory ceiling cannot be rounded down into range.

The approved normalization matches the direction of upstream [Quantity.Value](https://pkg.go.dev/k8s.io/apimachinery/pkg/api/resource#Quantity.Value); Kubernetes documents that [memory `400m` is 0.4 bytes](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#memory-resource-units). This parser is not a complete reimplementation of Kubernetes admission validation or Quantity canonicalization. Configured-resource restrictions and SDK/API field semantics still need later validation; the parser preserves fine CPU metric precision.

Accepted syntax uses ASCII digits, an optional leading sign, an integer or decimal mantissa, and at most one suffix: decimal `n`, `u`, `m`, `k`, `M`, `G`, `T`, `P`, `E`; binary `Ki`, `Mi`, `Gi`, `Ti`, `Pi`, `Ei`; or decimal exponent `e`/`E` with an optional sign. Whitespace, underscores, unknown/case-mismatched suffixes, non-finite values, and malformed syntax are rejected. Parsing never uses float or caller-dependent Decimal arithmetic/rounding.

The existing limits remain 128 input characters, 1,000,000 CPU cores, and `2**60` memory bytes. A fixed implementation expansion guard accepts explicit exponent magnitudes at most 128, checked before exponentiation; combined with the input-length bound, intermediate integers stay below 300 decimal digits. Excessively negative exponents are rejected too, not silently underflowed to zero. This is a documented parser guard, not an additional user setting, report field, or evidence tuning control. Retained identifiers keep the 1,024 UTF-8-byte cap and relevant name syntax limits.

## Startup clarification and governance

On 2026-09-29 the user approved requiring `container_started` to be explicitly true for future utilization eligibility. False, `ABSENT`, `INVALID`, and `UNAVAILABLE` must not establish startup eligibility. The domain preserves all five states; it does not calculate eligibility. See the amended [evidence contract](evidence-eligibility.md#required-behavior-by-condition) and Accepted [ADR 0007](adr/0007-explicit-container-started.md). Accepted ADRs 0001–0006 are unchanged.

The initial, unreleased `evidence-v1` specification retains its identifier with a dated amendment, recorded in the [consistency ledger](consistency-review.md#milestone-2-approved-clarifications). No prior implementation or emitted report exists to relabel; no claim is made that the original wording was identical. Future released policy changes require explicit version review.

## Tests and acceptance boundary

Synthetic unit cases exercise state distinctions; exact conversion and Decimal-context independence; malformed, exponent/length, type, and numeric bounds; name reuse; ownership consistency; startup uncertainty; independent metric resources; template uniqueness; immutability; and safe representations/errors. A static import check and isolated import with external/application dependencies blocked check the domain dependency boundary. No fixture directory is needed.

Run the existing [quality workflow](development.md#local-quality-checks). Milestone 2 was accepted on 2026-09-29 after these checks, package build, documentation links/consistency, unchanged toolchain/lock/ADRs 0001–0006, and user review. ADR 0007 was accepted on the same date. Runtime compatibility, real ownership, evidence gates, report safety, and UID teardown have not been integration-tested. Milestone 3 design is accepted; M3.1 and restricted kubeconfig document loading (M3.2A) are implemented; selection, authentication and all later behavior require separate authorization.
