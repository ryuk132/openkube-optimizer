# Planned repository and Python modules

Status: **Accepted architecture plan — frozen on 2026-09-28; Milestone 1 complete and committed.** The authorized [Milestone 2 domain records and quantities](domain-model.md) are complete and accepted on 2026-09-29. Other application modules remain unimplemented. See [development](development.md), Accepted [ADR 0006](adr/0006-python-project-foundation.md), and the approved [reference targets](compatibility.md). Those targets do not establish runtime support. ADR 0008 was accepted on 2026-09-30; M3 architecture/design is complete. Slice 1 authorizes only the approved dependencies, inert collection package and boundary tests. Later application implementation, manifests and Git publication remain separately authorized.

## Current implementation

```text
openkube-optimizer/
├── .gitignore
├── .python-version
├── README.md
├── AGENTS.md
├── LICENSE
├── pyproject.toml
├── uv.lock
├── src/openkube_optimizer/
│   ├── __init__.py
│   ├── collection/
│   │   └── __init__.py
│   └── domain/
│       ├── __init__.py
│       ├── models.py
│       └── quantities.py
├── tests/unit/
│   ├── test_package.py
│   ├── test_domain_models.py
│   ├── test_import_boundaries.py
│   └── test_quantities.py
└── docs/                           # includes domain-model.md and Accepted ADRs 0007/0008
```

The local `.venv`, tool caches, and `dist/` are ignored. No fixtures directory or CLI entry point exists. Slice 1 adds only kubernetes==36.0.3 and h11==0.16.0 as direct runtime dependencies and a docstring-only collection initializer; future collection/projection/ownership modules are not created. Initializers have no I/O. Tests cover installed-package metadata and pure domain invariants/conversion. No collection, evidence evaluation, or reporting behavior exists.

## Future repository plan

The tree below includes later milestones; it is not authorization to create placeholders. Add each file or directory only when that milestone needs it.

```text
openkube-optimizer/
├── README.md
├── AGENTS.md                       # concise persistent contributor/agent boundaries
├── LICENSE                         # Apache-2.0, selected in Milestone 1
├── CONTRIBUTING.md
├── SECURITY.md                     # reporting policy with a real contact
├── CHANGELOG.md
├── pyproject.toml
├── uv.lock
├── src/openkube_optimizer/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── logging_config.py
│   ├── domain/
│   │   ├── models.py
│   │   └── quantities.py
│   ├── collection/
│   │   ├── kubernetes.py
│   │   ├── projection.py
│   │   └── ownership.py
│   ├── metrics/
│   │   ├── base.py
│   │   └── metrics_api.py
│   ├── analysis/
│   │   ├── quality.py
│   │   └── rules.py
│   ├── recommendations.py
│   ├── reporting.py
│   └── service.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/                   # only when needed; synthetic data only
├── docs/
│   ├── architecture.md
│   ├── repository-structure.md
│   ├── security.md
│   ├── threat-model.md
│   ├── recommendations.md
│   ├── evidence-eligibility.md
│   ├── data-and-egress.md
│   ├── cli-contract.md
│   ├── consistency-review.md
│   ├── roadmap.md
│   └── adr/
├── deploy/kubernetes/              # future v0.1: operator-applied namespace RBAC examples only
├── dev/                            # later: reproducible disposable cluster
└── .github/workflows/              # later: validation and release automation
```

## Module responsibilities

| Module | Responsibility |
| --- | --- |
| `__init__.py` | Package initializer; no network or collection side effects |
| `cli.py` | Required local context/namespaces, report mode/output, fixed exit/status contract |
| `config.py` | Ten-field accepted configuration contract, validated thresholds/scope, fixed versioned policy constants under D1; no configuration framework/fallback/discovery |
| `logging_config.py` | Structured operational events; exclude bodies, credentials, and arbitrary metadata |
| `domain/models.py` | Milestone 2: eleven closed immutable identity/inventory/metric fact records, field states, and fixed version identifiers. Evidence results, findings, recommendations, and run summaries remain deferred until their producing milestones. AnalysisSettings is explicitly outside Milestone 2. |
| `domain/quantities.py` | Implemented bounded pure conversion: exact Decimal CPU, integer memory with upward fractional-byte normalization; no float or SDK dependency |
| `collection/kubernetes.py` | M3: three fixed namespaced inventory endpoints (Pods, Deployments, ReplicaSets); generated SDK dispatch behind controlled bounded transport, pagination, sanitized errors and prompt raw-reference release |
| `collection/projection.py` | Strict wire validation and exact data-contract allowlist; unprojectable mandatory structure invalidates namespace pass, representable uncertainty preserved; no raw API objects beyond adapter |
| `collection/ownership.py` | UID-based owner traversal with explicit unresolved outcomes |
| `metrics/base.py` | Small typed provider protocol returning samples and source limitations |
| `metrics/metrics_api.py` | M4: PodMetrics reads/normalization through shared controlled transport; no direct kubelet access |
| `analysis/quality.py` | Versioned evidence contract: identity, lifecycle, windows, coverage, duration, and abstention |
| `analysis/rules.py` | Deterministic functions from evidence to findings, without I/O |
| `recommendations.py` | Map findings to explanations, caveats, and human review actions |
| `reporting.py` | Separate UID-free report projection/allowlist, versioned JSON schema, escaped names in terminal output, safe file publication |
| `service.py` | Compose one local bounded run, inventory brackets, scheduled slots, partial status, deadlines, and measurements |

Accepted [ADR 0008](adr/0008-restricted-kubeconfig-and-bounded-transport.md) defines the adapter boundaries, not new placeholder modules: Ubuntu resolved/procfs transport; stable trusted credential loading; setup/native cancellation exception; bounded wire handling before projection. Its kubernetes==36.0.3 and h11==0.16.0 dependencies are now installed/locked under slice 1 authorization, without adapter implementation. macOS remains development-only; neither probes nor this plan establish runtime support. Choose concrete files only with authorized implementation. New defensive guards add no configuration or report fields.

The CLI depends on the coordinator; adapters and rules depend on the domain. Domain and analysis modules must not import the Kubernetes client, the CLI, or reporting code. Add abstractions at actual external boundaries, not a generic repository framework or plugin loader.

Use type hints throughout. Unit tests cover quantities, ownership, quality gates, and rules. Integration tests cover the real API contract, permissions, and an end-to-end report in a disposable cluster. Network access is not needed for unit tests.

There is no in-cluster loader, collector Job/image, namespace-discovery adapter, generic plugin loader, upstream projection service, or pseudonymization mechanism in v0.1. The future RBAC examples are operator provisioning inputs, never applied by the CLI. Foundation authorization does not authorize application modules or later milestones.

## Internal and output data contracts

| Record | Essential fields |
| --- | --- |
| Internal container allocation | Namespace, Deployment/ReplicaSet/Pod UIDs and names, container name, Pod creation time, lifecycle eligibility, requests/limits, source and allocation fingerprint; UIDs are memory-only, never serialized/logged/persisted |
| Usage sample | Source, namespace/Pod/container identity, observed timestamp, measurement window, CPU cores, memory bytes, quality flags |
| Finding | Rule ID/version, subject, resource, evidence, threshold, severity, limitations |
| Recommendation | Finding reference, investigation action, confidence and reason, human-review requirement; target value absent in v0.1 |
| Run report | Exact closed UID-free root/nested records; necessary namespace/Deployment/Pod/container names, evidence timestamps, source status/coverage, findings/actions/skips, versions/thresholds; potentially sensitive names, no prohibited object content |

Absent request, zero request, absent metric, unsupported allocation, and collection failure are distinct states. Serialize units explicitly. Avoid raw SDK objects, arbitrary labels, and free-form Kubernetes status messages in all domain records.

This table is a conceptual summary, not permission to add fields. The [data contract](data-and-egress.md) defines the exact internal/output allowlists; the [CLI contract](cli-contract.md) defines schema compatibility, exit codes, and operational limits; the [evidence contract](evidence-eligibility.md) defines sample eligibility. Keep those contracts authoritative rather than duplicating field lists in modules.
