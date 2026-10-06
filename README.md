# OpenKube Optimizer

OpenKube Optimizer is a planned open-source Kubernetes resource analysis tool. It will compare CPU and memory allocations with observed utilization and explain potential inefficiency and resource risks so engineers can make informed decisions.

**Status: v0.1 architecture frozen; Milestone 1 complete and committed; Milestone 2 complete and accepted on 2026-09-29.** D1–D3 are resolved and ADRs 0001–0008 are Accepted. The package now includes eleven immutable domain records and pure quantity conversion with synthetic unit tests. No Kubernetes access, analysis engine, CLI, or reporting exists. The approved compatibility selections are reference targets, not established OpenKube runtime support. [ADR 0008](docs/adr/0008-restricted-kubeconfig-and-bounded-transport.md) was accepted on 2026-09-30; M3 architecture/design and documentation consistency are complete. M3.1 provides dependencies and boundary tests; M3.2A loads restricted local kubeconfig documents, and M3.2B performs explicit selection and endpoint/authentication preflight without credential-file loading or connections. All later implementation, cluster work and Git publication require separate authorization.

> OBSERVE → ANALYZE → RECOMMEND → HUMAN DECIDES

OpenKube will be read-only. It will never automatically change workloads. Recommendations require human review and are not guarantees of safe resource reductions or infrastructure savings.

## Frozen v0.1 scope

- A local-only Python CLI for one explicitly selected cluster context per run, using the official Kubernetes client.
- Users must name every namespace to analyze; no automatic namespace discovery or namespace-list permission.
- Namespace-scoped discovery of Deployments, Pods, and containers; ReplicaSets provide ownership mapping.
- CPU/memory requests and limits, paired with recent Metrics API utilization.
- Explainable findings and investigation recommendations in terminal and JSON reports.
- Explicit handling of missing data, unsupported workloads, and incomplete analysis.

In-cluster execution, historical Prometheus analysis, numerical resizing recommendations, APIs, dashboards, and workload mutation are outside this release. Findings never establish production-safe resource values, monetary savings, reclaimable infrastructure capacity, or reliability improvements. See the [scope and architecture](docs/architecture.md) and [recommendation methodology](docs/recommendations.md).

## Read the architecture

| Document | Purpose |
| --- | --- |
| [Architecture](docs/architecture.md) | Scope, components, data flow, and review decisions |
| [Repository design](docs/repository-structure.md) | Planned Python modules and accepted dependency boundaries |
| [Domain model](docs/domain-model.md) | Implemented immutable facts, quantity conversion, invariants, and Milestone 2 limits |
| [Security model](docs/security.md) | Permissions, local authentication, and data handling |
| [Threat model](docs/threat-model.md) | Trust boundaries, threats, and planned verification |
| [Recommendation methodology](docs/recommendations.md) | Evidence, limitations, and measurable outcomes |
| [Evidence eligibility](docs/evidence-eligibility.md) | Startup, identity, lifecycle, coverage, and abstention contract |
| [Data and egress contract](docs/data-and-egress.md) | Exact projection/report allowlists, retention, and network boundaries |
| [CLI acceptance contract](docs/cli-contract.md) | Exit codes, partial success, schema versions, limits, and safe output |
| [Consistency review](docs/consistency-review.md) | Reconciled definitions, D1–D3 resolution, and architecture freeze |
| [Roadmap](docs/roadmap.md) | Incremental milestones and acceptance checks |
| [Reference targets](docs/compatibility.md) | Approved version/platform/authentication targets and actual validation limits |
| [ADRs](docs/adr/README.md) | Major decisions, alternatives, and trade-offs |

M3 will collect only Pods, Deployments and ReplicaSets; M4 adds PodMetrics. The initial runtime validation priority is Ubuntu 24.04 LTS x86_64 under the [documented resolved/procfs profile](docs/compatibility.md#initial-runtime-and-endpoint-profile). macOS remains a development environment. Disposable transport/credential probes establish feasibility only, not Kubernetes or managed-platform support.

## Local development

Use CPython 3.13.15 and uv. The [development guide](docs/development.md) explains environment setup, dependency locking, quality checks, and package validation. The package has exactly three direct runtime dependencies, `kubernetes==36.0.3`, `h11==0.16.0` and `PyYAML==6.0.3`, and no command-line entry point. Importing OpenKube does not import them or activate clients. See the [M3 boundary validation](docs/development.md#milestone-3-slice-1--dependencies-and-import-boundary) for transitive/import behavior. Development installation does not provide a working Kubernetes analyzer.

## Security and project maturity

Kubernetes Secrets, ConfigMaps, and application logs must never be requested. Transient full-object exposure in process memory is permitted only when technically required by the official client. Immediate allowlist projection reduces retention and exposure; it cannot guarantee that sensitive fields never temporarily enter memory. Raw objects must never reach persistence, logs, exceptions, or reports. Use a dedicated least-privilege identity; OpenKube cannot contain privileges already held by supplied credentials. [The security model](docs/security.md#data-minimization-and-its-limit) explains this boundary.

The accepted contract has ten configuration inputs, fixed versioned safety/evidence policies, and exits 0/2/3/4/5/130. Reports may include necessary allowlisted namespace, Deployment, Pod, and container names; names can contain sensitive organizational information, so reports are potentially sensitive artifacts. Kubernetes UIDs remain internal memory-only: never reported, logged, or persisted. No pseudonymization in v0.1. Architecture acceptance does not authorize implementation.

Do not contribute credentials, kubeconfigs, production manifests, real reports, or customer data. Use synthetic examples when needed; no fixture directory exists yet. A private vulnerability reporting channel, contribution guide, and release policy must be established before public release.

## License

Licensed under the [Apache License 2.0](LICENSE). Copyright 2026 Luis Assis.
