# Architecture decision records

ADRs **0001–0005 are Accepted on 2026-09-28**, following explicit user approval of D1–D3 and the final architecture review. OpenKube v0.1 architecture is frozen. Acceptance records architecture decisions, not implemented guarantees or authorization to start Milestone 1. Future major changes require a new Proposed ADR and explicit review; supersede accepted decisions rather than erase their history.

| ADR | Decision | Status | Accepted |
| --- | --- | --- | --- |
| [0001](0001-read-only-cli.md) | Local-only read-only CLI, explicit context/namespaces, no discovery or in-cluster fallback | Accepted | 2026-09-28 |
| [0002](0002-metrics-and-evidence.md) | Recent metrics, configurable heuristic ratios, fixed versioned evidence gates, conservative findings | Accepted | 2026-09-28 |
| [0003](0003-access-and-data-boundary.md) | Four namespaced list permissions, transient raw-object boundary, necessary names in sensitive reports, UIDs memory-only | Accepted | 2026-09-28 |
| [0004](0004-identity-and-domain-model.md) | Typed records, internal UID ownership, lifecycle/allocation evidence, UID-free reports | Accepted | 2026-09-28 |
| [0005](0005-cli-and-report-contract.md) | Ten inputs, fixed versioned policy, six exits, bounded runs, versioned safe reports | Accepted | 2026-09-28 |
| [0006](0006-python-project-foundation.md) | Python 3.13.15, uv/src packaging, minimal quality tools, Apache-2.0 | Accepted | 2026-09-28 |
| [0007](0007-explicit-container-started.md) | Explicit container_started=True for utilization; preserve uncertain states | Accepted | 2026-09-29 |
| [0008](0008-restricted-kubeconfig-and-bounded-transport.md) | Restricted kubeconfig loading, strict wire projection, and bounded Ubuntu transport | Accepted | 2026-09-30 |

ADR 0008 was accepted on 2026-09-30 after transport and credential-loading feasibility review. D1–D6, the trusted stable-file/setup boundary, kubernetes==36.0.3 implementation intent, h11==0.16.0 selection and unchanged closed report schema are resolved. Its separately authorized documentation consistency pass is complete. Architecture/design for Milestone 3 is complete; implementation, dependency addition and cluster work require separate authorization. Disposable Ubuntu probes establish limited feasibility evidence, not implemented runtime support or Kubernetes/platform compatibility.

The [consistency review](../consistency-review.md#resolved-decisions-and-acceptance) records the original D1/D2 approval and D3 policy: necessary names allowed, UIDs never reported/logged/persisted, no pseudonymization in v0.1. Milestone 1 is complete and committed; Milestone 2 records/quantities were accepted on 2026-09-29. ADR 0007 records the startup tightening accepted that day. ADRs 0001/0003/0004/0005 retain their original text with dated ADR 0008 cross-references appended; ADRs 0002/0006/0007 are unchanged. The ledger's dated M3 amendment distinguishes the later D1–D6 decisions. No runtime compatibility is established. Do not stage, commit, push, or implement Milestone 3 without authorization.

Future ADRs should cover in-cluster execution (identity, token handling, packaging, hardening, egress, output retention); any namespace-discovery scope increase; Prometheus authentication/query scope/retention; statistical sizing and confidence calibration; HPA/VPA interactions; supported Kubernetes versions/platforms and packaging; API/dashboard authentication and tenancy; persistent storage; or privacy-enhanced/pseudonymized reports if a real use case requires them. Report compatibility is accepted in ADR 0005. Workload mutation is prohibited by the current principle and would require a separate product/security review.
