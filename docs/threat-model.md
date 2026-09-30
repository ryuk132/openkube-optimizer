# Initial threat model

Status: **Accepted architecture threat model — frozen on 2026-09-28; mitigations remain unimplemented.** v0.1 is local CLI only with explicit namespaces. Accepted [ADR 0008](adr/0008-restricted-kubeconfig-and-bounded-transport.md) amends the resolver/credential/setup boundary on 2026-09-30. M3 design is complete; dependency/package-boundary slice 1 is implemented, while runtime I/O controls remain unimplemented and separately authorized. Validate controls before collection acceptance.

## Assets and boundaries

Protect cluster integrity, authentication material, workload metadata, report accuracy, and API availability. The operator's host, credential configuration, API server, and selected metrics provider are trust dependencies. Workload authors can control portions of returned metadata; authenticated API data is still untrusted input.

1. **Operator → CLI:** configuration and kubeconfig cross into the process.
2. **Cluster APIs → adapters:** full workload objects and metrics enter memory over authenticated TLS.
3. **Adapters → domain engine:** only validated, allowlisted records may cross this boundary.
4. **Engine → local report:** infrastructure identity and recommendations become shareable artifacts.
5. **Dependencies → local runtime identity:** compromised code can exercise the supplied identity's permissions and the local user's host access.
6. **Client configuration → resolved/DNS:** the initial Ubuntu profile uses trusted Varlink resolution. Helpers/proxies are excluded initially and require future review.
7. **Report → operator-controlled storage/capture:** shell redirection, synchronization, backup, and sharing can move artifacts off-host.

The data-minimization boundary is within the process, not isolation against a compromised collector. Unavoidable transient full-object exposure is permitted by the user; raw-object persistence, logging, exposed exceptions, and reporting remain prohibited. Reference release does not guarantee memory zeroization. See the [security model](security.md#data-minimization-and-its-limit) and [exact data/egress contract](data-and-egress.md).

## Threats and planned verification

| Threat | Required mitigation | Residual risk / planned check |
| --- | --- | --- |
| Collector compromise changes workloads | Dedicated list-only RBAC; no write methods in adapters | Broad local credentials bypass containment; integration checks deny writes and sensitive reads |
| Credentials leak through objects, exceptions, or debug logs | Immediate exact projection, prompt raw-reference release, sanitized error codes, SDK debug disabled | Unavoidable full objects still enter memory; canaries must never reach domain records, reports, logs, exposed exceptions, or persistent artifacts |
| Malicious kubeconfig executes commands | Trusted operator-managed kubeconfig only | Host trust remains required; reject untrusted configuration workflows |
| Metadata injects terminal controls or corrupts output | Validate fields, escape output, structured JSON | Test hostile synthetic strings in reports and errors |
| Large/slow API exhausts resources | Bounded controlled wire/decoded input, retained-data limits, DNS-through-HTTP deadline and explicit retries | Test chunked/compressed/slow streams, pagination and incomplete status; new guards are implementation policy, not report/configuration fields or a hard RSS guarantee |
| Native local setup stalls or expands parsing cost | Trusted regular stable inputs, size/format/parser guards, deadline checks before/after setup, cleanup | No hard mid-call file/OpenSSL parser cancellation; total elapsed includes setup without reset; a Python timer is not native cancellation |
| Credential path replacement or in-place mutation | CA bounded snapshot; retained cert/key descriptors and `/proc/self/fd` native loading; stable-file assumption | Identity pinning does not freeze contents; concurrent in-place mutation and guaranteed zeroization are outside protection; test overflow, cleanup and rejecting password callback |
| Resolver semantic substitution or local socket replacement | Trusted socket/peer checks; explicit multi-label absolute endpoint; controlled Varlink and bounded fallback | No search-suffix/single-label/custom NSS fallback or broad NSS equivalence; private answers allowed, original host remains TLS/SNI/HTTP authority; compromised resolver not contained |
| SDK coercion/error bodies escape projection | Intercept generated dispatch before stock REST/errors/deserialization; strict wire validation and immediate allowlist projection | Test body/UID canaries and raw-reference lifetime; mandatory structure failure invalidates namespace pass, representable uncertainty remains distinct |
| Wrong Pod or stale metrics cause harmful advice | UID ownership, bracketed inventory, full CPU-window/lifecycle gates | Test every condition in the evidence contract, including startup, late creation, restarts, rollouts, allocation changes, duplicates, shortened runs, and ambiguity; reads remain non-transactional |
| Short observations imply false certainty | Investigation candidates only; evidence and limitations included | Human may over-trust findings; test mandatory caveats and absence of resize targets |
| Metrics source compromised or incomplete | Validate values and provenance, report coverage | Cannot prove source truth; no automatic action even with apparently valid data |
| Reports reveal organizational identifiers | Closed name allowlist, explicit scope, restricted output permissions, potentially sensitive artifact warning | D3 permits necessary names; they may be sensitive and reports are not anonymous. No pseudonymization in v0.1 |
| Internal UIDs leak through serialization or IDs | Memory-only UID correlation; separate report projection; never log/persist UIDs or encode them into finding IDs | Test UID canaries in terminal/JSON, logs, exceptions, temporary/saved files; test name reuse and reference release on every termination path |
| Output path redirects or overwrites data | No symlink following/overwrite; exclusive restrictive temporary report and atomic no-replace publication | Test races, nonregular files, cleanup, broken pipes, and interrupted writes; stdout capture is outside file protections |
| Implicit namespace/authentication broadens access | Required namespaces/context; no discovery, in-cluster loader, or scope expansion | Test no Namespace/list-all calls or fallback on failure; broad supplied credentials remain broader |
| Helpers/proxies/key logging create unexpected egress or persistence | Reject excluded selected settings; disable inherited proxy/debug/keylog behavior; no credential copies | Future authentication integrations require separate review; initial keys use a rejecting callback, never passwords/environment/prompts/helper fallback |
| Inherited insecure TLS exposes credentials | Reject HTTP API URLs and disabled certificate/hostname verification | Test kubeconfig and effective client transport, including operator proxies |
| Threshold changes imply stronger claims | Versioned rules, explicit effective thresholds, fixed minimum evidence floor | Test configured boundaries and ensure shortened runs cannot enable overprovisioning candidates |
| Timing/count ambiguity exaggerates evidence | One baseline/slot/closure timeline, per-resource counts, explicit gap and source-time checks | Validate 27-of-30 and 54-of-60 examples, late brackets, boundary gaps, conflicting duplicates, and coverage without findings |
| Failure is mislabeled successful | Closed statuses, 401 versus 403 distinction, delivery status separate from analysis | Validate empty/unsupported scope, partial API failures, evidence abstention, and approved D2 exit precedence |
| Dependency supply-chain compromise | Locking, review, scans, SBOM, least privilege and minimal CI permissions | Scans do not prove safety; release checks document unresolved findings; collector image is deferred |

M3 grants only inventory access to Pods, Deployments and ReplicaSets; M4 adds PodMetrics. Runtime validation prioritizes Ubuntu 24.04 LTS x86_64 under the [resolved/procfs profile](compatibility.md#initial-runtime-and-endpoint-profile); macOS is development-only. Feasibility probes do not establish implementation or Kubernetes/managed-platform support. On deadline the implementation must release owned controllable resources and leave no OpenKube-owned resolver worker/task/process behind; instantaneous daemon/shared-work cancellation is not promised.

Out of scope for v0.1: defending a compromised operator host or control plane, tenant isolation inside the collector, and verifying application performance guarantees. This includes malicious root and compromised trusted filesystems/resolvers. Concurrent in-place credential mutation, guaranteed memory zeroization and native setup preemption are explicitly not guaranteed. These limits do not justify collecting additional sensitive data.
