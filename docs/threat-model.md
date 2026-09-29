# Initial threat model

Status: **Accepted architecture threat model — frozen on 2026-09-28; mitigations remain unimplemented.** v0.1 is local CLI only with explicit namespaces. Validate controls before collection acceptance; revisit architectural changes through review.

## Assets and boundaries

Protect cluster integrity, authentication material, workload metadata, report accuracy, and API availability. The operator's host, credential configuration, API server, and selected metrics provider are trust dependencies. Workload authors can control portions of returned metadata; authenticated API data is still untrusted input.

1. **Operator → CLI:** configuration and kubeconfig cross into the process.
2. **Cluster APIs → adapters:** full workload objects and metrics enter memory over authenticated TLS.
3. **Adapters → domain engine:** only validated, allowlisted records may cross this boundary.
4. **Engine → local report:** infrastructure identity and recommendations become shareable artifacts.
5. **Dependencies → local runtime identity:** compromised code can exercise the supplied identity's permissions and the local user's host access.
6. **Client configuration → helpers/DNS/proxies:** authentication and transport can cross additional network boundaries.
7. **Report → operator-controlled storage/capture:** shell redirection, synchronization, backup, and sharing can move artifacts off-host.

The data-minimization boundary is within the process, not isolation against a compromised collector. Unavoidable transient full-object exposure is permitted by the user; raw-object persistence, logging, exposed exceptions, and reporting remain prohibited. Reference release does not guarantee memory zeroization. See the [security model](security.md#data-minimization-and-its-limit) and [exact data/egress contract](data-and-egress.md).

## Threats and planned verification

| Threat | Required mitigation | Residual risk / planned check |
| --- | --- | --- |
| Collector compromise changes workloads | Dedicated list-only RBAC; no write methods in adapters | Broad local credentials bypass containment; integration checks deny writes and sensitive reads |
| Credentials leak through objects, exceptions, or debug logs | Immediate exact projection, prompt raw-reference release, sanitized error codes, SDK debug disabled | Unavoidable full objects still enter memory; canaries must never reach domain records, reports, logs, exposed exceptions, or persistent artifacts |
| Malicious kubeconfig executes commands | Trusted operator-managed kubeconfig only | Host trust remains required; reject untrusted configuration workflows |
| Metadata injects terminal controls or corrupts output | Validate fields, escape output, structured JSON | Test hostile synthetic strings in reports and errors |
| Large/slow API or helper exhausts resources | Pre-deserialization response caps, retained-data limits, absolute deadlines, bounded retries/helper execution | Test compressed/chunked bodies, slow streams, pagination, helper cancellation, and explicit incomplete status; no hard RSS guarantee |
| Wrong Pod or stale metrics cause harmful advice | UID ownership, bracketed inventory, full CPU-window/lifecycle gates | Test every condition in the evidence contract, including startup, late creation, restarts, rollouts, allocation changes, duplicates, shortened runs, and ambiguity; reads remain non-transactional |
| Short observations imply false certainty | Investigation candidates only; evidence and limitations included | Human may over-trust findings; test mandatory caveats and absence of resize targets |
| Metrics source compromised or incomplete | Validate values and provenance, report coverage | Cannot prove source truth; no automatic action even with apparently valid data |
| Reports reveal organizational identifiers | Closed name allowlist, explicit scope, restricted output permissions, potentially sensitive artifact warning | D3 permits necessary names; they may be sensitive and reports are not anonymous. No pseudonymization in v0.1 |
| Internal UIDs leak through serialization or IDs | Memory-only UID correlation; separate report projection; never log/persist UIDs or encode them into finding IDs | Test UID canaries in terminal/JSON, logs, exceptions, temporary/saved files; test name reuse and reference release on every termination path |
| Output path redirects or overwrites data | No symlink following/overwrite; exclusive restrictive temporary report and atomic no-replace publication | Test races, nonregular files, cleanup, broken pipes, and interrupted writes; stdout capture is outside file protections |
| Implicit namespace/authentication broadens access | Required namespaces/context; no discovery, in-cluster loader, or scope expansion | Test no Namespace/list-all calls or fallback on failure; broad supplied credentials remain broader |
| Helpers/proxies create unexpected egress or caches | Trusted configuration only, explicit indirect-egress disclosure, disable client kubeconfig persistence | Validate supported client inheritance/refresh behavior; no OpenKube telemetry does not constrain trusted external tools |
| Inherited insecure TLS exposes credentials | Reject HTTP API URLs and disabled certificate/hostname verification | Test kubeconfig and effective client transport, including operator proxies |
| Threshold changes imply stronger claims | Versioned rules, explicit effective thresholds, fixed minimum evidence floor | Test configured boundaries and ensure shortened runs cannot enable overprovisioning candidates |
| Timing/count ambiguity exaggerates evidence | One baseline/slot/closure timeline, per-resource counts, explicit gap and source-time checks | Validate 27-of-30 and 54-of-60 examples, late brackets, boundary gaps, conflicting duplicates, and coverage without findings |
| Failure is mislabeled successful | Closed statuses, 401 versus 403 distinction, delivery status separate from analysis | Validate empty/unsupported scope, partial API failures, evidence abstention, and approved D2 exit precedence |
| Dependency supply-chain compromise | Locking, review, scans, SBOM, least privilege and minimal CI permissions | Scans do not prove safety; release checks document unresolved findings; collector image is deferred |

Out of scope for v0.1: defending a compromised operator host or control plane, tenant isolation inside the collector, and verifying application performance guarantees. These limits do not justify collecting additional sensitive data.
