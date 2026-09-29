# v0.1 security model

Status: **Accepted architecture requirements — frozen on 2026-09-28, not implemented guarantees.** Read-only operation is mandatory, but read access still has confidentiality and availability risks.

## Permissions

The local-only collector uses namespace-scoped list operations. The operator must explicitly name every namespace. No automatic namespace discovery, all-namespaces endpoints, `get`, or `watch` in v0.1. HTTP GET on a collection is authorized as Kubernetes verb `list`.

| API group | Resource | Verbs | Scope and reason |
| --- | --- | --- | --- |
| Core (`""`) | `pods` | `list` | Selected namespaces: observed allocations, lifecycle and ownership |
| `apps` | `deployments` | `list` | Selected namespaces: workload identity and template allocations |
| `apps` | `replicasets` | `list` | Selected namespaces: Pod-to-Deployment owner chain |
| `metrics.k8s.io` | `pods` | `list` | Selected namespaces: recent per-container utilization |

Recommend a dedicated least-privilege analysis identity in a trusted local kubeconfig. A namespace Role with these four rules and a RoleBinding in each allowed namespace is sufficient. Operators may reuse an identically narrow ClusterRole through namespace RoleBindings, but must not use a ClusterRoleBinding for analysis. A separately provisioned ServiceAccount identity can be used from the local CLI; it does not imply an in-cluster runtime or authorize OpenKube to create tokens. See [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).

Namespace objects must never be listed. Report scope as operator-supplied, not globally discovered. Do not add wildcard resources, non-resource URL grants, or permission self-review calls. Use fixed, tested API endpoints; unexpected client discovery needs require review, not automatic extra permissions.

No permissions for Secrets, ConfigMaps, nodes, events, Pod logs, exec, attach, port-forward, proxy, RBAC resources, impersonation, or token creation. No create/update/patch/delete verbs, including on status or scale subresources. Do not use the built-in broad `view` role. Kubernetes privileges are additive: an omitted permission is not an explicit deny, so operators must check other bindings too. [RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) support narrowly scoped grants.

The operator provisions identities and RBAC separately; OpenKube never administers either. No collector Job, container runtime, projected-token setup, or deployment manifests are part of the v0.1 application. OpenKube cannot protect the user from supplying credentials that already possess broader permissions; recommend a dedicated identity and verify effective access outside the collector.

## Data minimization and its limit

The user permits transient receipt/deserialization of full allowed-resource API objects **only when technically required by the official Kubernetes client**. Responses can include literal environment secrets or sensitive annotations. This resolves the earlier interpretation question; it does not authorize retention of those values.

Immediately project each retrieved response/page into the [exact field allowlist](data-and-egress.md#exact-projection-allowlist). Release raw references as soon as technically possible; do not retain SDK objects in domain records, caches, callbacks, traceback frames, or error records. Raw objects must never be persisted, logged, included in exposed exceptions, or written to reports. Client exceptions must be converted at the adapter boundary to fixed sanitized codes without formatting raw bodies, headers, object representations, or exception chains.

The [data and egress contract](data-and-egress.md) separately defines permitted internal records, report fields, authentication-only material, and prohibited data. No deliberate extraction of labels, annotations, environment variables, commands, credentials, volume contents, application content, or free-form status text. Secrets, ConfigMaps, and application logs must never be requested. Use synthetic fixtures only; no raw object serialization, debug HTTP traces, or process-state dumps.

Projection reduces retention and exposure but cannot guarantee sensitive fields never temporarily exist in process memory. It is not an isolation boundary against compromised code. Reference release is not secure memory erasure; host swap/crash capture remain residual risks. Resource names may contain personal/customer identifiers even when syntactically valid. Operators must choose suitable scope and protect reports; arbitrary clusters cannot be promised PII-free output.

D3 is approved: only necessary allowlisted namespace, Deployment, Pod, and container names may identify report subjects. These names can contain sensitive organizational information, so reports are potentially sensitive artifacts. Kubernetes UIDs are permitted solely for internal memory-only identity/ownership analysis; never log, report, persist, hash into report identifiers, or retain them beyond the necessary analysis lifetime. Report projection removes UID fields before any serialization or temporary-file write. Credentials, raw objects, labels, annotations, and application data remain prohibited. No pseudonymization in v0.1; a demonstrated privacy use case requires a future ADR. See the [resolved decisions](consistency-review.md#resolved-decisions-and-acceptance).

## Authentication and network boundaries

The v0.1 contract requires an explicit local context from one trusted kubeconfig file, explicitly selected or defaulting to `~/.kube/config`; no `KUBECONFIG` merging or implicit context. The accepted input surface is closed in the [CLI contract](cli-contract.md#complete-configuration-surface). The [approved reference-target contract](compatibility.md#planned-authentication-profile) selects externally supplied bearer tokens and existing file-based client certificate/key credentials for future validation, with explicit CA files and verified HTTPS. No authentication mechanism or platform has established OpenKube runtime support. Helpers, embedded certificate data, proxies, and the other listed workflows are outside the initial profile; reject them before loading credentials or invoking client behavior. These exclusions are not claims that the corresponding cloud providers or clusters are incompatible. Kubeconfigs may invoke credential helpers; treat them as trusted executable configuration, not uploadable input. Kubernetes warns that [untrusted kubeconfigs can execute code or expose files](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/). Do not embed kubeconfigs in reports. A local admin credential defeats RBAC containment even if the application uses only read calls; integration tests must use a restricted identity.

No in-cluster loader or fallback, automatic context switching, credential/token creation, or implicit client kubeconfig persistence. Authentication data stays transport-only. Credential helpers may contact other services or maintain their own caches; test their timeout/cancellation behavior and document supported modes. In-cluster execution requires a separate future ADR covering identity, token projection, runtime hardening, egress, and output retention.

Verify TLS certificates and hostnames; reject plain-HTTP API endpoints and insecure-skip-verification settings inherited from kubeconfig as well as any attempted CLI override. Use only the selected API endpoint and tested client authentication; no arbitrary URL fetches or direct node/kubelet access. The [egress contract](data-and-egress.md#expected-network-communication) distinguishes API requests from DNS, credential helpers, transport proxies, and operator-controlled output capture. No telemetry or analytics. A configured HTTP transport proxy is not authorization to use Kubernetes proxy functionality.

## Local runtime, outputs, and supply chain

Run as an ordinary local user; no privileged host access is required. The host and its credential helpers remain trust dependencies. Container hardening and NetworkPolicy are deferred with in-cluster execution, not described as v0.1 protections.

Validate API fields, metric quantities, timestamps, namespace inputs, configuration, and output paths. Enforce the [concrete operational bounds](cli-contract.md#operational-limits-and-timeouts), including transport-size checks before SDK deserialization, absolute deadlines, helper timeouts, and retained-data limits. Reject malformed data with sanitized codes. Disable SDK body/header debug logging. Operational logs contain safe event codes, counts, and timings; object names belong only in reports. Escape terminal controls and use a JSON serializer. Test exclusion from domain records, reports, logs, and exposed exceptions with canary secrets.

Reports expose infrastructure topology even after minimization. The [output contract](cli-contract.md#safe-output-file-behavior) requires a new regular-file destination, no symlink following/overwrite, `0600` permissions, bounded serialization, and atomic no-replace publication. A temporary file may contain only the requested allowlisted report. Stdout redirection, backups, and synchronized directories are operator-controlled and may move output off-host. No report-upload feature exists in v0.1.

Implementation acceptance must inject synthetic UID canaries as well as credential canaries and verify absence from both output formats, logs, exposed errors, temporary/saved files, and finding IDs. Test internal name reuse/ownership correlation still works, and discard UID references after required analysis or failed/interrupted teardown. Memory reference release does not guarantee physical erasure or protection against OS swap/host capture; OpenKube itself must never write UID-bearing artifacts.

During implementation, pin direct and transitive dependencies reproducibly and review updates. Before v0.1 release, add dependency scanning, secret checks, an SBOM, and minimal CI permissions. Scan/pin disposable test-environment images where used; shipping a collector image is deferred. Establish a real private vulnerability-reporting route before publishing `SECURITY.md`; do not invent a contact or response SLA.
