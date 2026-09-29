# Initial reference targets and validation status

Status: **Approved Milestone 1 reference contract — 2026-09-28.** These selections are initial reference targets or planned validation targets, not established OpenKube runtime support. No Kubernetes application, authentication, metrics, or report-filesystem integration has been validated. Runtime dependencies remain empty.

## Terminology and evidence

| Term | Meaning |
| --- | --- |
| Initial reference / planned validation target | A user-approved combination selected for future implementation and validation; not a support guarantee |
| Documented upstream compatibility | An upstream project's version mapping or capability statement; not an OpenKube test result |
| Locally tested compatibility | A specific combination and scope that passed recorded OpenKube checks; currently foundation and pure domain units only, not Kubernetes runtime integration |
| Not yet validated | Required OpenKube application, authentication, filesystem, or integration checks have not passed or have not run |

Use these terms in release and development documentation. Do not describe a selected target as a fully supported runtime environment. A portable wheel, a dependency's Python classifier, or a working kubectl session does not establish OpenKube runtime compatibility.

## Approved reference matrix

| Component | Initial reference / planned validation target | Current OpenKube evidence |
| --- | --- | --- |
| Kubernetes | Minor 1.36; initial reference patch **1.36.4** | Not yet validated; no cluster accessed |
| Official Kubernetes Python client | **36.0.3** | Not installed; no SDK integration tested |
| CPython | **3.13.15** | Foundation and pure domain unit checks pass; Kubernetes runtime not tested |
| Metrics Server | **0.9.0** | Not yet validated; operator-managed reference implementation |
| Metrics API | **metrics.k8s.io/v1beta1** | Not yet validated; fixed namespaced PodMetrics endpoint planned |
| Development reference | **macOS 15 / x86_64** | Foundation checks passed on Darwin 24.6.0 / x86_64; host reported macOS 15.7.9 during review; no application-runtime claim |
| Planned platform validation | **Ubuntu 24.04 LTS / x86_64** | No local validation yet |
| Planned report-filesystem validation | Local APFS on the macOS reference; local ext4 on the Ubuntu target | Safe report publication, permissions, races, and cleanup not yet tested |

Keep one Kubernetes minor and the exact initial reference versions above. Review patch changes and record the exact combinations actually tested. Do not claim other patches, Kubernetes minors, distributions, or cloud providers have been validated. The initial cluster reference uses Linux nodes; Windows-node and mixed-OS clusters have not been validated.

Do not add ARM64, Windows, WSL, other Linux distributions, network filesystems, or containerized OpenKube execution to this matrix. A future disposable test cluster is operator infrastructure, not permission to run OpenKube in a container or in-cluster.

This documentation does not add a version-selection input or API discovery permission. Operators and test records identify cluster versions; OpenKube remains limited to the four approved namespace-scoped list endpoints. Required field visibility, allocation/resize semantics, and unsupported-state abstention must be verified against the selected SDK before collection acceptance.

## Planned authentication profile

Use one explicit context from one trusted kubeconfig, following the existing path/default contract. Exactly one unambiguous mechanism in the selected context is a planned validation target:

1. `user.token` containing an externally obtained bearer token.
2. Existing file-based `user.client-certificate` and `user.client-key` credentials, without encrypted-key prompts.

Both require an explicit `certificate-authority` file, HTTPS, and hostname verification. No implicit trust-store fallback or authentication fallback is allowed. Credential provisioning and sufficient validity for the intended run are the operator's responsibility. OpenKube must not acquire/refresh tokens, rewrite kubeconfig, or create credential files. An externally provisioned ServiceAccount bearer token may be used locally; that is not in-cluster execution or token-creation authority.

The following are outside the initial profile and must not be silently invoked or selected:

- Exec credential plugins and cloud-provider authentication helpers.
- Legacy `auth-provider` blocks and automatic OIDC/cloud refresh.
- Browser authentication, MFA or other interactive authentication during analysis, and encrypted-key prompts.
- `tokenFile` workflows, including rotation; only the explicit `user.token` form is in the initial bearer-token target.
- Embedded CA, client-certificate, and client-key data.
- Transport proxies, custom TLS server-name overrides, and implicit trust-store fallback.
- Basic authentication and anonymous authentication.
- Impersonation, in-cluster fallback, token creation, and insecure TLS, which also remain prohibited by the frozen architecture.

These exclusions do not establish that any corresponding cluster or cloud provider is incompatible. They identify workflows OpenKube v0.1 has not validated; architecture-prohibited behavior additionally requires a separately reviewed scope change. No authentication workflow is currently an established OpenKube runtime capability.

During future implementation, reject unsupported selected-context settings before client credential loading, helper invocation, or network requests; use the existing configuration-error contract. Never silently ignore an excluded setting or select another mechanism. Runtime authentication failures retain the frozen failed/3 behavior, without credential fallback. Validate effective proxy/TLS behavior, not only kubeconfig text.

The reviewed Python client can materialize embedded certificate/key data in temporary files; disabling kubeconfig persistence alone does not prevent this. Its exec implementation can wait without an explicit subprocess timeout and expose helper stderr. These are reasons for the restricted profile, not implemented OpenKube safeguards. Expanding the profile requires reviewed evidence for deadline/cancellation, TLS, refresh, sanitization, and persistence behavior; permitting credential files created by the client would require explicit review of the persistence boundary.

## Metrics reference and evidence requirements

The initial metrics reference is Metrics Server 0.9.0 serving `metrics.k8s.io/v1beta1`. Plan to list only `/apis/metrics.k8s.io/v1beta1/namespaces/{namespace}/pods` through the selected Kubernetes API server. Do not access kubelets/nodes directly, query APIService objects, discover namespaces, or grant Metrics Server's own permissions to the OpenKube identity.

The operator must provide a working aggregation layer, the Metrics API service, valid certificate trust, kubelet authentication/authorization, and the necessary cluster networking. TLS verification remains enabled; disabling kubelet certificate validation is not the reference configuration. OpenKube does not install or configure Metrics Server.

CPU describes average usage over the reported window; memory is a timestamped working-set estimate. Metrics Server's collection cadence is not OpenKube's polling interval and does not guarantee fresh data at each poll. **Repeated Metrics API responses must not count as distinct observations merely because OpenKube polled again.** Deduplication, conflicting duplicates, timestamps/windows, coverage, startup, gaps, shortened runs, and abstention remain governed by [evidence-v1](evidence-eligibility.md), including its explicitly approved 2026-09-29 startup clarification. Local domain unit tests do not validate Metrics API or SDK integration.

Preserve missing-metrics/partial-failure behavior from the [CLI contract](cli-contract.md#exit-codes-and-report-status): retain independently valid inventory/configuration findings, never substitute zero usage, and mark required unavailable utilization evidence incomplete. Empty or known inapplicable inventories retain their existing exceptions. No history, safe resize values, or accurate monitoring guarantee is introduced. Other metrics providers and API versions remain outside the initial reference matrix.

## Upstream evidence and later acceptance

Research reviewed for the approved 2026-09-28 reference selection:

- [Kubernetes releases](https://kubernetes.io/releases/) lists the 1.36 branch and 1.36.4 patch. This establishes release availability, not OpenKube compatibility.
- The [official Python client matrix](https://github.com/kubernetes-client/python#compatibility) maps 36.x to Kubernetes 1.36; [36.0.3](https://github.com/kubernetes-client/python/releases/tag/v36.0.3) is a stable client release. Its [package metadata](https://github.com/kubernetes-client/python/blob/v36.0.3/setup.py) includes Python 3.13; SDK integration here is still untested.
- The [versioned Metrics Server matrix](https://github.com/kubernetes-sigs/metrics-server/blob/v0.9.0/README.md#compatibility-matrix) associates 0.9.x with `metrics.k8s.io/v1beta1` and Kubernetes 1.34+. See [Kubernetes 1.36 metrics semantics](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/resource-metrics-pipeline/) for CPU windows and memory working sets.
- The [kubeconfig specification](https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/) defines the credential/TLS fields. The reviewed [client kubeconfig loader](https://github.com/kubernetes-client/python/blob/v36.0.3/kubernetes/base/config/kube_config.py) and [exec provider](https://github.com/kubernetes-client/python/blob/v36.0.3/kubernetes/base/config/exec_provider.py) establish implementation risks, not verified OpenKube behavior.

Before any runtime-support claim, record exact versions/platform/filesystem/authentication combinations and passing application tests. Milestone 3 must verify SDK field visibility, the restricted authentication profile, TLS, four-endpoint RBAC and denial cases, transport/deadline bounds, and sanitized failures. Milestone 4 must verify metrics/evidence behavior. Milestone 6 must verify report safety, filesystem behavior, and exit semantics. Remaining packaging/release checks stay in their roadmap milestones. Do not waive any of these because upstream projects document compatibility.

Milestone 1 selects and documents reference targets; it does not perform those later integration tests. No SDK/runtime dependency or application behavior is authorized by this reference contract. Milestone 2 domain records and pure conversion were subsequently authorized separately and were accepted on 2026-09-29; their synthetic tests do not validate any Kubernetes/authentication/metrics combination. Milestone 3 is not authorized.
