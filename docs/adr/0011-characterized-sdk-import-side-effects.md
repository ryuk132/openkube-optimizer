# ADR 0011: Characterized SDK import side effects

- Status: Accepted
- Date: 2026-10-16
- Accepted: 2026-10-16
- Authority: Accepted by the project coordinator on 2026-10-16. This supersedes only ADR 0010's absolute prohibition on the one characterized incidental import-time PoolManager allocation. It authorizes neither OpenKube construction/use of stock transport nor any behavior prohibited in D2. ADR 0010 otherwise remains Accepted and unedited. Acceptance records this design correction, not M3.5 completion; resuming preserved M3.5A requires separate coordinator authorization. M3.5B and M3.6 remain unauthorized; dependencies and read-only scope are unchanged.

## Context

[Accepted ADR 0010](0010-controlled-kubernetes-sdk-dispatch.md#d1--describe-then-dispatch-seam) uses the pinned generated Kubernetes methods solely as request describers, with an explicit narrow adapter. Its prohibition on constructing urllib3 managers was intended to exclude stock transport authority. Strict M3.5A setup guards discovered that importing `kubernetes==36.0.3` imports `urllib3==2.8.0`, whose module itself executes `_DEFAULT_POOL = PoolManager()` before any generated call. That incidental construction was missing from ADR 0010's import characterization. M3.5A correctly stopped at the conflict; its partial implementation and failing strict guard are preserved.

This decision distinguishes allocation of an unused library object from granting it transport authority. An empty PoolManager still has callable network-capable methods. It is not disabled, safe to dispatch through, or an in-process security sandbox. The accepted exception permits only its characterized allocation, never its use by OpenKube.

## Source characterization

The exact installed packages were inspected on CPython 3.13.15. Corresponding source hashes matched on macOS and Ubuntu for six urllib3 files and three Kubernetes files: urllib3 `__init__.py`, `poolmanager.py`, `_request_methods.py`, `_collections.py`, `util/connection.py`, `util/retry.py`; Kubernetes `__init__.py` and the generated CoreV1Api/AppsV1Api files.

| Pinned source | Observed behavior |
| --- | --- |
| `urllib3/__init__.py:114` | Allocates the module-global `_DEFAULT_POOL` with exactly `PoolManager()`, no arguments. |
| `urllib3/poolmanager.py:201–230` | `PoolManager.__init__` initializes inherited headers, stores connection options, creates an empty `RecentlyUsedContainer(10)`, references the scheme-to-pool-class mapping and copies the pool-key function mapping. Its optional retry-normalization branch is not taken for this no-argument construction. |
| `urllib3/_request_methods.py:51–52` | The inherited initializer sets headers to the supplied mapping or `{}`; this import uses `{}`. |
| `urllib3/_collections.py:82–91` | The cache initializer allocates an empty OrderedDict and RLock. The lock is a synchronization object, not a started worker/thread. |
| `urllib3/util/connection.py:114–138` | `_has_ipv6("::1")` creates one AF_INET6 stream socket, binds it locally to `("::1", 0)` and closes it. This is distinct from the manager allocation; it performs no DNS, connect, send or TLS. |
| `urllib3/util/retry.py`, final assignment | `Retry.DEFAULT = Retry(3)` allocates one configuration object during import. No retry increment, sleep or other retry activity occurs. |
| `urllib3/__init__.py`, `request` | The top-level convenience function delegates to `_DEFAULT_POOL.request(...)`; it must remain unreachable during OpenKube dispatch. |

Neither the PoolManager initializer nor its inherited/cache initializers create an HTTPConnectionPool, HTTPSConnectionPool, ProxyManager, socket, DNS lookup, connection, TLS context, worker/thread or subprocess. References to connection-pool classes do not instantiate those classes. The separate IPv6 capability probe and Retry configuration allocation must not be mislabeled as connection or retry activity.

The two central source SHA-256 values were:

- `urllib3/__init__.py`: `24ca35b60d67215d40789daf10d0bf4f17e5d1ee61e86ce5f43195935ad645ba`.
- `urllib3/poolmanager.py`: `46654506338ff9a0e79baeef8a409af7d37aad001633150384a1eb4a5d1ff4cb`.

## Decision

### D1 — Exact incidental allocation exception

OpenKube must not construct or use stock SDK/urllib3 transport objects. Solely during explicit lazy SDK import, the pinned stack may allocate exactly the urllib3 module-global `_DEFAULT_POOL` through the characterized urllib3 module statement. The observed constructor's object must be identical to that global; a second manager, other caller, ProxyManager, manual reload or import workaround is not covered.

This exception is characterized for `kubernetes==36.0.3`, its locked transitive `urllib3==2.8.0`, and CPython 3.13.15. It does not make urllib3 a new direct dependency. Direct requirements remain `kubernetes==36.0.3`, `h11==0.16.0` and `PyYAML==6.0.3`; declarations and lock are unchanged.

The manager must remain inert throughout setup and generated description:

| State | Required characterized value |
| --- | --- |
| Type | `urllib3.poolmanager.PoolManager` |
| Populated connection pools | `len(_DEFAULT_POOL.pools) == 0` |
| Cache capacity | 10; capacity is not populated pools |
| Proxy / proxy configuration | `None` / `None` |
| Configured headers | `{}` |
| `connection_pool_kw` | `{}` |

OpenKube must never reference this manager for dispatch, supply it an endpoint, credential, TLS context or header, populate its cache, or mutate/replace/delete it to make the import appear safe. Test-only inspection of its identity/state is necessary evidence, not production dispatch authority.

### D2 — Transport prohibitions remain intact

There is no exception for constructing or using SDK Configuration, ApiClient, RESTClientObject, ProxyManager, or actual HTTP/HTTPS connection pools for dispatch. There is no exception for SDK deserialization, configuration/authentication loaders, thread pools or background workers.

During SDK setup/generated description, prohibit and record attempts to invoke:

- Top-level `urllib3.request` and manager `request`, `request_encode_url`, `request_encode_body` or `urlopen`.
- Every `connection_from_*` method and `_new_pool`.
- DNS helpers, remote connect/connect_ex/send, HTTP, TLS setup/handshake, retry or redirect activity.
- Credential/trust loading, proxy authority, helper processes and worker/thread starts.

The already characterized AF_INET6 `::1` bind-and-close is the only socket effect considered here, not permission for arbitrary network I/O. Subsequent application transport remains exclusively the existing controlled M3.4 stack under separately authorized work. This decision neither implements nor authorizes that composition.

Generated methods must still receive the three-member narrow adapter explicitly, remain synchronous, and return exactly one validated description without invoking stock transport. All operation/path/query/namespace/authentication/deadline/response/projection decisions in ADR 0010 remain unchanged.

### D3 — Import boundaries and drift

The OpenKube dispatch module itself remains inert; it must not eagerly import the SDK. Explicit setup retains visible import characterization, including KUBECONFIG string access, the IPv6 capability probe, this manager allocation and platform metadata access. String reads are not credential, proxy or trust authority.

Implementation acceptance must guard both sides of the import boundary. Permit only the exact incidental constructor in controlled setup, verify its identity and empty state before/after generated description, and record attempted forbidden calls even if an exception is swallowed. Outside that origin/phase, PoolManager construction remains prohibited. Guard the top-level urllib3 convenience API as well as manager methods.

Any dependency or interpreter upgrade requires renewed source/import/generated-contract characterization and review before accepting drift. Do not dynamically broaden guards. Implementation gates must apply this accepted exception precisely, without general guard relaxation. Resuming preserved M3.5A requires separate coordinator authorization.

## Disposable evidence — 2026-10-16

macOS 15.8.1 x86_64 and Ubuntu 24.04.5 LTS x86_64 each passed **30 fresh isolated subprocess probes**, with 0 failures. Both used CPython 3.13.15, kubernetes 36.0.3 and urllib3 2.8.0. Ubuntu matched kernel 6.8.0-142-generic, uv 0.12.20 and systemd-resolved 255.4-1ubuntu8.17.

Each process first checked inert OpenKube module import, then permitted the exact dependency import effects under observers. It exercised only the preserved narrow seam: all three approved generated list methods, each with first/continuation-page descriptions, six descriptions per process. No M3.4 dispatch or response processing ran.

| Observation | macOS | Ubuntu |
| --- | --- | --- |
| Import-time manager constructor count / origin | 1 / `urllib3.<module>:114` | Same |
| Post-import and post-describe manager state | Exactly D1's empty state | Same |
| Pool-method, proxy, actual connection-pool, Configuration/ApiClient/RESTClientObject/model and loader calls | 0 | 0 |
| Socket attempts | 1 AF_INET6 stream socket; successful `::1` bind; closed | Same |
| DNS, connect/connect_ex, send/sendall/sendto/sendmsg, receive, TLS and M3.4 transport activity | 0 | 0 |
| Retry configuration allocations / retry activity | 1 / 0 | Same |
| New threads/subprocesses; descriptor changes after import/description | None | None |
| Non-code open attempts during the observed import | SystemVersion.plist only | None |
| Python `.py`/`.pyc` open attempts | 1,128 | 2,212 |

Code-open counts include audit-observed attempts, not just successful reads; they are evidence, not a new limit. The macOS metadata path was `/System/Library/CoreServices/SystemVersion.plist`. Both platforms read HOME and KUBECONFIG strings plus `PYTHONDOCS`, `PYTHONUSERBASE`, `_PYTHON_PROJECT_BASE`, `_PYTHON_SYSCONFIGDATA_NAME` and `_PYTHON_SYSCONFIGDATA_PATH`; macOS additionally read `ARCHFLAGS`. These are the observed platform/import differences, with no material transport/security difference.

Distinctive proxy, HOME, kubeconfig and SSL trust environment canaries were supplied. No HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY or SSL_CERT_FILE/SSL_CERT_DIR authority was consulted during import; no environment reads occurred during generated description. KUBECONFIG became only the SDK's default-location string. Neither that string nor HOME caused credential/configuration loading or authority-bearing file access. Proxy counts stayed zero, and manager headers/options stayed empty.

Each platform's other 29 probes deliberately attempted one prohibited entry after the clean baseline. All stopped before manager request processing, pool construction, authority loading or network/thread/process activity could execute: the top-level convenience API, nine manager request/pool methods, extra manager/proxy/HTTP-pool/HTTPS-pool constructors, DNS, connect/connect_ex, send/sendall, TLS, thread/process creation, Configuration/ApiClient/RESTClientObject, both auth loaders, and environment/file authority. The top-level canary specifically recorded `urllib3.request` reaching `RequestMethods.request` on the identical `_DEFAULT_POOL`, then blocked it before request processing. These are attempted-activation canaries, not real requests or baseline transport activity. Cache state and descriptor baselines remained unchanged.

Observers were temporary test-process hooks, never production patches. No SDK/urllib3 source, global manager or import machinery was replaced. Nine installed dependency source hashes matched across platforms. Only 17 necessary files went to the VM: thirteen transitively imported OpenKube source modules, three temporary probe scripts and hashed locked runtime requirements. Their SHA-256 manifests passed before/after. A checksum-verified disposable uv/Python environment lived under `/tmp`; no sudo or persistent toolchain changes were used. VM home listings were identical before/after. The disposable native root was removed after evidence capture.

Tool/package downloads were setup traffic. Application probes made no Kubernetes/minikube API, external HTTP/HTTPS or public socket connection. No full M3.5A suite or OpenKube build was run for this characterization. These probes support only this pinned import exception; they do not complete M3.5A, establish Kubernetes runtime support, or replace later implementation acceptance.

## Consequences and alternatives

The evidence supports an allocation-only exception while retaining the strict transport boundary. The global object remains capable of I/O if called; tests cannot protect against deliberate reflection or compromised code in the same process. The import still loads substantial third-party code and retains an unused manager/configuration object until interpreter teardown. No zeroization or universal side-effect-free import claim is made.

Rejected alternatives are production monkeypatches/fake managers, replacing or deleting `_DEFAULT_POOL`, patching/vendoring dependencies or generated code, import-hook/cache bypasses, stock ApiClient/RESTClientObject dispatch, manually replacing the generated-method seam, and general network-guard relaxation. They either alter the pinned library semantics, erase evidence, or grant forbidden authority. This accepted correction resolves the incidental-allocation conflict. Resuming the preserved M3.5A work still requires separate coordinator authorization and its full implementation acceptance gates.
