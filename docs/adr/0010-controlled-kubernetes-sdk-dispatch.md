# ADR 0010: Controlled Kubernetes SDK dispatch

- Status: Accepted
- Date: 2026-10-15
- Accepted: 2026-10-16
- Authority: Accepted by the project coordinator on 2026-10-16 as the M3.5 design direction only. Acceptance does not claim M3.5 is implemented, authorize M3.5 or M3.6 implementation, change v0.1 read-only scope, or authorize dependencies or cluster contact. It supersedes only the two ADR 0008 statements named under [Relationship to ADR 0008](#relationship-to-adr-0008); every other accepted decision is unchanged.

## Context

M3.4 provides a bounded, native-accepted transport: validated endpoint → controlled resolution → ordered numeric candidates → nonblocking TCP → TLS with the original logical hostname → one bounded h11 GET → bounded private response → deterministic cleanup. M3.5 must let the official generated Kubernetes client describe the three inventory requests ([Accepted ADR 0008 D1](0008-restricted-kubeconfig-and-bounded-transport.md#d1--strict-wire-projection)) without giving the SDK any transport, credential, configuration or deserialization authority. Raw responses go to a later wire-validation/projection slice (M3.6), not to SDK models.

The [data contract](../data-and-egress.md#exact-projection-allowlist) limits collection to namespace-scoped lists of Pods, Deployments and ReplicaSets in M3; PodMetrics belongs to M4. The [CLI contract](../cli-contract.md#operational-limits-and-timeouts) freezes `page_size` 200, `max_pages_per_list` 100, the 15-second attempt deadline, three attempts per list page and the retry/backoff policy.

## Characterization evidence — kubernetes==36.0.3

Source inspection of the installed package and isolated probes on macOS/CPython 3.13.15 (platform-neutral SDK call structure) used no network, no cluster and canary environment values for `HOME`, `KUBECONFIG`, proxies, in-cluster service variables and `SSL_CERT_FILE`. Probes are disposable and not part of the repository.

| Observation | Result |
| --- | --- |
| Generated call graph | `list_namespaced_*` sets `_return_http_data_only=True` and returns `*_with_http_info(...)` unchanged. That method validates kwargs against a closed list (`ApiTypeError` otherwise), builds path/query/header values, calls `api_client.select_header_accept(...)`, and returns `api_client.call_api(...)` unchanged. Stock `call_api` → private `__call_api` (path quoting, auth injection from `Configuration`, URL from `configuration.host`, `last_response`, optional deserialization) → `ApiClient.request` → `RESTClientObject` → urllib3. `async_req` routes to a lazily created `ThreadPool`. |
| Attributes the three generated methods use | Exactly `client_side_validation`, `select_header_accept` and `call_api`. A non-`ApiClient` object exposing only these worked for all three; constructors accept it without type checks. A body-bearing generated method (PATCH) failed closed on the narrow object because it also needs `select_header_content_type`. |
| Return shape | Both wrappers return whatever `call_api` returns, unexamined. No model is required. |
| Stock `Configuration()` | Reads `HTTPS_PROXY`/`https_proxy`/`HTTP_PROXY`/`http_proxy`/`NO_PROXY`/`no_proxy` in its constructor; `safe_chars_for_path_param` is empty; `retries` is `None`. |
| Stock `ApiClient(...)` | Always constructs `RESTClientObject`. With the proxy canary it built a `urllib3.ProxyManager` (via `requests.utils.should_bypass_proxies`). Without a configuration it uses the global `Configuration.get_default_copy()`. Generated API classes construct `ApiClient()` when given none. Default `User-Agent` is `OpenAPI-Generator/36.0.3/python`; bearer auth is injected as a lowercase `authorization` header from `Configuration.api_key`. |
| Stock dispatch | URL `configuration.host + quote(path)`, namespace `a/b` sent as `a%2Fb`; `last_response` retained; with `_preload_content=True` it constructed `V1PodList` and `V1ListMeta`. urllib3's default is `Retry(total=3)`. `str(ApiException)` contained synthetic body, header and reason canaries. |
| SDK import | Importing a generated API module imports the whole package (about 1,260 modules, about 2.9 s cold on macOS), including urllib3, requests, PyYAML, oauthlib and `kubernetes.config`. `kube_config` reads the `KUBECONFIG` string at import (no file open). urllib3 creates one `AF_INET6` socket bound to `('::1', 0)` and closes it (`_has_ipv6`); no connect, listen, send, DNS, thread, subprocess or global-default change occurred. The existing import-boundary test already records that urllib3 probe. macOS also opened its system-version file; Linux import opens must be recorded natively. |

Generated request contract, identical for the three methods except where noted:

| Item | Pods | Deployments | ReplicaSets |
| --- | --- | --- | --- |
| Generated method | `CoreV1Api.list_namespaced_pod` | `AppsV1Api.list_namespaced_deployment` | `AppsV1Api.list_namespaced_replica_set` |
| Path template | `/api/v1/namespaces/{namespace}/pods` | `/apis/apps/v1/namespaces/{namespace}/deployments` | `/apis/apps/v1/namespaces/{namespace}/replicasets` |
| `response_types_map` | `{200: "V1PodList", 401: None}` | `{200: "V1DeploymentList", 401: None}` | `{200: "V1ReplicaSetList", 401: None}` |

Common: method `GET`; `path_params` `{"namespace": <raw value>}` (no encoding or validation by the generated method; `a/../b` passes through unchanged); `body` `None`; `post_params` `[]`; `files` `{}`; `collection_formats` `{}`; `auth_settings` `["BearerToken"]`; `header_params` `{"Accept": "application/json"}` after `select_header_accept` receives seven types (`application/json`, `application/yaml`, `application/vnd.kubernetes.protobuf`, `application/cbor`, `application/json;stream=watch`, `application/vnd.kubernetes.protobuf;stream=watch`, `application/cbor-seq`); `_preload_content` `True`, `_request_timeout` `None`, `async_req` `None`, `_request_auth` `None` unless the caller supplies them. Generated query parameters: `pretty`, `allowWatchBookmarks`, `continue`, `fieldSelector`, `labelSelector`, `limit`, `resourceVersion`, `resourceVersionMatch`, `sendInitialEvents`, `shardSelector`, `timeoutSeconds`, `watch`. Values pass through with their Python type (`limit=True` arrives as a boolean). The caller-controlled `_headers`, `_request_auth`, `_request_timeout`, `_preload_content`, `_content_type` and `async_req` reach `call_api` unchanged.

## Decision

### D1 — Describe-then-dispatch seam

Use the generated public method only to **describe** one request. Pass a private, single-use OpenKube object that is not an `ApiClient` subclass and exposes exactly `client_side_validation = True`, `select_header_accept` and `call_api`.

- `select_header_accept` accepts only the exact seven-type tuple above and returns `application/json`; anything else rejects.
- `call_api` performs no I/O. It validates every argument against the D3 allowlist and returns a private immutable request description; the generated wrapper returns it unchanged. The dispatcher requires exactly one `call_api` invocation and identity of the returned description.
- Transport happens only **after** the generated call returns, outside SDK frames, through the existing M3.4 functions.

Never construct `Configuration`, `ApiClient`, `RESTClientObject`, urllib3 managers, `ThreadPool` or SDK models; never call `ApiClient.call_api`, `request`, `deserialize`, `load_kube_config` or `load_incluster_config`; never read or set `Configuration._default`. Always pass the adapter explicitly so generated constructors cannot create a default `ApiClient`. No global SDK patching.

### D2 — Operation allowlist

A closed private enum maps each operation to exactly one generated class/method, `GET`, path template and response-type invariant:

| Operation | Generated method | Path template |
| --- | --- | --- |
| `LIST_PODS` | `CoreV1Api.list_namespaced_pod` | `/api/v1/namespaces/{namespace}/pods` |
| `LIST_DEPLOYMENTS` | `AppsV1Api.list_namespaced_deployment` | `/apis/apps/v1/namespaces/{namespace}/deployments` |
| `LIST_REPLICASETS` | `AppsV1Api.list_namespaced_replica_set` | `/apis/apps/v1/namespaces/{namespace}/replicasets` |

No generic method/path entry point exists. The adapter checks the received method and template against the selected operation, so a DELETE/POST/PATCH, cluster-wide (`/api/v1/pods`) or other-resource (for example Secrets) description rejects even though generated code produced it. OpenKube calls each generated method with only the positional namespace, `limit=200` and, when continuing, `_continue=<token>`.

### D3 — Exact request validation

Reject, before any resolution or connection, unless **all** of the following hold:

- `method == "GET"`; template equals the operation's frozen template; `path_params` is exactly `{"namespace": ns}`.
- `ns` is a `str` that passes the existing namespace rule (DNS label, 1–63 lowercase alphanumeric/hyphen, alphanumeric ends) and is one of the explicitly configured namespaces supplied by the caller. Substitute it literally for the single `{namespace}` occurrence. Because the rule admits only unreserved characters, `quote(ns, safe="")` equals `ns`; no percent-encoding is ever produced or accepted, so traversal and double encoding cannot occur. M3.4 then applies its unchanged path grammar and validated base-path prefix.
- `query_params` is exactly `[("limit", 200)]` or `[("continue", token), ("limit", 200)]`. `limit` must be an `int` that is not a `bool`. `token` must be a nonempty `str` accepted by M3.4's visible-ASCII and request-metadata rules; M3.5 treats it as opaque. M3.4 escapes it once.
- `header_params == {"Accept": "application/json"}`; `body is None`; `post_params == []`; `files == {}`; `collection_formats == {}`; `auth_settings == ["BearerToken"]` and `response_types_map` equals the frozen map (both checked only as generated-method invariants, never used); `async_req is None`; `_return_http_data_only is True`; `_preload_content is True` (the untouched generated default; content is never deserialized); `_request_timeout is None`; `_request_auth is None`; no other keyword.

Frozen v0.1 query profile: `limit=200` always; `continue` only on later pages. `watch`, `allowWatchBookmarks`, `sendInitialEvents`, `timeoutSeconds`, `fieldSelector`, `labelSelector`, `shardSelector`, `resourceVersion`, `resourceVersionMatch` and `pretty` are prohibited. No accepted contract requires selectors or resource-version semantics, and the API rejects `resourceVersion` with `continue`.

### D4 — Authentication, TLS and headers

OpenKube builds the request headers given to M3.4:

| Header | Owner and value |
| --- | --- |
| `Host`, `Connection: close` | M3.4, from the validated logical authority |
| `Accept` | Fixed `application/json`; the generated value is validated as metadata, not trusted |
| `Authorization` | Bearer profile only: `Bearer ` + the token from the M3.2 private preflight record, unchanged and subject to M3.4's visible-ASCII rule. No `Configuration.api_key`, JWT parsing, refresh, logging or serialization. Absent for the client-certificate profile |
| `User-Agent` | Fixed `openkube-optimizer`; no Python/SDK version, hostname or environment details |
| Prohibited | `Content-Type`, `Accept-Encoding`, `Cookie`, proxy headers, caller `_headers`, any SDK default header |

Client certificate/key stay in the M3.3 `SSLContext`; no path, descriptor or credential reaches the SDK. The generated `auth_settings` metadata never selects or loads credentials.

### D5 — Transport composition and deadline

Production M3.5 introduces the first composition of the accepted M3.4 functions. One dispatch is exactly one attempt: describe (D1–D3) → `_resolve` → `_connect` with the borrowed M3.3 `_TlsContext` → `_exchange`. The caller supplies one finite absolute monotonic deadline (the existing per-attempt budget, already clipped by cycle/run deadlines and the finalization reserve). M3.5 checks it before describing and before resolving, forwards it unchanged, and never creates socket timeouts, `_request_timeout` values, retry budgets or phase resets.

The SDK is imported lazily by an explicit setup step, not at module import, and its first-import cost counts against the existing run budget. Description is pure CPU before the attempt's network work.

M3.5 performs no retry, re-dispatch, redirect or reconnection; one generated dispatch maps to one M3.4 exchange. The existing three-attempt/backoff policy and run/cycle/page deadlines belong to the later collection coordinator, which may call M3.5 again as a new attempt with a new description.

### D6 — Response boundary, status policy and failures

Only status 200 succeeds. It returns a private immutable record with slots, redacted `repr`, and serialization and copy rejection, following the M3.4 pattern. It holds the operation enum, the requested namespace and the bounded raw body bytes. The successful status is implicitly 200; no separate status field, headers, SDK object, socket or candidate are retained. Raw body bytes are transient memory-only data for M3.6: never persist or log them. Every other final status releases any body immediately without inspection and returns a fixed failure. The completed M3.4 correction returns non-2xx statuses with an empty body without draining; other 2xx bodies remain bounded by M3.4. The future implementation extends the existing private `_Failure` enum with the fixed members below. These are adapter-local categories, not new public diagnostic codes or exits; later CLI handling uses the existing [error policy](../cli-contract.md#json-schema-and-error-strategy).

| Status | Future private failure | Later CLI handling (unchanged contract) |
| --- | --- | --- |
| 401 | `KUBERNETES_UNAUTHORIZED` | `AUTHENTICATION_FAILED`, fatal, no retry |
| 403 | `KUBERNETES_FORBIDDEN` | `ACCESS_DENIED` for that namespace, no retry |
| 404 | `KUBERNETES_NOT_FOUND` | `INVENTORY_UNAVAILABLE`, no retry |
| 410 | `KUBERNETES_GONE` | expired continuation; namespace pass incomplete, no retry |
| 429 | `KUBERNETES_THROTTLED` | retryable category under the existing policy |
| 500, 502, 503, 504 | `KUBERNETES_UNAVAILABLE` | retryable category under the existing policy |
| Any other final status, including other 2xx, 3xx, other 4xx such as 409, and other 5xx | `KUBERNETES_UNEXPECTED_STATUS` | non-retryable source failure |
| Request outside D2/D3 | `SDK_DISPATCH_REJECTED` | internal failure; nothing sent |

M3.4 transport failures pass through unchanged. Failures carry no namespace, endpoint, token, body, Kubernetes `Status` message, headers, SDK/urllib3 text, candidate or path; the caller already knows which namespace it requested. No `ApiException` is constructed, so error bodies cannot enter exception text.

### D7 — Pagination

Pagination is required in v0.1: the CLI contract freezes `page_size` and `max_pages_per_list`, the data contract allowlists `metadata.continue`, and the M3 roadmap acceptance lists pagination. Reading `metadata.continue` is JSON interpretation, so M3.5 does not do it. The boundary is:

- **M3.5:** dispatches one page with `limit=200` and an optional opaque caller-supplied token.
- **M3.6:** validates the list envelope and extracts `metadata.continue` (and `resourceVersion` for consistency) under the wire guards.
- **Later collection coordinator:** owns the page loop, `max_pages_per_list`, inventory caps, deadlines and the D3 discard semantics for any incomplete pass. 410 ends the pass as incomplete.

This assignment introduces no milestone conflict and changes no contract.

### D8 — Isolation guarantees

- **Async/threads:** `async_req` other than `None` rejects; no `ThreadPool`, future or worker exists because no `ApiClient` exists.
- **Retries/redirects:** urllib3 and stock REST are unreachable, so their `Retry(total=3)` and redirect defaults cannot run.
- **Deserialization:** no `deserialize`, `model_from_dict`, generated response-model construction or `ApiException`; `_preload_content` is never acted on.
- **Global and configuration state:** no `Configuration` instance, default copy, `set_default`, kubeconfig or in-cluster loading, and therefore no proxy, `KUBECONFIG`, `HOME`, service-account or trust-store authority.
- **Import:** importing the M3.5 module imports neither the SDK nor h11. Explicit lazy SDK setup must match the pinned characterization above, including the `KUBECONFIG` string read, urllib3 IPv6 loopback bind-and-close and platform metadata reads. Native Linux import opens must be characterized and guarded during implementation acceptance. This permits no DNS, remote connect/send or stock transport setup.

### M3.5 / M3.6 boundary

M3.5 produces generated-request description → validated controlled dispatch → bounded raw wire response, or a fixed failure. M3.6 owns bounded wire decoding, strict JSON/shape validation, `apiVersion`/`kind`/namespace checks, `metadata.continue`, projection into OpenKube records and malformed-object handling. M3.6 needs no SDK transport. M3.5 never parses JSON.

## Relationship to ADR 0008

This ADR supersedes only two SDK-dispatch seam statements in ADR 0008; they were demonstrated by a feasibility probe, not by the accepted transport:

- D1's "demonstrated interception point is `ApiClient.request` with synchronous generated calls and `_preload_content=False`".
- The authentication section's "Construct fresh explicit SDK `Configuration` and `ApiClient` instances".

The probes above show that this path constructs proxy-aware stock transport objects from environment variables, retains `last_response`, depends on stock path quoting and auth injection, and leaves body-bearing exception and deserialization code reachable. D1 of this ADR replaces it with a seam that creates none of these objects. All other ADR 0008 decisions, including the strict wire projection principle, D3 failure semantics, D4 limits and the D5 credential model, remain unchanged. ADR 0008's text is not edited.

## Alternatives

1. **Stock `ApiClient` with an overridden `request` (ADR 0008 probe seam).** Rejected for the reasons above.
2. **Subclass `ApiClient` and override `call_api`.** Rejected: `ApiClient.__init__` still builds `RESTClientObject` and a proxy-aware pool, and the global default is reachable.
3. **Call `*_with_http_info` directly.** Workable, but the public method fixes `_return_http_data_only=True`, giving one more checkable invariant. It is not needed.
4. **Hand-written request paths without the SDK.** Simpler, but drops the accepted use of generated request knowledge and loses drift detection against the pinned SDK.
5. **Global monkeypatching of SDK/urllib3.** Rejected: process-global and order-dependent.
6. **Generic `request(method, path)` tunnel.** Rejected: it is not a read-only allowlist.

## Consequences and limitations

- Generated SDK request knowledge stays useful while transport, credentials, configuration and response handling remain OpenKube-owned. Any SDK upgrade must re-run the characterization: changes to the call-signature or attribute set fail closed in tests.
- The SDK import is heavy and loads urllib3/requests code that is never used for network I/O.
- The M3.4 no-drain erratum is implemented, validated and committed in `e9bc7ae`. Final non-2xx responses preserve status, return `body == b""` and close the single-use TLS transport without draining; final 2xx responses retain bounded body processing. The former technical prerequisite is resolved. M3.5 implementation still requires separate authorization.
- Retry-After is not exposed in M3.5. No arbitrary response headers are added to M3.4. Any later Retry-After support requires separate authorization; M3.5 does not retry.
- No Kubernetes, RBAC, pagination or real API payload behavior is established by this design.

## Acceptance strategy for implementation

**Unit (platform-neutral):**
- The three operations produce exactly the D2/D3 contract.
- Every non-allowlisted generated method and every D3 deviation (each prohibited query, `watch`, selectors, resource versions, `_headers`, `_request_auth`, `_request_timeout`, `async_req`, `_preload_content=False`, bool `limit`, empty/invalid/unconfigured namespace, traversal input, a second `call_api`, a foreign returned object) rejects before resolution.
- Deny-guards for `Configuration`, `ApiClient`, `RESTClientObject`, urllib3 managers and `urlopen`, `ThreadPool`, `deserialize`, every model constructor, `ApiException`, kubeconfig/in-cluster loaders and `Configuration._default` record zero calls, including swallowed attempts.
- The status table maps exactly and bodies are released.
- Failures contain no canaries.
- Import inertness holds and the lazy SDK import's recorded side effects match the characterization.
- A drift test pins the generated attribute set, kwargs list, templates, Accept list and response-type maps for kubernetes==36.0.3.

**Integration (authoritative Ubuntu):**
- Each operation runs over real M3.4 loopback TCP/TLS/h11 to a synthetic server serving canned bytes: exact request line, Host, Connection, Authorization or no Authorization, Accept, fixed User-Agent and absence of other headers; a single exchange.
- One deadline shared across describe/resolve/connect/exchange.
- No retry or redirect.
- The token and mTLS paths.
- Proxy/`KUBECONFIG`/`HOME`/service-account canaries ignored.
- Descriptor and thread baselines restored.
- Negative canaries detect removed checks.
- Installed-wheel validation in a clean CPython 3.13.15/uv 0.12.20 environment, as in M3.4D.

No cluster contact is required for M3.5 acceptance.

## Coordinator decisions and implementation gate

The coordinator accepted the design direction and the limited ADR 0008 supersession described above on 2026-10-16; ADR 0008 remains unedited. This accepts the design only: M3.5 is not implemented, and neither M3.5 nor M3.6 implementation is authorized by this acceptance.

- M3.5 dispatches exactly one page (`limit=200`, optionally preceded by `continue`); it never parses JSON, extracts `metadata.continue` or runs a pagination loop. M3.6 extracts the validated continuation; a later coordinator owns the loop and `max_pages_per_list = 100`. A 410 can later classify the pass as incomplete.
- The future User-Agent is exactly `openkube-optimizer`.
- Retry-After is not exposed; support requires separate authorization.
- The future module remains inert and imports the SDK only during explicit setup. The characterized `KUBECONFIG` string access and urllib3 local AF_INET6 `::1` bind-and-close must remain guarded; no remote connect/send or arbitrary network I/O is authorized.
- The M3.4 non-2xx close-without-draining prerequisite is resolved by `e9bc7ae`. M3.5 implementation can now be separately authorized; M3.6 remains future work requiring separate authorization.
