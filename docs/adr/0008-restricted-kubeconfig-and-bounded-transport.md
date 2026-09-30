# ADR 0008: Restricted kubeconfig loading and bounded Kubernetes transport

- Status: Accepted
- Date: 2026-09-30
- Accepted: 2026-09-30
- Authority: Explicit user approval of D1–D6, the trusted credential-stability/setup boundary, h11==0.16.0, and the unchanged report contract; acceptance authorized after final consistency review. The review found no remaining architecture decision. This records design acceptance only.
- Scope: Milestone 3 design. Acceptance alone authorizes no collector, runtime dependency, manifest or broader documentation implementation; the subsequently authorized documentation pass is recorded below. Milestone 3 implementation still requires separate authorization.
- Relationship: Dated refinements to Accepted ADRs [0001](0001-read-only-cli.md), [0003](0003-access-and-data-boundary.md), [0004](0004-identity-and-domain-model.md), and [0005](0005-cli-and-report-contract.md). The bounded-execution qualification below explicitly supersedes the stronger setup-cancellation interpretation; their historical text remains unchanged. The separately authorized documentation consistency pass is recorded below; accepted technical decisions remain unchanged. See [consistency plan](#documentation-consistency-plan).

## Context and decision status

The frozen architecture requires one local synchronous Python process, read-only namespaced access, bounded execution, exact allowlisted projection, and no sensitive output. Ordinary transport timeout parameters did not prove that blocking system name resolution could be cancelled. The earlier macOS investigations established useful response-safety and SDK-interception evidence, but did not prove a complete cancellable resolver path. macOS must not drive a universal resolver design for v0.1.

The subsequent executable Ubuntu investigation demonstrated nonblocking Varlink resolution, bounded TCP/TLS/HTTP consumption, cleanup, and generated Kubernetes API dispatch. It also demonstrated that direct systemd-resolved lookup differs from this host's normal `files dns` NSS path, even though that path uses resolved's DNS stub. Option 2 explicitly constrains endpoint semantics instead of claiming equivalence or reconfiguring the host.

The following categories must remain separate:

| Category | Status in this ADR |
| --- | --- |
| Existing accepted architecture | ADRs 0001–0007, ten inputs, six exits, exact data boundary, evidence methodology, and existing numeric operational limits remain authoritative, subject only to the explicit dated amendments below. |
| Accepted design | D1–D6, Ubuntu priority, direct resolved/endpoint semantics, credential stability and setup non-guarantees, dependency selection and unchanged report schema are accepted on 2026-09-30. Implementation remains unauthorized. |
| Executable feasibility evidence | Disposable probes, not repository application code or Kubernetes integration. Evidence is limited to the exact tested combinations and cases. |
| Initial validation profile | A restricted target for implementation validation, not established OpenKube runtime support. |
| Versioned implementation policy | D4 separates architectural requirements, existing operational limits and initial defensive guard values. Guard values require implementation tests and documented policy review when changed; they are not permanent architecture invariants or Kubernetes semantic limits. |
| Remaining validation and future targets | Explicitly listed below; no inference of platform, authentication, or cluster support from a passing transport probe. |

The D1–D6 labels in this ADR are Milestone 3 decisions. They are distinct from the original architecture-freeze D1 configuration, D2 exit-code, and D3 reporting decisions.

## D1 — Strict wire projection

Use official Kubernetes Python client generated API methods for request construction/dispatch where useful. Intercept before stock REST response handling. Receive bounded wire bytes, validate HTTP framing/content decoding and strict JSON structure/types, then immediately project the exact [data allowlist](../data-and-egress.md#exact-projection-allowlist) into OpenKube-owned records.

Stock SDK error-body handling and generic generated-model deserialization are not the projection boundary. In particular, truthiness conversion must not turn a wire string into a boolean, coercion must not erase invalid types, and SDK field loss must not turn an unsupported field into apparent absence. Preserve exact quantities/timestamps and the domain's explicit absence/invalid/unavailable distinctions. Unknown fields are not projected; ignoring them does not excuse malformed framing, duplicate JSON keys, or unsafe nesting. Validate endpoint/list/object structure before interpreting allowlisted facts.

The demonstrated interception point is `ApiClient.request` with synchronous generated calls and `_preload_content=False`, bypassing the stock REST implementation. That flag alone is insufficient: the stock REST path can construct body-bearing SDK exceptions on errors. Clear `ApiClient.last_response` on every path and release raw buffers/temporary trees after immediate projection. Construct closed sanitized outcomes without returning or retaining raw exception objects, traceback chains, headers, or bodies. Do not format a raw exception before sanitizing it.

Transient raw API/SDK data is permitted only as technically required within this adapter boundary. It must not enter analysis, reports, logs, persistence, caches, or unsanitized exceptions. UIDs retain their accepted internal memory-only lifetime; no UID-derived public identifiers. No new projected field or API permission is introduced.

M3 inventory uses only namespaced Pods, Deployments and ReplicaSets. PodMetrics collection belongs to M4. A synthetic PodMetrics dispatch probe is evidence about the shared transport only, not permission to implement metrics during M3.

## D2 — Bounded synchronous transport

The initial priority runtime validation target is Ubuntu 24.04 LTS x86_64 with systemd-resolved active and authoritative for the chosen native resolver profile. Its local Varlink interface must be accessible and trusted. Do not require NSS `resolve`, installation of `libnss-resolve`, or changes to the host's NSS, stub, DNS servers, search domains, or network manager.

Accepted transport sequence (after local trusted-input/TLS-context setup):

```text
Synchronous caller and existing run/cycle budgets
  -> one monotonic attempt deadline
  -> nonblocking local Varlink ResolveHostname
  -> validated bounded address candidates
  -> bounded nonblocking TCP attempts
  -> nonblocking TLS using the original endpoint hostname
  -> bounded HTTP framing, content decoding, and strict wire validation
  -> immediate allowlisted projection
```

Use `/run/systemd/resolve/io.systemd.Resolve`; do not flatten per-link resolver configuration into an independent DNS client. Validate the local socket path/type, trusted ownership/parent directories and peer credentials. A successful `stat` alone is not sufficient against replacement; identity/replacement handling needs implementation tests. Fail closed when the required resolver service/profile is unavailable. No `getaddrinfo` fallback, executor-backed DNS, abandoned worker thread, `resolvectl` subprocess resolver, subprocess isolation, public DNS fallback, or provider-specific resolver. No asynchronous application architecture or worker process is introduced.

The earliest active deadline wins. The existing 15-second HTTP-attempt budget includes resolution, all candidate selection/connection attempts, TCP, TLS, HTTP metadata/body consumption, and bounded decoding/validation. Each TCP attempt is additionally limited to five seconds. Every read/write/wait uses the remaining deadline; progress or a new address never resets it. There is no separate tunable read timeout: the remaining absolute budget bounds each read, including slow-drip input. The earlier run/cycle deadlines still apply; they are not replaced by these per-attempt limits.

### Bounded-execution amendment — 2026-09-30

Local trusted-input loading and native TLS-context construction are setup operations protected by explicit input-size guards, parser/format guards, bounded OpenKube-controlled reads, validation, cleanup and sanitized failures. They are synchronous filesystem/native parsing operations. OpenKube does **not** claim hard mid-call cancellation of an executing regular-file read or OpenSSL parser operation. A surrounding Python timer is not native cancellation.

The per-request monotonic transport deadline begins at the controlled resolution/transport attempt and covers systemd-resolved Varlink resolution, bounded address attempts, TCP connection, TLS handshake, and HTTP request/response processing. TLS-context construction is setup; the network TLS handshake is inside the transport deadline.

The total monotonic run clock still starts before authentication/setup. Setup elapsed time consumes the existing budget; it is not omitted, reset or added as an extension. Check deadlines before and after setup operations and at OpenKube-controlled boundaries; if expired, stop before beginning further authentication/transport work and apply existing sanitized deadline/failure handling. Existing numerical auth, run, cycle and finalization budgets are unchanged, but an executing trusted-file/native setup call can overrun them before control returns. Thus these budgets are not an unconditional wall-clock return guarantee across that setup boundary.

This explicitly qualifies ADR 0005's total/per-operation deadline requirement and the CLI contract's statement that the total deadline includes every operation. It supersedes only an interpretation promising hard cancellation inside these trusted-input/native setup calls, together with the external-daemon interpretation below. It does not move DNS or network I/O outside the attempt deadline, permit abandoned OpenKube-owned workers, weaken evidence timing, or relax output-safety requirements. Accepted ADR history is preserved; corresponding contract annotations were applied by the subsequently authorized documentation consistency pass.

### Controlled transport behavior

Validate each address, family and IPv6 scope before connection; deduplicate candidates and attempt each at most once per HTTP attempt, within the fixed count and time bounds. Do not promise glibc ordering, Happy Eyeballs performance, or success after every candidate has stalled. Numeric connection addresses are internal results of resolving the configured hostname, not a numeric-IP-only endpoint requirement. Never perform a second hidden name lookup during connection or sorting. Private IP results are permitted; unspecified/multicast destinations are not valid API-server candidates. Link-local IPv6 requires valid interface scope and separate connection validation.

Disable automatic redirects and underlying automatic retries. Explicit retries remain solely the existing [CLI policy](../cli-contract.md#operational-limits-and-timeouts): at most three HTTP attempts per list-page request, specified transient errors/backoff, no retry of 401/403, TLS validation failure or malformed data, and no deadline extension. Address fallback is not an extra HTTP retry budget. Never resend an HTTP request automatically after a partial exchange.

Bound HTTP metadata, aggregate encoded input and decoded bodies, including chunked and compressed responses. Reject unsupported content encodings; the demonstrated profile is identity/gzip, including concatenated gzip members. Decode incrementally with an output bound at each decompression step. Do not rely on `Content-Length`, compression ratio, or an object count after deserialization. Close unsuccessful responses without draining their bodies or constructing SDK exceptions. A bounded socket read may receive error-body bytes alongside headers; this is transient buffering, not a zero-network-body-byte guarantee. Only the existing allowlisted status/Retry-After interpretation may survive into sanitized control flow.

Close every OpenKube-owned controllable socket/response/selector on success, failure, cancellation, malformed input, or limit exhaustion. Do not make cleanup depend on draining a hostile peer or completing a TLS shutdown handshake. Connection pooling is not needed for the initial candidate; explicit connection closure makes ownership/cleanup simpler. There is no listener/server in the application; listeners and joined server threads existed only in the synthetic test harness.

### System resolver cancellation boundary

The required OpenKube guarantee is: when its deadline expires, it stops waiting, closes its Varlink connection and all OpenKube-owned transport resources, and leaves no OpenKube-owned worker thread/task/process running. This is a required implementation guarantee, not a claim that repository transport code already exists.

Upstream systemd-resolved v255's disconnect handler aborts the associated live query. Daemon-side query abortion was supported by source inspection, not directly observed in the Ubuntu runtime probe. Shared resolver work can serve other clients. OpenKube does not guarantee hard-real-time cancellation inside the daemon, instantaneous termination of daemon/shared work, or control over unrelated resolver clients. Normal scheduling overhead also prevents a hard-real-time return-at-the-exact-nanosecond promise for the CLI.

This refines the frozen meaning of cancellation to OpenKube-owned controllable work; it does not remove DNS from the attempt budget, allow a background OpenKube resolver to continue, lengthen any numerical deadline, or authorize terminating the whole CLI as the normal timeout mechanism. Any interpretation requiring instantaneous termination of all external daemon work is superseded by this explicitly accepted boundary. The separate trusted-input/native setup non-guarantee is stated above.

### Constrained endpoint semantics

The selected trusted kubeconfig context supplies the sole HTTPS endpoint. The initial profile requires an explicitly specified multi-label ASCII DNS hostname, treated as absolute even without a final dot. Require nonempty labels containing only ASCII letters, digits and hyphens, with alphanumeric ends, and the length bounds in D4. Numeric URL hosts, IDN forms (including `xn--` labels) and trailing-dot URL hosts are outside the initial target syntax pending explicit tests; internal numeric address candidates remain necessary and permitted. No endpoint override input is added.

Resolution must not depend on search-suffix expansion, single-label aliases, special synthesized names such as localhost/_gateway, custom NSS providers, or glibc resolver-environment overrides. There is no NSS/DNS fallback. Multi-label syntax alone cannot prove that an operator intended an absolute rather than search-relative name: document this contract, resolve only the name as given, and fail rather than trying suffixes. Normal private DNS and per-link routing remain owned by resolved; successful VPN/split-DNS integration is not established by the current probes.

Returned address order may differ from glibc; use bounded fallback under the same deadline. The ORIGINAL configured hostname remains the TLS SNI and certificate-verification identity; HTTP authority uses that hostname and its configured port. DNS canonical names never replace it. Do not weaken verification to compensate for different addresses. The localhost-family names in loopback fixtures exercised transport mechanics; they do not demonstrate production endpoint acceptance under this constrained syntax.

## D3 — Unprojectable mandatory structure

If a required object/list structure cannot be safely and unambiguously projected for identity/ownership, invalidate the affected namespace inventory for that collection pass. Examples include missing/invalid mandatory identity, an unparseable required owner-reference structure, contradictory duplicate identities, or malformed list items. Never silently drop such an object and call the inventory complete; never guess identity or ownership.

Use the existing [collection-result contract](../cli-contract.md#partial-success-semantics): discard that incomplete namespace pass from analysis, preserve independently complete namespace inventories and previously trustworthy results where allowed, and emit a closed sanitized error. Some usable inventory means incomplete/4; none means failed/3, subject to the existing fatal/interruption/output precedence. No new exit or free-form diagnostic is introduced.

Do not confuse structural failure with representable uncertainty. A well-formed unsupported owner, orphan/unresolved chain, multiple well-formed controller references, or invalid non-identity lifecycle/allocation field can be represented through existing unresolved/unsupported/field states and abstention as applicable. D3 does not invalidate an entire namespace merely because one otherwise identifiable subject is ineligible for utilization. The precise mandatory-field fixtures must be reviewed against the existing domain and data allowlist before implementation acceptance.

## D4 — Local input and wire safety limits

### A — Architectural requirements

Require bounded local inputs, parser complexity, wire input, decoded input, resolver results, pagination/inventory, and retries/backoff; credential identity/trust rules; noninteractive authentication; cleanup and sanitized failures. These guarantees are subject to the explicit D2 setup and D5 trusted-file assumptions, not hard native-parser CPU/RSS guarantees. No new CLI inputs or report fields are introduced. A safe-looking object count cannot replace byte/depth/deadline guards.

### B — Existing accepted operational limits

Retain the frozen values in the CLI contract, including decoded-response, pagination, inventory, retained-data and request/retry budgets reproduced in the table below for review. They were accepted before ADR 0008 and are not newly invented implementation guards. Other existing namespace/sample/report, baseline/closure, auth/run/finalization and quantity/identifier limits remain defined by that contract. D2 explicitly qualifies setup cancellation without changing those numbers. Evidence timing is unchanged.

### C — Versioned implementation guards

The table identifies initial implementation-policy values separately from existing frozen limits and syntax/rejection rules. The new defensive numbers are starting values to implement and boundary-test, not Kubernetes semantic limits or permanent architecture invariants. Document/version changes with rationale and tests; changes to the architectural boundary still require review. They are not operator tuning controls.

MiB/KiB mean binary bytes. Equality is permitted for maxima; reject on the next byte/item or before exceeding the retained allocation. OpenKube-controlled file reads count actual bytes, not `stat` alone, using one-byte overflow detection; D5 explains subsequent native reads under the stability assumption. Depth is the number of nested mapping/sequence or object/array containers, with the root at depth 1; check before constructing deeper structures. Reject duplicate JSON keys, non-finite JSON numbers, invalid encodings and trailing non-whitespace content. YAML parsing must not invoke arbitrary constructors. DNS length/label limits are endpoint syntax constraints, not discretionary resource-sizing limits.

Failure legend: **C** = reject configuration before API access, sanitized `CONFIGURATION_INVALID`, exit 2. **L** = `LIMIT_EXCEEDED`; stop the affected operation and invalidate incomplete inventory, producing existing failed/3 or incomplete/4 according to usable inventory. **M** = `MALFORMED_DATA`, no malformed-data retry, same inventory semantics. **T** = existing request/deadline/connection codes and bounded retry/status policy. No source exception text is copied. TLS/authentication failures retain fatal/3.

| Key or structural rule | Value and scope | Rationale / classification | Failure | Executable evidence |
| --- | --- | --- | --- | --- |
| `max_kubeconfig_bytes` | 1 MiB, entire selected file | Initial implementation guard: enough space for an ordinary multi-context trusted file; bounds preflight even though only one context is used. No claim that larger kubeconfigs are invalid Kubernetes configuration. | C; reject oversize/truncated/malformed input | Not tested |
| `max_credential_file_bytes` | 1 MiB per referenced CA, client-certificate or client-key file | Initial implementation guard: accommodates chains/bundles; at most the selected three inputs. Bounds OpenKube's inspection and stable native inputs, not changed-in-place contents or native heap/CPU. | C on detected oversize; D5 stability assumption required during native loading | Overflow and near-cap synthetic material tested; native reread exceeding cap after mutation demonstrated, not prevented |
| YAML documents / depth | Exactly 1 document; maximum depth 32 | Initial implementation guards: one configuration, bounded nesting with ample margin above the selected-context structure. | C before deep construction | Not tested |
| YAML anchors, aliases, merge keys, duplicate mapping keys, custom tags | 0 permitted; mapping keys must be strings | New rejection policy: avoid expansion/cycles, hidden overrides and executable constructors. Also reject ambiguous duplicate context/cluster/user entry names; unused entries never activate authentication. | C | Not tested |
| `max_endpoint_hostname_bytes` / DNS label length | 253 ASCII bytes total, 63 per label; at least 2 labels | DNS syntax-derived constrained endpoint rule, not a Kubernetes resource-name limit. Exclude IDN and trailing-dot forms until tested. | C | A 254-byte name was rejected in the resolver probe; full endpoint grammar/boundaries untested |
| `max_varlink_request_bytes` | 1 KiB including terminating NUL | Initial implementation guard: the closed ASCII hostname/family/flags request fits well below this; 4 KiB in the probe was unnecessarily generous. Check serialized bytes before sending. | C for invalid endpoint; impossible oversized internally built request is internal failure/3 | The probe used 4 KiB; the initial 1 KiB boundary is not tested |
| `max_varlink_response_bytes` | 64 KiB including NUL, one reply | Initial implementation guard: ample room for the address cap and metadata; no streaming/multiple replies required. | L; close socket, no fallback | Oversized reply rejection tested |
| `max_resolver_addresses` | 64 raw address records per reply, before deduplication | Initial implementation guard: finite candidate parsing and connection work; reject rather than silently truncate. This is a policy ceiling, not a claimed DNS maximum. | L | 65-record reply rejected |
| Address connection attempts | At most 64 per HTTP attempt, each distinct candidate at most once | Derived from the address cap; no independent configuration/limit key needed. Shared time budget remains stricter during stalls. | T on exhausted candidates/deadline | Two-address fallback, eight refusals, saturated-queue timeout tested; full 64-candidate boundary not tested |
| `max_wire_json_depth` | 32 for Kubernetes and Varlink JSON | Initial implementation guard: avoids deeply nested construction; allows ordinary Kubernetes envelope/Pod structures. Does not imply a process-memory ceiling. | M | Probe used depth 8 for Varlink and rejected depth 10; initial depth 32 and Kubernetes wire parsing not tested |
| `max_http_metadata_bytes` | 16 KiB each for request metadata and aggregate response metadata | Initial implementation guard: request line/headers and response status/header/trailer blocks; bounded framing overhead and inherited credential/header sizes. Count across informational blocks if supported, not once per block. | Oversized configured auth/request input C; response excess L; invalid framing M | Oversized response-header rejection tested; complete aggregate/request/trailer boundaries not tested |
| `max_encoded_response_bytes` | 32 MiB aggregate HTTP plaintext received before content decoding, per attempt | Initial implementation guard: includes HTTP metadata/chunk framing/trailers and compressed data; gives framing/compression overhead above the decoded cap while bounding encoded floods. Not a bound on TCP/IP or TLS record/handshake overhead. | L; close immediately | Counter present in probe; crossing 32 MiB was not independently tested |
| `max_response_bytes` | 16 MiB decoded per response | Existing frozen guard, retained; incremental decompression must enforce it before wire-tree/model construction. | L | Exact cap accepted by decoder; larger plain/chunked and gzip/chunked bodies rejected, including through SDK dispatch |
| `page_size` | 200 where inventory pagination is supported | Existing request-page policy, not a substitute for actual response/count validation; never assume PodMetrics pagination. | L if collection cannot complete within bounds | No cluster/pagination validation |
| `max_pages_per_list` | 100, per list | Existing guard; continuation still present at exhaustion means incomplete, never successful truncation. | L | Not tested |
| `max_inventory_objects` | 10,000 across a pass over selected namespaces | Existing guard; count consumed inventory records, not only successfully projected subjects. | L; retain only complete namespace inventories | Not tested |
| `max_container_subjects` | 20,000 distinct Pod UID/container subjects per run | Existing guard; does not permit UID persistence. | L | Collection accounting not tested |
| `max_domain_bytes` | 256 MiB accounted retained domain/sample/report data | Existing guard, not Python RSS or total transient parser/TLS heap. Include live accounted allocations before accepting more data; no disk spill. | L; bounded release/finalization under existing contract | Runtime accounting not tested |
| `connect_timeout_seconds` | 5 per TCP candidate, shortened by earlier deadlines | Existing guard; do not allocate five new seconds past the attempt deadline. | T | Saturated loopback queue returned in 5.005720 s |
| `request_timeout_seconds` | 15 per HTTP attempt across all stages | Existing guard, clarified to include DNS; no progress-based extension. | T | Actual 15-second stall returned in 15.014545 s; shorter fault tests also passed |
| `max_attempts` / backoff | 3 HTTP attempts; 1 s then 2 s, at most 250 ms jitter per backoff | Existing explicit retry policy, never multiplied by SDK retries; valid Retry-After must fit remaining budgets. | T | SDK/HTTP implicit retry absence tested for selected statuses; full coordinator retry policy not tested |

The [frozen operational limits](../cli-contract.md#operational-limits-and-timeouts) remain the numeric authority for class B; the D2 amendment is the authority for their setup-cancellation qualification. Nothing here lowers evidence eligibility or changes observation timing.

Do not promote the probe's 150 ms/2 s test budgets, 4 KiB request cap, depth-8 JSON cap, socket-read chunk size, decompression step size, synthetic delay, test-server timeouts, or external test-harness process limits into product policy. Small read/decompression steps remain implementation choices that must respect the reviewed aggregate budgets.

The closed v0.1 report schema remains unchanged. Retain exactly the existing required `configuration.limits` keys; document/version additional internal parser, input and transport guards with implementation policy/tool releases, analogous to the existing quantity-parser expansion guard. They create no report fields or user configuration inputs. Do not change schema `1.0.0` or the domain's data/evidence/rule version constants for these adapter-local guards. This resolves the earlier reporting question; it is not pending review.

## D5 — Trusted credential symlinks and bounded local inputs

Trusted local symlinked kubeconfig-referenced CA/certificate/key inputs may be accepted when their targets are regular local files and satisfy the input guards. Resolve relative references against the selected kubeconfig location, not the process working directory. Bound the actual reads; reject directories, devices, FIFOs, sockets and remote/network filesystem profiles outside the validated local-file scope. Do not add a blanket credential-symlink prohibition merely because report destinations have a different no-symlink policy.

### Trusted-file and identity policy

Explicit CA, client certificate and private-key inputs must be trusted local regular files satisfying the symlink and bounded-input policy. Credential files must remain stable during TLS-context construction. Trust includes the selected files and their local path/permission environment; OpenKube does not change operator credentials or permissions. No protection is claimed against malicious local root, a compromised trusted filesystem, concurrent in-place mutation of trusted credential files, or guaranteed zeroization of Python/OpenSSL copies.

Verify file type and identity through descriptors; reject nonregular inputs without blocking on FIFO/device content. Inspect sizes before reading and enforce the actual byte cap while reading, including a one-byte overflow check. Metadata/identity checks around reads are useful diagnostics, not proof of an atomic immutable snapshot. The exact opening sequence and cleanup require implementation tests; the probe is not production code.

### Explicit CA

Open the CA through the bounded trusted-file boundary, size-limit before/while reading, detect overflow, and validate certificate-only material. Convert/load the bounded in-memory snapshot using `SSLContext.load_verify_locations(cadata=...)`; do not reopen the original CA pathname for TLS loading. For PEM, strict certificate-envelope/base64 validation followed by DER `cadata` avoids native PEM password callbacks. No embedded kubeconfig materialization or implicit system trust-store fallback is allowed. Native OpenSSL configuration/provider initialization can still perform infrastructure file reads; this is not a claim of zero native filesystem I/O.

### Client certificate and private key

Validate and boundedly inspect both trusted files, retain descriptors for the selected files, and use descriptor-backed Linux paths such as `/proc/self/fd/<fd>` for `SSLContext.load_cert_chain()`. Require this facility in the initial Ubuntu profile and fail closed if unavailable; do not fall back to the original path. Keep descriptors open throughout loading, then close them on success or failure. This pins file identity against pathname/symlink replacement; it does **not** make contents immutable. OpenSSL performs subsequent native reads of those inodes. In-place mutation remains a documented trusted-input race, including growth beyond the inspected cap; a preliminary size/metadata check cannot enforce a native read cap against that excluded mutation.

Loading failure aborts the authentication attempt with no fallback. Reject invalid selected configuration through the existing configuration-error path; native TLS-context loading failures use fixed sanitized `TLS_FAILED`/failed-3 handling. Discard partially populated failed contexts and release buffers/descriptors on every path. Never format/log raw exception text, arguments, paths, credential material or traceback chains. No new error code is introduced.

### Noninteractive keys and retention

Encrypted/password-protected private keys are outside the initial profile. Always supply a noninteractive rejecting password callback during client-key loading, even after format preflight. Do not prompt, accept credential passwords from OpenKube configuration or environment variables, invoke external helpers, rely on OpenSSL's default interactive callback, or use an empty password as a substitute. An encrypted format identified during preflight is rejected as `CONFIGURATION_INVALID`; rejection encountered during native loading is sanitized as above, without exposing the callback exception.

OpenKube must not persist credentials, create temporary or memory-backed credential-file copies to satisfy a path API, rewrite kubeconfig, or activate embedded-data materialization. Necessary bounded transient in-memory processing is permitted. Files/paths and authentication material remain transport-only and absent from logs/reports. Release references promptly, but Python/OpenSSL copies cannot be guaranteed zeroized; OS swap/crash capture remain outside this protection. Do not add pyOpenSSL or cryptography as direct project dependencies for this design. Synchronous file/native parsing follows the explicit D2 setup non-guarantee; no Python timer is represented as native cancellation.

## D6 — Fixed API-server base path

Permit a validated fixed HTTPS base-path prefix from the selected trusted kubeconfig endpoint. Do not assume the API server is at URL path `/`. Append only the fixed approved namespaced inventory paths beneath that prefix; preserve the origin, original hostname/port and prefix. Do not use a URL-join operation that silently discards the prefix when given a leading slash.

Reject userinfo, query, fragment, redirects, origin changes, insecure TLS, dot-segment traversal and ambiguous encoded path separators. Percent-encoding/path validation must reject ambiguity rather than silently change the selected endpoint. Test prefix preservation, trailing prefix separators, escapes and traversal before acceptance of the adapter; this does not establish trailing-dot hostname support. M4 will reuse the transport for the fixed PodMetrics path. No arbitrary URL fetching, API discovery, reverse-proxy administration, or transport-proxy support is introduced.

## Kubeconfig and authentication boundary

Read exactly one trusted kubeconfig file: explicit path or the existing `~/.kube/config` default, with exactly one explicitly selected context. No `KUBECONFIG` merging/selection, `current-context` fallback, implicit namespace, or in-cluster fallback. Preflight the selected context, cluster and user, their references, endpoint and authentication settings before activating client authentication machinery. Parse unused entries safely but never invoke their authentication settings.

Construct fresh explicit SDK `Configuration` and `ApiClient` instances; no global default configuration or unreviewed generic kubeconfig loader side effects. Initially allow only an externally obtained selected `user.token`, or existing file-based client certificate plus key, with exactly one unambiguous mechanism. Require explicit CA trust, HTTPS and hostname verification. Do not fall back to a system trust store or another mechanism. No refresh hooks, token creation, external helper execution or authentication prompts during analysis.

Reject excluded selected settings before helper execution or API calls: exec/provider helpers, legacy auth-provider, automatic OIDC/cloud refresh, browser/MFA/interactive authentication, encrypted-key prompts, tokenFile rotation, embedded CA/certificate/key data, transport proxies, TLS server-name override, basic/anonymous authentication, impersonation, in-cluster fallback and insecure TLS. Disable inherited proxy behavior and SDK debug/body logging. TLS key logging must remain off, including environment-triggered `SSLKEYLOGFILE`; Python's convenience TLS-context factory can otherwise enable it. This exclusion follows the credential-persistence boundary and was not tested by the transport probe.

The initial auth restriction is a validation boundary, not a permanent architectural prohibition on future exec/provider-integrated authentication. A future reviewed auth adapter may produce transport-only credentials with explicit acquisition/refresh deadlines, cancellation, persistence and egress controls. Discovery/projection/analysis remain provider-neutral; do not prebuild that adapter or add cloud SDKs now. Authentication compatibility, API compatibility, RBAC compatibility, Metrics API availability and platform-specific integration are separate validation dimensions.

## Recorded feasibility evidence

The 2026-09-30 Ubuntu probe used Ubuntu 24.04.5 LTS x86_64, kernel `6.8.0-142-generic`, systemd/resolved package `255.4-1ubuntu8.17`, isolated CPython 3.13.15, Kubernetes client 36.0.3 and h11 0.16.0. System Python 3.12.3 was unchanged. `systemd-networkd` was active, NSS was `hosts: files dns`, `libnss-resolve` was absent, and `/etc/resolv.conf` pointed to resolved's stub with `localdomain` search. One DNS-bearing link was observed; no VPN/split-DNS result was established. No resolver configuration changed. Transport HTTP/TLS endpoints were loopback fixtures; DNS comparison and temporary package downloads used the existing network. No Kubernetes cluster was contacted.

| Evidence | Observed result / scope |
| --- | --- |
| Ordinary NSS versus direct Varlink | Existing host entries matched in tested cases; `localhost` differed in address set, `localhost.localdomain` in order. Tracing showed NSS suffixing a multi-label negative name with `.localdomain`; native lookup did not provide that fallback. A trailing-dot DNS comparison suppressed NSS search, but did not test trailing-dot TLS endpoints. |
| Private addresses / IPv6 | Native gateway lookup returned a private address; loopback IPv6 and IPv4-failure-to-IPv6-success worked. This is not validation of private API servers or IPv6 link-local endpoints. |
| Real resolver deadline | A stalled lookup returned in 0.151167 s for a 0.150 s deadline; the client socket closed and descriptor/thread counts returned to baseline. No direct daemon-abort observation. |
| Synthetic resolver faults | Stalled/partial replies returned in 0.150562/0.151028 s; peers observed client closure. Oversize, malformed/duplicate/deep JSON, excess addresses, service errors/disconnect and absent socket were rejected. |
| Shared transport budget | TLS/header/body/slow-drip stalls returned in 0.150464–0.151188 s for 0.150 s. Synthetic resolver delay followed by stalled TLS returned in 0.150974 s total. Saturated TCP connect enforced 5 s; a body stall enforced the actual 15 s attempt budget. Scheduling overhead is visible, not hidden. |
| Response safety | Plain/chunked/gzip/concatenated-gzip successes; decoded cap and oversize rejection; truncated gzip and oversized metadata rejection; error-body canary exclusion. Encoded-input counter existed but its maximum was not independently crossed. |
| SDK boundary | Generated namespaced Pod/Deployment/ReplicaSet/PodMetrics methods reached the controlled loopback transport; guards recorded zero stock REST, generated deserializer and SDK exception-constructor calls. `last_response` cleared. No real Kubernetes payload projection/auth/RBAC was tested. |
| Cleanup | Four descriptors, one native thread and one Python thread before/after cases; synthetic server threads joined; no probe process/socket remained. No abandoned OpenKube-owned work. |
| Assertions | Sixteen explicit result assertions passed. This is not a claim that every D4 value, local input, error path or production implementation was tested. |

Earlier macOS probes showed that timeout parameters/abandoning a wait are insufficient for a blocking native resolver, and that generated dispatch can be intercepted before unsafe REST error consumption. Native/asynchronous resolver alternatives did not establish a portable complete deadline path. That prior evidence motivated the Ubuntu-specific boundary; it does not impose macOS transport work or override the newer Ubuntu measurements.

Disposable evidence was retained outside the repository: Ubuntu `/tmp/openkube-d2-20260930/`; local `/private/tmp/openkube-d2-ubuntu-l19FxA/`, including retrieved `evidence/assertions.json`, `semantic-313.jsonl`, `dns-queries.json`, `probe-results.jsonl`, `extra-results.jsonl` and an artifact manifest. These temporary paths are provenance, not durable repository tests or portable links. No SSH private key was copied. No probe scripts, credential fixtures, environments or generated evidence are added by this ADR.

### Credential/TLS input evidence — 2026-09-30

The subsequent disposable Ubuntu gate used CPython 3.13.15 linked to OpenSSL 3.5.8. The system OpenSSL 3.0.13 command generated synthetic fixtures only; it was not the Python TLS backend. No dependencies were installed for this gate and no Kubernetes endpoint was contacted. Sixteen credential-input assertions passed, separately from the sixteen earlier transport assertions.

| Tested fact | Result and limitation |
| --- | --- |
| CA snapshot | Both ASCII PEM and DER `cadata` loaded after original-path replacement; `cafile` read the replacement instead. PEM bytes are interpreted as DER, not PEM text. Tracing showed no CA-path reopen, but did show native OpenSSL configuration-file access. |
| Public client-loading API | File objects/integer descriptors were rejected; byte arguments were interpreted as filenames, not in-memory keys. Source and traces confirm separate certificate/key native opens. |
| Pinned inode | Descriptor-backed loading survived pathname replacement. It did not prevent in-place truncation/growth. A certificate inspected at 1,131 bytes grew to 2,098,283 bytes; tracing confirmed OpenSSL consumed the larger file and accepted it. This is evidence for the stability assumption, not prevention of that race. |
| Noninteractive rejection | Encrypted PKCS#8 and traditional PEM keys invoked the rejecting callback and failed without prompting; an unencrypted key loaded without invoking it. The default interactive path was not executed. |
| Input guards | Trusted symlink acceptance, nonregular-file rejection, oversize rejection and a 1,048,577-byte overflow read were exercised. The production opening sequence, complete formats and all races remain unvalidated. |
| Native parsing | A 1,048,437-byte repeated-certificate bundle took approximately 40 ms for CA loading and 39 ms for client-chain loading. A 1 ms Python alarm was delivered only after approximately 38 ms of native parsing. This does not demonstrate a 30-second budget breach or establish worst-case CPU/memory bounds. |
| Cleanup and exposure | Four descriptors and one native thread before/after; stderr empty; trace read buffers represented as pointers/counts, not credential content. Memory high-water measurements are not an isolated or hard RSS bound. |

Credential evidence remains outside the repository at Ubuntu `/tmp/openkube-tls-input-T7EbC6/` and local `/private/tmp/openkube-tls-input-tLcmAa/` (scripts and sanitized evidence only locally). Synthetic credential fixtures were not copied to the development host; no operator private-key material was inspected/copied. These are disposable provenance paths, not portable tests or claims of client-certificate Kubernetes authentication. D5 and the D2 setup amendment record the user's reviewed resolution of the limitations they demonstrated.

## Dependencies, alternatives and maintenance

**kubernetes==36.0.3** is the intended initial official SDK dependency for M3. **h11==0.16.0** is approved as the initial HTTP/1.1 framing dependency for the controlled transport. Add either only with separate implementation authorization; neither is currently a project runtime dependency. pyOpenSSL is not required; cryptography is not a direct project dependency for this design. The transport bypasses urllib3 network I/O rather than treating urllib3 timeouts as a complete deadline guarantee. Existing locking/security review requirements apply to all direct/transitive packages; the project's dependency list and lock remain unchanged. Exact pins do not establish implementation correctness or a security-support guarantee.

Rejected alternatives include blocking `getaddrinfo` with an outer timer, executor resolution whose worker continues, subprocess isolation, public DNS replacement, numeric-only API URLs, and a universal OS resolver layer. They fail the reviewed cancellation, system-policy or scope constraints. h11 supplies framing rather than a custom HTTP parser. An internally asynchronous network stack is not needed for the demonstrated synchronous design.

For credentials, ordinary pathname reopening retains replacement races; descriptor-backed paths remove that identity race under the accepted stability assumption. pyOpenSSL/cryptography can offer in-memory certificate/key APIs but would introduce a different TLS integration and do not establish hard cancellation of native parsing. That extra backend is not required by the approved trusted-file model. Temporary/memory-backed credential copies and private SSL-pointer/native-binding hacks are not the selected solution.

The cost is a Linux/resolved/procfs-specific I/O adapter with explicit socket/TLS ownership, strict parser guards, h11 maintenance, and tests against pinned SDK behavior. The proof does not justify copying disposable probe code directly into the application or adding a generic transport/plugin framework.

## Initial profile, future targets and non-guarantees

Ubuntu 24.04 LTS x86_64 under the specified resolver/endpoint/auth profile is the initial priority runtime validation target. macOS is a development environment, not a v0.1 runtime transport support obligation. Windows, other Linux distributions, custom resolver profiles, ARM64, network filesystems and containerized OpenKube execution remain outside initial runtime validation. No generic Ubuntu/Linux compatibility claim follows from this one VM.

Upstream Kubernetes, EKS, AKS, OpenShift, ROSA and ARO are long-term platform validation targets. A working Ubuntu transport does not validate their API versions, authentication, RBAC or Metrics API availability. Keep discovery/projection/analysis provider-neutral; platform-specific code needs a future demonstrated requirement and reviewed decision. Future auth integrations belong outside the core.

OpenKube does not promise NSS equivalence, search fallback, daemon hard-real-time cancellation, instantaneous cancellation of shared DNS work, control of other resolver clients, hard mid-call cancellation of trusted local-file/native TLS setup, immutable credential contents during in-place mutation, arbitrary local filesystem robustness, secure memory erasure, a hard process RSS cap, immunity to DNS rebinding, or protection against compromised local root/trusted resolver/control plane. TLS stays tied to the original host and explicit CA trust; resolver trust is not a substitute for TLS. Existing sensitive-report, UID, read-only, no-telemetry and human-review boundaries remain unchanged.

## Acceptance and remaining implementation validation

Final review against ADRs 0001–0007, architecture, compatibility, CLI, data/egress, evidence, recommendations, security/threat model, repository structure, roadmap and domain model found no unresolved architecture decision after applying the user's final approvals. D1/D3 refine the adapter boundary without changing permissions/domain/evidence semantics; D2/D5 explicitly qualify setup/daemon cancellation; D4 preserves existing numeric limits and the closed report schema; D6 fixes endpoint construction. ADR 0008 is Accepted on 2026-09-30. The credential-loading design blocker is closed under the approved stable-file assumption and native-setup non-guarantee, not by claiming the old stronger guarantee was proven.

The user separately authorized the documentation consistency pass after final ADR review; it is complete and the index records acceptance. See the dated administrative update below. Implementation and dependency addition still require separate authorization. M3 is Pods/Deployments/ReplicaSets inventory; M4 owns PodMetrics. No source, RBAC manifest, dependency, or cluster work is authorized by acceptance.

Implementation acceptance must cover every initial guard at/either side of its boundary; strict YAML/JSON types/duplicates/depth; selected-context preflight and rejected auth modes; trusted-file/symlink/overflow/descriptor cleanup and noninteractive TLS loading; no original CA-path reread or credential copies; expired setup-budget handling without claiming native preemption; proxy/keylog/environment rejection; original-name TLS/base paths; socket trust/replacement, IPv6 scope and bounded fallback; error/body/UID canaries and raw-reference lifetime; mandatory structure versus representable uncertainty; pagination/count/retained-memory enforcement; full explicit retry and enclosing run/cycle budgets; and restricted-identity inventory/RBAC integration. These are future tests, not permission to contact a cluster now.

Successful private endpoint, VPN/split-DNS and multi-link tests are required before claiming those profiles validated. The source-supported daemon-abort boundary is explicitly limited as approved; direct daemon instrumentation is useful future evidence, not a new hard-real-time guarantee. Retest the client-owned cleanup requirement against implementation, not only the disposable probe. M4 adds metrics integration/evidence checks; M6 retains reporting/output-filesystem acceptance.

The earlier D2 result was NOT YET PROVEN against the unqualified contract. The user has now explicitly accepted the constrained resolver semantics, owned-resource cancellation boundary and trusted local-input/native setup qualification. This resolves the design decision; disposable feasibility is not an implemented control, runtime-support claim or proof of all remaining authentication/integration cases.

## Documentation consistency plan

**Administrative update — 2026-09-30:** the user separately authorized and this pass completed the documentation plan below after final ADR acceptance. The table preserves the acceptance review's follow-up checklist, now applied where needed; ADR 0006 needed no additional cross-reference. The index records Accepted / 2026-09-30, historical ADRs have append-only clarifications, and the [consistency ledger](../consistency-review.md#milestone-3-accepted-design-and-consistency--2026-09-30) records completion. No D1–D6 technical decision or implementation authorization changes.

| Document | Consistency amendment checklist (completed where applicable) |
| --- | --- |
| [README](../../README.md) | Distinguish M3 design/feasibility authorization from implementation, link the reviewed transport/profile, preserve no-runtime-support wording. |
| [AGENTS.md](../../AGENTS.md) | Concise updated gate and links to authoritative transport/compatibility contracts; M3 inventory versus M4 metrics; no duplicated constants or broad implementation authorization. |
| [Architecture](../architecture.md) | Refine official-client usage to controlled wire handling; explain resolved/endpoint/cancellation boundary and D3 namespace failure; distinguish complete-v0.1 four-resource flow from M3's three inventory resources. Qualify total-run boundedness with D2 setup accounting/non-preemption and link D5 stability rather than claiming unconditional cancellation. |
| [Compatibility](../compatibility.md) | Record Ubuntu priority with active trusted resolved Varlink and descriptor-backed procfs loading, NSS differences/endpoint syntax, macOS development-only status, and future platform/auth targets. Replace “no SDK integration tested” / “No local validation yet” with exact disposable dispatch/transport/credential evidence, not cluster/auth support. Keep APFS as development evidence only, not a v0.1 runtime obligation; validate Ubuntu output filesystems in M6. Add stable credentials and noninteractive encrypted-key rejection. Move four-endpoint M3 validation to inventory in M3 and PodMetrics in M4. |
| [CLI contract](../cli-contract.md) | Add a dated D2 amendment beside “includes every operation/backoff/write”: setup consumes existing auth/run budgets, but regular-file/native parsing calls are not hard-cancellable; stop when control returns if expired. Preserve numeric budgets, ten inputs, six exits and exact report-limit keys. Link implementation-only parser/input/transport guards without adding them to the operational report table. Add credential/output symlink distinction, fixed base paths and existing-code preflight/loading failures. |
| [Data and egress](../data-and-egress.md) | Clarify bounded raw-wire parsing versus generated deserialization, D3 mandatory structure, native resolved egress and excluded helpers/proxies. Preserve exact field/UID/report allowlists; explicitly exclude new implementation guards from `configuration.limits`. Link setup non-guarantees where total execution is described; no credential copies, raw error propagation or new report fields. |
| [Security](../security.md) | Add trusted stable regular credentials/symlinks, bounded CA snapshot, descriptor-backed client rereads/in-place mutation risk, rejecting password callback, cleanup/zeroization limits and the native setup non-guarantee. Add socket trust, original-host identity and keylog/proxy rejection. Label three M3 inventory grants and later M4 metrics grant without changing final v0.1 RBAC. Clarify helper discussions concern future profiles. |
| [Threat model](../threat-model.md) | Add NSS semantic substitution, socket replacement, native blocking setup, credential pathname versus in-place mutation, parser expansion and SDK error-body hazards. Distinguish guarded inputs from hard native cancellation, and required controls from probe evidence and untested mitigations. |
| [Repository structure](../repository-structure.md) | Correct `collection/kubernetes.py` “four fixed namespaced list endpoints”: three inventory endpoints in M3; `metrics/metrics_api.py` owns PodMetrics in M4 using the shared controlled transport. Describe adapter boundaries only when implementation scope is approved; no speculative files. |
| [Roadmap](../roadmap.md) | Record accepted design and separate implementation authorization; M3 inventory/preflight/projection/ownership and credential/transport tests, M4 metrics. Replace macOS-centric runtime validation assumption with Ubuntu priority; keep cluster setup separately authorized and do not choose a new cluster tool through this amendment. |
| [Development](../development.md) | Add Ubuntu transport/credential feasibility provenance separately from historical foundation/domain checks; distinguish disposable SDK/h11 installations from empty project runtime dependencies. Record intended SDK and approved h11 pins without installing them; revise current M3 status and macOS-runtime implications, not historical results. |
| [Consistency review](../consistency-review.md) | Append a dated M3 amendment with these decision IDs distinct from original D1–D3; preserve the original freeze and historical status. Record accepted D2/D5 non-guarantees, closed credential design blocker, D4 classification, unchanged report schema and separate implementation gate. |
| [Domain model](../domain-model.md) | Update current authorization wording and clarify the projection-boundary link for malformed mandatory structure versus representable field/ownership uncertainty; leave records, quantities and M2 acceptance unchanged. |
| [ADR index](README.md) | Updated 0008 to Accepted / 2026-09-30; replaced pending D4/report/h11/credential decisions with the accepted distinctions and separate implementation gate. The index update is complete; no unresolved acceptance decision remains. |
| [ADR 0001](0001-read-only-cli.md) | Later dated cross-reference: official client can supply generated dispatch while its stock network/deserializer path is bypassed. Single synchronous process, inputs and permissions are unchanged. |
| [ADR 0003](0003-access-and-data-boundary.md) | Later dated cross-reference: controlled bounded wire projection and preventing body-bearing SDK exceptions refine sanitization; transient raw permission is not a mandate for full SDK model construction. Four-resource v0.1 RBAC is staged M3/M4, not superseded. |
| [ADR 0004](0004-identity-and-domain-model.md) | Later dated cross-reference: unprojectable mandatory structure invalidates namespace inventory; well-formed unresolved/unsupported ownership remains representable. UID-based identity and evidence remain unchanged. |
| [ADR 0005](0005-cli-and-report-contract.md) | Append a dated cross-reference to the explicit setup/native-parser and external-daemon cancellation qualifications; preserve the original text and numeric budgets. Clarify that “report effective constants” refers to the closed existing report contract, not all new implementation guards. No schema change. |
| [ADR 0006](0006-python-project-foundation.md) | Preserve historical foundation/reference selection; if adding a current cross-reference, distinguish later Ubuntu priority and separately authorized dependencies from foundation results. No rewrite of its accepted toolchain decision. |

ADRs [0002](0002-metrics-and-evidence.md) and [0007](0007-explicit-container-started.md) and [recommendations](../recommendations.md) require no technical change: startup, timing, utilization methodology and conservative findings remain authoritative. [Evidence eligibility](../evidence-eligibility.md#one-observation-timeline) needs only a cross-reference to D2 beside the pre-authentication total-run timer: setup elapsed remains counted, native setup is not hard-preemptible, and setup never contributes observations. No sample, coverage, startup, baseline, slot or closure value changes. M4 placement is not a change to metric semantics. Historical authority/status language in accepted ADRs is not a current authorization and must not be erased.

The substantive conflict with the previous unqualified bounded-execution wording is explicitly resolved by D2's dated amendment, not described as proof of the old guarantee. The broad reading of ADR 0005's “report effective constants” is resolved by preserving its linked closed allowlist while keeping new guards implementation-only. ADRs 0001/0003/0004 need explanatory cross-references, not different SDK/permission/UID/domain decisions. ADR 0006's historical empty-dependency foundation remains accurate; future SDK/h11 additions require separate authorization. No technical conflict was found with ADRs 0002 or 0007. The later expressly authorized consistency pass is recorded above; this technical review itself did not authorize those edits.

## Upstream sources

- [systemd v255 resolved Varlink implementation](https://github.com/systemd/systemd/blob/v255/src/resolve/resolved-varlink.c): disconnect handler, query completion and interface behavior; source evidence is distinct from runtime daemon observation.
- [systemd v255 resolver semantics](https://github.com/systemd/systemd/blob/v255/man/systemd-resolved.service.xml): native versus traditional glibc search behavior, hosts handling and per-link routing.
- [Kubernetes client 36.0.3 ApiClient](https://github.com/kubernetes-client/python/blob/v36.0.3/kubernetes/client/api_client.py), [REST implementation](https://github.com/kubernetes-client/python/blob/v36.0.3/kubernetes/client/rest.py), and [exceptions](https://github.com/kubernetes-client/python/blob/v36.0.3/kubernetes/client/exceptions.py): generated dispatch, response retention and unsafe body-bearing exception path.
- [Python 3.13 SSL API](https://docs.python.org/3.13/library/ssl.html): nonblocking TLS operations, file-based client certificate loading, and convenience-context keylog environment behavior.
- [CPython 3.13.15 SSL source](https://github.com/python/cpython/blob/v3.13.15/Modules/_ssl.c): CA memory loading, certificate/key path opens, callback handling and native parsing boundary.
- [Python signal execution](https://docs.python.org/3.13/library/signal.html#execution-of-python-signal-handlers): Python handlers may be delayed by native code; not native mid-call cancellation.
- [Linux descriptor paths](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html) and [open semantics](https://man7.org/linux/man-pages/man2/open.2.html): descriptor-backed file identity and regular-file nonblocking limitations.
- [OpenSSL PEM callbacks](https://docs.openssl.org/3.5/man3/PEM_read_bio_PrivateKey/): default password callback behavior; use explicit noninteractive rejection.
- [h11 API](https://h11.readthedocs.io/en/stable/api.html): HTTP/1.1 framing events separated from network I/O; version 0.16.0 approved for later authorized implementation, not installed in the project.

Accepted on 2026-09-30 after the expressly authorized final design review. No implementation, dependency addition, broader consistency edit, RBAC creation, Kubernetes/minikube contact, staging, commit or push is authorized by this acceptance.
