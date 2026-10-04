# v0.1 CLI and acceptance contract

Status: **Accepted architecture contract — frozen on 2026-09-28; not implemented.** No CLI or JSON schema artifact exists yet. This document defines its acceptance criteria; [ADR 0005](adr/0005-cli-and-report-contract.md) records the decision. Numeric defaults/caps are fixed engineering limits to validate, not measured capacity guarantees. Milestone 1 is complete and committed; the authorized [Milestone 2 domain model](domain-model.md) is complete and accepted on 2026-09-29. AnalysisSettings is explicitly deferred and the ten-input contract is unchanged. Milestone 3 architecture/design is complete under Accepted [ADR 0008](adr/0008-restricted-kubeconfig-and-bounded-transport.md), dated 2026-09-30; M3.1 and restricted kubeconfig document loading (M3.2A) are implemented; selection, authentication and all later behavior require separate authorization.

## Invocation and scope

The analysis command requires an explicit kubeconfig context and at least one explicit namespace; a trusted kubeconfig path may be supplied. Repeated namespace arguments form a deduplicated ordered list. No implicit current-context/current-namespace selection, namespace discovery, wildcard/all-namespaces option, or in-cluster fallback. Reject invalid names or unknown arguments before network access. Help/version commands perform no network I/O.

Default mode is one snapshot. Observation mode requires an explicit choice; its default duration is 30 minutes. Reports default to terminal format on stdout; JSON is selectable. An explicit output path sends the report only to that file. Sanitized operational diagnostics go to stderr, never mixed into JSON. No automatic report persistence or resume/history feature.

## Complete configuration surface

This table is the entire accepted v0.1 analysis configuration. Names are conceptual contract keys, not implemented flags. No configuration-file format, OpenKube-specific environment overrides, presets, plugin settings, rule toggles, endpoint overrides, debug-body logging, or authentication-mode switch is included. Reject unknown keys. Help/version are local informational commands, not analysis configuration.

**D1 approved on 2026-09-28:** only these ten inputs are configurable; eligibility and safety limits are fixed, versioned policy constants. This replaces the earlier draft's lowerable caps/tightenable knobs. Add configuration only if implementation demonstrates a concrete requirement that cannot reasonably fit the existing contract, with a documented review before changing the freeze. See the [resolved decisions](consistency-review.md#resolved-decisions-and-acceptance).

| Name | Type | Required / default | Allowed values | Security implications | May appear in reports? |
| --- | --- | --- | --- | --- | --- |
| `context` | String | Required; no default | Nonempty exact context name present in the selected trusted kubeconfig; no implicit current-context | Selects cluster and identity; never switch/fallback | No; not even the alias |
| `namespaces` | List of strings | Required; no default | 1–10 distinct explicit namespace names; DNS-label syntax, 1–63 lowercase alphanumeric/hyphen characters, alphanumeric ends; deduplicate preserving order | Defines maximum collection scope; no wildcards/discovery; names may be sensitive | Yes, only under `scope` and allowed subject/source/error records; reports are potentially sensitive |
| `kubeconfig` | Local path or null | Optional; null resolves to the current user's `~/.kube/config` | One existing readable trusted file; no URLs or multi-file merging | Executable credential configuration; client credentials stay transport-only; OpenKube does not rewrite it | No |
| `mode` | Enum | Optional; `snapshot` | `snapshot`, `observation` | Observation increases bounded read traffic; neither permits writes | Yes, `run.mode` |
| `observation_seconds` | Integer | Optional; `1800` in observation, null in snapshot | Observation: 1800–3600 inclusive, multiple of 60; supplying it in snapshot is a configuration error | Bounds collection/retention time; early termination never qualifies as a shorter complete run | Yes, planned duration |
| `output_format` | Enum | Optional; `terminal` | `terminal`, `json` | Both obey the same closed data allowlist and escaping rules | No; presentation setting only |
| `output_path` | Local path or null | Optional; null means stdout | New regular-file destination in existing directory; no symlink components, existing target, devices/FIFOs/sockets, or URL | Persistence only on explicit request; `0600`, atomic no-replace; stdout capture is external | No |
| `cpu_overprovisioning_ratio` | Exact decimal | Optional; `0.30` | `0 < value < 1` | Changes hypothesis threshold, never evidence gates or scope | Yes, effective rules and matching findings |
| `memory_overprovisioning_ratio` | Exact decimal | Optional; `0.30` | `0 < value < 1` | Same as CPU ratio | Yes, effective rules and matching findings |
| `memory_limit_headroom_ratio` | Exact decimal | Optional; `0.90` | `0 < value <= 1` | Investigation threshold, never a safe limit or OOM guarantee | Yes, effective rules and matching findings |

Reject non-finite values, fractions for integer inputs, and decimal input longer than 128 characters. Explicit input overrides the documented default; there is no other OpenKube precedence layer. The three ratios may be supplied in either mode; overprovisioning rules remain inapplicable in snapshot mode.

Kubeconfig authentication and certificate files are external client inputs, not additional OpenKube configuration fields. Do not use `KUBECONFIG` to merge or select files; the path above is authoritative. The [approved reference-target profile](compatibility.md#planned-authentication-profile) selects two authentication forms for future validation and excludes helpers/proxies from the initial profile. This is not established runtime support. Reject excluded settings before client authentication or network access, without fallback, using configuration error/2. TLS verification is mandatory. No token/password/URL/proxy command-line overrides. The [egress contract](data-and-egress.md#potential-indirect-network-communication) records helper/proxy trust boundaries, not permission to enable unvalidated workflows.

### Accepted connectivity and credential amendment — 2026-09-30

Follow [ADR 0008 D2/D5/D6](adr/0008-restricted-kubeconfig-and-bounded-transport.md) and the [initial runtime/endpoint profile](compatibility.md#initial-runtime-and-endpoint-profile): Ubuntu resolved Varlink, explicit multi-label absolute hostname without search/single-label/custom NSS fallback, bounded address attempts and original-host TLS/SNI/HTTP authority. Private answers are allowed; preserve the validated HTTPS base path. No NSS-equivalence claim or additional endpoint input.

Trusted regular credential files may use approved symlinks, unlike output destinations. Boundedly inspect stable files with overflow detection; CA loads from a certificate-only memory snapshot, while retained certificate/key descriptors supply `/proc/self/fd` paths for native rereads. No original CA-path reopen, credential copies or persistence. Always reject encrypted keys through a noninteractive callback; no prompt/password/environment/helper fallback. Configuration rejection uses existing exit 2; native TLS loading failure uses sanitized TLS_FAILED/3, without raw paths, contents or exception chains. D5 states the in-place mutation and zeroization limitations.

## Exit codes and report status

| Exit | Report `run.status` | Meaning |
| --- | --- | --- |
| `0` | `complete` | Required source collection succeeded and each applicable subject/resource/rule had enough evidence to evaluate, whether or not it triggered. Declared unsupported/inapplicable rules can be skipped. Help/version also return 0 without a report. |
| `2` | No analysis report | Invalid arguments/configuration, missing explicit scope, unsupported mode/bounds, or rejected TLS configuration. |
| `3` | `failed` | Authentication/TLS failure, no complete namespace inventory, or unexpected internal failure. Emit a sanitized failure report where safely possible; never a raw traceback. |
| `4` | `incomplete` | Usable inventory exists but at least one requested namespace/source failed, an otherwise supported subject lacks required evidence, or a deadline/collection cap stopped work. Valid supported findings may remain. |
| `5` | No successfully delivered report | Output validation, serialization, size, or write failure, including broken pipe. Never claim a saved report succeeded. |
| `130` | `interrupted`, if safely possible | Operator interruption. Stop collection, keep a bounded best-effort report, and suppress whole-run overprovisioning. |

**D2 approved on 2026-09-28:** internal errors use failure exit 3. The only exits are success (0), invalid configuration (2), failure (3), incomplete (4), output delivery failure (5), and interruption (130). Do not introduce additional exit codes without a future documented reason and contract review.

Configuration rejection 2 occurs before analysis; it emits only a sanitized diagnostic. For an analysis that started, determine `run.status` in this order: internal/authentication/TLS fatal error → failed; operator interruption → interrupted; no usable inventory → failed; source/limit/evidence shortfall → incomplete; otherwise complete. A failure report can retain trustworthy earlier findings. Derive exit 3/130/4/0 from that status. If delivery fails, exit 5 overrides that exit; it does not rewrite the analysis status in any partially delivered bytes. If an internal failure makes safe serialization impossible, return 3 with only the fixed diagnostic. A failure while attempting delivery still returns 5.

“Complete” means complete within the declared mode/support boundary, never healthy, optimized, or safe to resize. An empty successfully inventoried namespace is valid and needs no usage sample. Unsupported owners/container semantics are explicit exclusions, not source failures; malformed data, missing lifecycle fields for otherwise supported subjects, or missing expected metrics make the affected analysis incomplete. Snapshot intentionally omits overprovisioning and is not incomplete for that reason. A zero request suppresses ratio rules with a reason but is not itself a collection failure.

## Partial-success semantics

M3 inventory requires successful, bounded lists of Pods, ReplicaSets, and Deployments. M4 adds PodMetrics. Under ADR 0008 D3, unprojectable mandatory identity/ownership or list structure invalidates that namespace pass; never silently drop an object and claim completeness. Well-formed unresolved/unsupported ownership and representable non-identity field uncertainty retain their existing states. A complete namespace inventory requires all three inventory lists. If any inventory list fails or is truncated, discard that cycle's incomplete projected inventory for analysis; report the namespace failure. Completed inventories in other explicitly requested namespaces can still be used. An unavailable Metrics API yields inventory-only findings and exit 4 when inventory is usable. Authorization denials never cause retries or scope expansion.

| Condition | Required outcome |
| --- | --- |
| Sufficient evidence, no finding or one/many findings | Complete/0; findings are not process errors. |
| Supported subject lacks required evidence (startup, insufficient coverage, instability, missing lifecycle/metrics) | Incomplete/4 when inventory exists; affected rules abstain, other justified findings survive. |
| Known unsupported owner/resource semantics, snapshot overprovisioning, absent/zero ratio denominator | Explicit inapplicable/unsupported skip; by itself does not make the run incomplete. Malformed or unknown required semantics remain an evidence shortfall. |
| HTTP 401 or credential acquisition/refresh failure | Abort further network calls; failed/3 even with earlier inventory. |
| HTTP 403 on an inventory endpoint | That namespace cycle fails; continue other explicitly selected namespaces. Some usable inventory → incomplete/4; none → failed/3. |
| HTTP 403/404 on Metrics API or missing metrics provider | Inventory can support configuration findings; incomplete/4. Do not conflate metrics denial with invalid credentials. |
| Timeout, connection failure, persistent 429/5xx, inventory 404 | Retry only within policy; after exhaustion, some usable inventory → incomplete/4; none → failed/3. No credential/scope fallback. |
| Invalid context/path/namespace/mode/threshold or insecure configured TLS | Configuration error/2 before API calls. A valid configuration whose TLS handshake fails is failed/3. Invalid/unsafe output destinations use output error/5, even if detected before collection. |
| All selected namespaces successfully read and empty | Complete/0; no expected PodMetrics, so no metrics request is necessary. Known unsupported-only namespaces also require no usage samples. |

Record source failures even if later retries/cycles recover; a source marked partial or failed makes the run incomplete. Subject-level rejected/duplicate slots within the permitted coverage/gap budget do not by themselves make a run incomplete if all applicable rules remain evaluable. A read outage is a source failure; a rejected sample is an evidence event. Never suppress either in reporting.

An observed restart/rollout/allocation change or insufficient observation coverage causes utilization abstention as defined in the [evidence contract](evidence-eligibility.md). Keep configuration findings and independently valid snapshot findings. Record requested/completed/failed namespaces, per-source availability, per-rule abstention reasons, counters, actual observation interval, and termination cause. No silent omission, filling missing values with zero, or downward revision of the scheduled denominator.

## JSON schema and error strategy

Initial report schema version is `1.0.0`, independent of tool version. Use semantic versions: major for removed/renamed fields, changed types/units/meaning, or changed closed-enum meanings; minor for reviewed additive optional fields; patch for clarifications that do not change accepted instances or semantics. A new consumer-visible enum value requires a major change unless the original schema explicitly defined an extensible string. Readers must reject unsupported major versions and tolerate unknown optional fields for supported majors; the writer must still obey the exact current allowlist. Every field addition requires data/security review.

Publish the machine-readable schema with the reporting implementation, validate reports against the pinned schema, and maintain synthetic golden reports for complete/incomplete/failed/interrupted runs. Do not create schema artifacts or application models in this documentation milestone. The [report contract](data-and-egress.md#data-openkube-may-write-to-reports) is the single authority for all root/nested fields, types, nulls, and counters. Initial schema `1.0.0` is frozen as an unpublished implementation contract, not a claim of a released artifact. D3 excludes all Kubernetes UIDs from every output form, including temporary reports.

Initial fixed diagnostic/error codes: `AUTHENTICATION_FAILED`, `TLS_FAILED`, `CONNECTION_FAILED`, `ACCESS_DENIED`, `INVENTORY_UNAVAILABLE`, `METRICS_UNAVAILABLE`, `REQUEST_TIMEOUT`, `DEADLINE_EXCEEDED`, `LIMIT_EXCEEDED`, `MALFORMED_DATA`, `CONFIGURATION_INVALID`, `OUTPUT_FAILED`, `INTERNAL_ERROR`, `INTERRUPTED`. `ACCESS_DENIED` applies to either inventory or metrics; resource/stage fields distinguish them. `CONFIGURATION_INVALID`/`OUTPUT_FAILED` may exist only as stderr diagnostics when no report is delivered. No API/SDK message copying. Closed abstention/quality codes are defined in the evidence contract.

Each finding records its rule ID/version, actual threshold (null for non-threshold rules), comparison, and evidence. Root `configuration` records effective rules and evidence/operational policy values, never the raw invocation or credential configuration. Rule versions track algorithm/default changes; changing a configured threshold does not fabricate a new rule version.

## Operational limits and timeouts

Under approved D1, the following are fixed internal safety constants or mode-derived values, not CLI options or lowerable per-run overrides. Types are positive integers; byte values use integer bytes in reports (1 MiB = 1,048,576 bytes). All table keys belong to `configuration.limits`, along with the six explicitly named setup/parser keys below. Configurable observation duration belongs to `run`; fixed polling belongs to `configuration.evidence`. These non-identifying policy values are all reportable; they bound API load, exposure, parsing, memory retention, or delivery rather than expanding permissions. Bounds apply to the entire run unless stated. Changing constants requires policy/documentation review.

| Key | Default / hard ceiling | On exhaustion |
| --- | --- | --- |
| `max_namespaces` | 10 / 10 distinct namespaces | Reject over-limit input before network access. |
| `page_size` | 200 / 200 objects where pagination is supported | Follow tokens only within other bounds; never assume PodMetrics pagination is supported. |
| `max_pages_per_list` | 100 / 100 | Mark the list/cycle incomplete; discard it for analysis. |
| `max_inventory_objects` | 10,000 / 10,000 across a pass over the explicitly selected namespaces | Stop collecting; keep only previously completed namespace inventories. Never an all-namespaces endpoint. |
| `max_container_subjects` | 20,000 / 20,000 distinct Pod UID/container subjects during the run | Stop collection and report incomplete. |
| `max_response_bytes` | 16 MiB / 16 MiB decoded per response, including unpaginated metrics | Abort before an oversized body reaches SDK deserialization. |
| `max_samples` | 1,200,000 / 1,200,000 distinct subject/source-timestamp observation records, each holding up to two resource values | Stop collection and report incomplete; report per-resource slot counts separately. No disk spilling. |
| `max_domain_bytes` | 256 MiB / 256 MiB accounted retained domain/sample/report data | Stop collection, release sample detail, and report explicit resource exhaustion within the cap. This is not a Python process RSS guarantee. |
| `max_report_bytes` | 16 MiB / 16 MiB UTF-8 encoded output | Fail output with exit 5; never truncate findings or JSON to fit. |
| `connect_timeout_seconds` | 5 / 5 per connection attempt | Transient retry only within attempt/cycle/run bounds. |
| `request_timeout_seconds` | 15 / 15 absolute seconds per HTTP attempt, including body read | Abort stalled/slow-drip responses, not just idle sockets. |
| `auth_timeout_seconds` | 30 / 30 per credential acquisition/refresh/helper invocation | Abort; unsupported helper cancellation/bounding blocks support for that auth mode. |
| `max_attempts` | 3 / 3 per list-page request | Initial attempt plus at most two retries. |
| `collection_cycle_seconds` | 60 / 60 for one global slot across selected namespaces; snapshot has one such cycle | Each namespace's full bracket must finish before the same slot boundary; unfinished/unvisited subjects are missing. |
| `run_deadline_seconds` | Snapshot: 180; observation: configured observation duration + 180; maximum 3,780 | Cancel collection and finalize within reserved time; usable inventory gives exit 4, otherwise 3. |
| `finalization_seconds` | 15 / 15 reserved within run deadline | Bound serialization/output; exit 5 if a report cannot be delivered. |

The fixed `baseline_seconds` and `final_inventory_seconds` budgets are each 60 and are also required keys in `configuration.limits`. `baseline_seconds` applies only to observation setup; `final_inventory_seconds` applies to observation closure. Snapshot uses a single 60-second bracket cycle without separate baseline/final passes. The [evidence timeline](evidence-eligibility.md#one-observation-timeline) defines `t0`, slot boundaries, and final closure; initialization/finalization do not count toward observation duration or coverage.

The total monotonic clock starts before authentication and counts elapsed setup, operations, backoff and writes without resetting. The existing budgets remain authentication 30 seconds, observation baseline 60, duration D, final inventory 60 and finalization 15 within D + 180; snapshot remains 180 seconds. Stop collection by the total deadline minus the finalization reserve. The earliest active deadline wins; bound stdout/file writes too. Helpers and refresh are outside the initial authentication profile; their existing budget does not authorize them.

**Dated bounded-execution qualification, 2026-09-30:** Accepted [ADR 0008](adr/0008-restricted-kubeconfig-and-bounded-transport.md#bounded-execution-amendment--2026-09-30) explicitly qualifies the earlier “includes every operation/backoff/write” cancellation interpretation. Trusted local-file reads and native TLS-context construction are setup guarded by input size, parser/format checks, validation, cleanup and sanitized failures. OpenKube does not promise hard mid-call cancellation of executing synchronous file reads or OpenSSL parsing; a Python timer is not native cancellation. Setup consumes existing budgets and can overrun them before returning control. Check deadlines before/after setup and stop further authentication/transport work if expired. This is not an unconditional total wall-clock return guarantee across setup.

The unchanged 15-second attempt deadline begins with controlled Varlink resolution and covers all address attempts, TCP, TLS handshake and HTTP processing; each TCP candidate also has the five-second cap, shortened by earlier deadlines. No progress or address change resets it. Close/release owned controllable resources on cancellation and leave no OpenKube-owned resolver worker/task/process behind. Instantaneous systemd-resolved/shared-work cancellation is not guaranteed. Numeric limits, output safety and evidence timing are unchanged.

Retry connection resets, timeouts, HTTP 429, and transient HTTP 500/502/503/504 only. Backoff is 1 second then 2 seconds with at most 250 ms jitter, bounded by remaining deadlines. Honor a valid `Retry-After` only if it fits the remaining budget; otherwise report unavailable. Never retry 401/403, certificate validation failure, malformed data, or permanent 4xx responses. SDK implicit retries must not multiply this budget.

Quantity ceilings: 1,000,000 decimal CPU cores and 2^60 memory bytes per field; at most 128 characters per quantity and 1,024 UTF-8 bytes per retained identifier. These reject unreasonable inputs; they are not Kubernetes resource-sizing advice. Reject before expensive parsing. Implementation acceptance must demonstrate transport byte/deadline enforcement with the official client, including chunked/compressed responses; `Content-Length` or an object count after deserialization alone is insufficient. If the chosen client cannot enforce these controls, revise the adapter design before supporting collection.

The user-approved Milestone 2 normalization rounds valid nonnegative fractional memory upward after exact parsing, with the memory ceiling enforced on the result. CPU remains exact Decimal cores. The pure [quantity parser](domain-model.md#exact-quantity-conversion) bounds explicit exponent magnitude before expansion; this implementation guard adds no CLI input or report-limit key. Transport controls remain unimplemented.

These additional fixed parser limits are required `configuration.limits` keys: `max_cpu_cores` (decimal string `1000000`), `max_memory_bytes` (integer 1152921504606846976), `max_quantity_characters` (integer 128), `max_identifier_bytes` (integer 1024). They are not user inputs. Backoff constants are implementation policy described above, not a configurable retry framework.

### Additional implementation guards

[ADR 0008 D4](adr/0008-restricted-kubeconfig-and-bounded-transport.md#d4--local-input-and-wire-safety-limits) separates architectural boundedness requirements, previously frozen operational limits above, and versioned implementation guards such as local-file caps, parser nesting, Varlink framing/address caps and HTTP metadata/wire caps. The latter are defensive policy, not Kubernetes semantic limits, extra user inputs or report keys. The ten-input configuration, six exits and closed 18-group report schema remain unchanged; only the established `configuration.limits` allowlist is emitted. Guard values and boundary tests are versioned with implementation policy.

## Safe output-file behavior

Validate the requested destination before collection; perform final race-safe checks when publishing. Write only to a user-selected regular-file destination in an existing directory. Do not create parent directories, follow symlinks in any path component, write devices/FIFOs/sockets, or overwrite an existing destination. No force-overwrite option in v0.1. Use directory-handle-relative checks where supported; platforms without equivalent protections are unsupported until tested.

Serialize the complete bounded report before publication. Create a same-directory exclusive temporary file with permissions `0600`, write/flush it, and publish atomically with no replacement. Keep restrictive permissions, reject destination races, and remove the temporary file on failure/interruption when possible. Temporary files contain only allowlisted reports, never raw API data; they exist only when a file output was requested. Report a cleanup failure with a fixed diagnostic. A crash can leave a restrictive temporary report, so document operator cleanup/retention responsibility.

Stdout output is serialized before writing, but a broken pipe/interruption can still leave a partial byte stream at the receiver; return exit 5 and never label that delivery successful. External shell redirection controls permissions and persistence outside OpenKube. Do not echo destination paths or raw OS error text into diagnostic logs. Avoid automatic copies, backups, or auxiliary debug files.

## Required validation

Test exit/status precedence, empty inventories, mixed namespace permissions, missing metrics, shorter interrupted runs, every bound, hostile/oversized responses, rejection of excluded helpers, stalled transports/sinks, raw exception canaries, and output symlink/overwrite races. Validate schema and exact field allowlists with synthetic data. Restricted-identity integration tests must deny excluded resources and mutations. These are future implementation acceptance checks, not claims of checks already passed.
