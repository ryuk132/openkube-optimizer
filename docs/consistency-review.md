# Documentation consistency review

Status: **Final architecture review complete — v0.1 architecture frozen on 2026-09-28.** D1 and D2 are approved; D3 is approved with necessary human-readable names allowed and UIDs internal memory-only. ADRs 0001–0005 are Accepted under the user's explicit authorization following the final review. This ledger preserves that historical snapshot: implementation was not authorized at that point. Milestone 1 is now complete and committed; separately authorized Milestone 2 records/quantities are complete and accepted on 2026-09-29. See the current [roadmap](roadmap.md), [development guide](development.md), and [domain model](domain-model.md). This establishes no Kubernetes runtime support. Historical findings below remain unchanged; the dated amendments at the end record subsequent decisions and is not a second source of operational defaults.

## Specification authorities

- [CLI contract](cli-contract.md): entire user configuration surface, fixed operational limits, exits/statuses, schema compatibility, output safety.
- [Evidence contract](evidence-eligibility.md): baseline/slot/closure timing, resource-specific eligibility, counters, abstention vocabulary.
- [Data/egress contract](data-and-egress.md): exact internal projection paths, entire conceptual report structure, retention/egress and prohibited fields.
- [Recommendations](recommendations.md): six rule meanings, comparisons, heuristic defaults, conservative action language.
- Architecture, security, threat model, module plan, roadmap, and ADRs summarize/link these authorities. None permits implementation before approval.

## Inconsistencies found and resolutions

| ID | Inconsistency or missing contract | Resolution in revised proposal |
| --- | --- | --- |
| C01 | Baseline meant both initial inventory and first complete metric bracket. | Baseline is inventory-only before one global t0; each scheduled slot contains its own fresh bracket. |
| C02 | Possible counted baseline/31st sample; final closure mixed with observation duration. | Exactly D/60 slots; separate baseline and final inventory add no sample/time to D. Default 27/30, maximum 54/60. |
| C03 | Namespace-local cycle budget conflicted with one-minute global polling. | All sequential namespace brackets share the same global slot boundary; incomplete brackets are missing; no overlapping/catch-up work. |
| C04 | A metric could count before its post-inventory stability check completed. | Whole bracket must finish before its half-open slot ends; on-boundary/late work cannot count. |
| C05 | Startup gating treated CPU windows and point-in-time memory as interchangeable. | CPU interval start and memory point independently pass lifecycle/startup gates; CPU-only window validation. |
| C06 | Both CPU/memory fields were required despite claims of independent analysis. | Eligibility, missing/duplicate/rejected counts, and coverage are per subject/resource. |
| C07 | Gaps, minimum count rounding, future planned slots, and snapshot count were underspecified. | Elapsed receipt gaps include endpoints; ceil(0.90*N); shortened/late-created subjects retain N; snapshot has one slot. |
| C08 | Final-inventory failure/disappearance and readiness loss had no precise whole-run effect. | Suppress affected whole-run candidates; preserve independently valid immediate findings, explain incomplete evidence. |
| C09 | Conflicting duplicates could leave already-emitted evidence valid. | Invalidate affected old uses; recompute counts/findings from remaining evidence. |
| C10 | Aggregation by subject/rule could mix allocations or restarts. | Aggregate only within the same execution/allocation segment; separate finding IDs otherwise. |
| C11 | Unchanged brackets implied historical/transactional allocation certainty. | Explicit residual uncertainty; startup/freshness gates remain necessary but no historical stability guarantee. |
| C12 | Rollout checks could describe scaling/readiness as a proven rollout. | Report Deployment instability; conservative whole-run abstention without causal claims. |
| C13 | Configuration keys/types/defaults, precedence, input/report boundaries were incomplete. | Ten-field accepted table with security/reportability; one selected kubeconfig; no configuration framework/implicit merging. D1 approved. |
| C14 | Optional lowerable safety caps/tightenable evidence knobs enlarged the MVP. | Fixed versioned reported policy constants; only three heuristic ratios and duration remain analysis tuning. D1 approved. |
| C15 | Root/nested report fields, counts, enums/nulls, and rule configuration were partly open-ended. | Closed conceptual tables, exact primitive types/counters/vocabularies; no application models or schema files. |
| C16 | No-finding/abstention reports lacked evidence coverage; Deployment summaries were promised but absent. | Add explicit coverage and Deployment grouping records, with defined eligible/skipped semantics. |
| C17 | Output configuration could mean a dump of paths/context/auth data. | Report only sanitized rules/evidence/limits; invocation paths, aliases, endpoints and credentials never appear. |
| C18 | Unique infrastructure counts and repeated samples were conflated. | UID-based inventory counts; subject/resource slot counters; distinct observation-record memory cap; overlaps/subsets documented. |
| C19 | Source recovery, tolerated missing samples, and sufficient evidence had conflicting success interpretations. | Exhausted source failure means incomplete even after later recovery; individual sample rejection within all gates need not. Known inapplicable rules are explicit skips, not failures. |
| C20 | Authentication, authorization, missing Metrics API, and general API failures lacked a full outcome matrix. | 401/credential failure aborts; 403/source failure can be partial with usable inventory; no inventory fails; empty namespaces can complete. |
| C21 | Internal-error exit and output-failure precedence added ambiguity. | Internal errors under exit 3, delivery failure exit 5 separate from analysis status; D2 approved. |
| C22 | Architecture promised no partial JSON while stdout delivery can break. | Fully serialize; no intentional truncation. Partial external streams are possible on delivery failure and never reported successful. |
| C23 | Retry-After handling conflicted with the header allowlist. | Allow transient parsing of just Retry-After into bounded delay; no raw header retention/reporting. |
| C24 | Prohibition on local file reads accidentally covered normal runtime/OS trust loading. | Limit application analysis inputs while acknowledging required runtime, trust/DNS, and output infrastructure. |
| C25 | Named reports conflicted with an unconditional no-sensitive-data expectation. | D3 approved: necessary namespace/Deployment/Pod/container names permitted; reports potentially sensitive; no UIDs in outputs/logs/persistence; no pseudonymization. |
| C26 | No clear separation of open architecture choices and later implementation validation. | D1–D3 resolved and architecture frozen; client/platform/transport/filesystem checks remain staged implementation acceptance work. |
| C27 | “New baseline” after restart/allocation change could reset observation eligibility. | Use a post-change inventory checkpoint for later immediate evidence; never reset run baseline, t0, or N. |
| C28 | Unknown/malformed/unstable allocations could be classified as harmless unsupported exclusions. | Separate known unsupported skips from insufficient-evidence quality codes and incomplete outcomes. |
| C29 | Report elapsed/end time could imply measurement of its own future output delivery. | Measure analysis/report finalization time before delivery; total execution deadline still covers delivery. |
| C30 | Final D3 policy prohibited UID fields in the earlier proposed subject/Deployment records. | Remove every output UID and unnecessary ReplicaSet name; use existing creation-time evidence for name reuse; keep identity/deduplication memory-only, never hash UIDs into finding IDs. |

Scope scan found no surviving affirmative v0.1 authorization for namespace discovery, in-cluster execution, workload mutation, resize targets, money/capacity/reliability claims, broad permissions, or telemetry. References to them are explicit exclusions, reviewed alternatives, or deferred decisions. Kubernetes proxy functionality remains prohibited; trusted transport proxies are a separately disclosed client boundary. Operator RBAC examples/disposable test clusters do not imply collector deployment or provisioning privileges.

## Resolved decisions and acceptance

| Decision | Approved resolution | Decision date / effect |
| --- | --- | --- |
| D1 — configuration scope | Ten documented inputs; safety/evidence constants fixed and versioned, no extra tuning surface. Additional configuration requires a concrete demonstrated requirement not reasonably handled by the existing contract and documented review. | Approved 2026-09-28; reflected in ADRs 0001/0002/0005. |
| D2 — exits | Exactly 0 complete, 2 invalid configuration, 3 failed, 4 incomplete, 5 output delivery failure, 130 interrupted. Internal failures use 3; any new exit needs a future documented reason. | Approved 2026-09-28; reflected in ADR 0005. |
| D3 — sensitive identifiers | Only necessary allowlisted namespace, Deployment, Pod, and container names in reports. Names may contain sensitive organizational information; reports are potentially sensitive artifacts. UIDs are memory-only internal identity/correlation data, never reported/logged/persisted and released when no longer needed. No pseudonymization; future privacy use cases require an ADR. | Approved with this policy 2026-09-28; reflected in ADRs 0003/0004/0005. |

The technically unavoidable transient raw-object memory boundary was already approved and remains unchanged. D3 separately resolves output identifiers. Concrete thresholds/limits are accepted, versioned engineering policy values, not calibrated production best practices. All five ADRs are Accepted with decision date 2026-09-28; the freeze does not authorize implementation.

## Final architecture review

Reviewed the full documentation as one specification after applying D1–D3. No unresolved architectural blocker remains:

- Local-only synchronous read-only scope, explicit context/namespaces, four namespaced list permissions, and no mutation/discovery/in-cluster/telemetry path remain consistent.
- The ten configuration inputs and six exits match the approved contracts. Fixed evidence/operational policies remain versioned; no extra tuning or technologies were added.
- Timing retains inventory-only baseline, per-resource scheduled slots, explicit gaps/startup/freshness, full observation/closure requirements, and abstention. No numerical production sizing or savings claims appear.
- Internal identity still uses UIDs in memory; the separate output contract has no UID fields, UID-derived IDs, or ReplicaSet names. Existing Pod creation-time evidence moves into the report subject, and Deployment creation time distinguishes reused Deployment names. These timestamps come from the existing internal allowlist; no extra Kubernetes access or pseudonymization is introduced.
- Report names are explicitly allowed but potentially sensitive. Reports/logs/errors/temporary artifacts cannot contain raw objects, credentials, UIDs, endpoints, or other prohibited content. UID and credential canaries are required implementation checks.
- ADRs record explicit user approval and acceptance date; AGENTS.md preserves the separate Milestone 1 authorization gate. Unimplemented controls are never described as verified guarantees.

## Scope control and staged validation

Keep one local synchronous process, a small metrics provider protocol, typed allowlisted records, and pure rules. Do not add configuration-file formats, tuning frameworks, plugin loaders, telemetry, persistent storage, collector images/Jobs, identity services, schema registries, or anonymization services. Use compact per-segment findings and aggregate failures rather than per-poll report expansion. Retain size/deadline/output controls because they address documented threats; validate their feasibility rather than claiming they already work.

Milestone 1 will choose supported Python/client/Kubernetes/Metrics API versions, local platforms, dependency tooling, and a license. Before collection acceptance, test required SDK field visibility, exact permissions, TLS/proxy/helper behavior, byte/deadline limits, and immediate projection/canaries. Before reporting acceptance, test the schema contract and safe filesystem/delivery behavior. Maintainers/private reporting channel are release-readiness choices. None of these implementation tests was run in this documentation-only review.

## Architecture freeze and readiness

**The architecture is frozen for OpenKube v0.1 as of 2026-09-28.** D1–D3 are resolved, ADRs 0001–0005 are Accepted, and the repository is ready for Milestone 1 from an architecture/documentation perspective. Milestone 1 has not started and must wait for explicit user authorization. No code, dependencies, models, schema artifacts, or manifests were created. Documentation checks establish consistency, not runtime correctness or security guarantees.

Future changes must preserve the freeze or explicitly review/supersede it. Client/version/platform/authentication choices, policy calibration, transport/helper enforcement, UID lifetime/output exclusion, and filesystem safety remain implementation risks with staged acceptance tests, not open architecture decisions.

## Milestone 2 approved clarifications

On 2026-09-29 the user approved the domain design and authorized its reduced implementation scope:

| Decision | Resolution and implementation boundary |
| --- | --- |
| A — fractional memory | Exact parsing followed by upward whole-byte normalization for nonnegative fractions; preserve existing input/value ceilings. Implemented in pure conversion and synthetic tests; no SDK parsing/integration claim. |
| B — started confirmation | Future utilization eligibility requires explicit `container_started=True`; false, ABSENT, INVALID, and UNAVAILABLE cannot establish startup. Domain state preservation is implemented; eligibility is not. Accepted [ADR 0007](adr/0007-explicit-container-started.md) records the approved tightening without modifying accepted ADRs. |
| Scope — AnalysisSettings | Explicitly excluded from Milestone 2. The ten-input configuration contract remains unchanged. Add a settings object only when later analysis/configuration code needs it. |
| Administrative status | Milestone 1 is complete and committed as `1e52383`; Milestone 2 was accepted on 2026-09-29. No staging, commit, push, or Milestone 3 authorization. |

The initial unreleased `evidence-v1` retains its identifier with an explicit dated amendment: no prior evaluator or emitted reports exist, and numeric gates are unchanged. This is not a claim that the earlier wording already required true. Accepted ADRs 0001–0006 remain byte-for-byte unchanged; ADR 0007 was explicitly accepted on 2026-09-29. The data/report allowlists, permissions, ten inputs, six exits, and no-runtime-dependency boundary remain unchanged. Parser expansion bounds and the implemented record subset are documented in [domain-model.md](domain-model.md), not new user controls.

## Milestone 3 accepted design and consistency — 2026-09-30

[ADR 0008](adr/0008-restricted-kubeconfig-and-bounded-transport.md) is Accepted on 2026-09-30. Its D1–D6 labels are distinct from the original freeze's D1–D3. Architecture/design for M3 is complete, and the separately authorized documentation consistency pass applies its amendments without changing historical decisions. M3 implementation, dependency addition, RBAC/cluster work, staging, committing and pushing remain unauthorized.

| Decision / consistency point | Resolution |
| --- | --- |
| D1 — SDK/wire | Official generated dispatch precedes controlled bounded wire validation and immediate exact projection. Stock REST errors and generated-model deserialization are not the boundaries; transient raw data never propagates into domain/report/log/persistence. |
| D2 — transport/setup | Ubuntu 24.04 LTS x86_64, trusted resolved Varlink/procfs, explicit multi-label absolute hostname without search/single-label/custom NSS fallback. Bounded address fallback permits private answers; original hostname remains TLS/SNI/HTTP authority. Numeric budgets remain unchanged. Setup elapsed counts without reset, but synchronous file/OpenSSL parsing is not hard mid-call cancellable. Controlled DNS-through-HTTP stays inside the attempt deadline. Owned resources close without abandoned OpenKube resolver workers; no instantaneous daemon/shared-work cancellation claim. |
| D3 — mandatory structure | Invalid mandatory identity/ownership/list structure invalidates the namespace pass; independent complete namespaces survive. Well-formed unresolved/unsupported ownership and representable field uncertainty remain distinct. |
| D4 — classification/report | Architectural boundedness requirements, previously frozen operational values and new versioned implementation guards are separate. File/nesting/Varlink/HTTP guards are not Kubernetes semantic limits, user tuning inputs or report fields. Ten inputs, exits 0/2/3/4/5/130 and the existing closed 18-group report schema remain unchanged. |
| D5 — credentials | Trusted stable regular files with approved symlinks and bounded reads; certificate-only CA memory snapshot; retained cert/key descriptors via `/proc/self/fd`, with native rereads and in-place mutation limitation. Always rejecting password callback; no passwords/environment/prompts/helpers/fallback/copies/persistence. No guaranteed memory zeroization. Credential design blocker is closed under these approved assumptions, not by proving native cancellation. |
| D6 — endpoint | Preserve validated fixed HTTPS base path, origin and original hostname/port; reject redirects, traversal and ambiguous forms. |
| Milestones | M3 is Pods/Deployments/ReplicaSets inventory; M4 adds PodMetrics/metrics.k8s.io. No collection implemented by this pass. |
| Platforms/evidence | Ubuntu is runtime validation priority; macOS is development-only. Other initial scope exclusions remain. Disposable synthetic feasibility, accepted design, implemented runtime support and validated Kubernetes/platform compatibility are separate. No EKS/AKS/OpenShift/ROSA/ARO support claim. |
| Dependencies | kubernetes==36.0.3 intended and h11==0.16.0 approved for later implementation. Project dependencies remain empty; pyOpenSSL not required, cryptography not direct. |
| History | Original ADR 0001/0003/0004/0005 text preserved with dated cross-references appended. ADRs 0002/0006/0007 unchanged. Original freeze/M1/M2 evidence remains historical. |

The substantive previous conflict was unconditional cancellation wording across setup. The dated ADR 0008 amendment explicitly qualifies it while retaining elapsed-time accounting and numerical budgets. The broad interpretation of “report effective constants” is resolved through the unchanged closed allowlist. Current status/profile/module descriptions and the ADR index now agree; no architecture decision remains unresolved.

Documentation validation checks local Markdown targets/anchors, ADR/index status, M3/M4 and runtime wording, original ADR preservation, exact configuration/exit/report tables, unchanged operational/evidence values, empty dependencies and Git whitespace. These checks establish documentation consistency only. No application tests/builds, new transport probes or Kubernetes calls are part of this pass. Implementation boundary and integration tests remain required before support claims.

Validation result: 206 local Markdown targets and 65 anchors passed across 24 documents. ADR/index statuses and dates agree for all eight Accepted ADRs. The ten-input, six-exit and 18-root-group tables, existing projection/report tables, operational-limit table and evidence tables are byte-for-byte unchanged. Historical ADR append-only checks passed; ADRs 0002/0006/0007, package metadata/lock and all non-documentation files are unchanged. External upstream URLs were preserved, not re-fetched. Git whitespace checks passed and no files were staged.
