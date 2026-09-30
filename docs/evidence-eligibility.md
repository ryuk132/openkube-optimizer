# v0.1 evidence eligibility contract

Status: **Accepted architecture contract — frozen on 2026-09-28; not implemented.** Policy version: `evidence-v1`. These are fixed conservative engineering defaults, not calibrated Kubernetes best practices. See [rules](recommendations.md), [field allowlists](data-and-egress.md), and [runtime limits](cli-contract.md).

**Approved amendment, 2026-09-29:** the user tightened startup confirmation from "started not false" to explicitly true. False, ABSENT, INVALID, and UNAVAILABLE cannot establish startup eligibility. Accepted [ADR 0007](adr/0007-explicit-container-started.md) preserves this decision and its rationale without rewriting Accepted ADRs. Keep the initial unreleased `evidence-v1` identifier with this dated amendment; no prior implementation or emitted reports exist. All other gates and constants remain unchanged. Milestone 2 preserves states only; eligibility calculations remain future work.

## Units, subjects, and clocks

A subject is `(namespace, Pod UID, regular container name)`, with a verified controller chain to a Deployment UID. Container restart count and running start time identify its execution segment. Keep each Pod/container separate; no interpolation, cross-replica averaging, or stitching replacement Pods together.

These UID-based keys are internal memory-only analysis identities, never report/log/persistence fields. Retain references only while required for this run's analysis and release them on completion/failure/interruption. Reports project necessary human-readable names and creation-time evidence under D3; name-based output must not replace UID-based internal joining or leak UIDs through tool-generated finding IDs.

CPU represents an average over `[source timestamp - window, source timestamp]`; memory is a working-set estimate at the source timestamp. CPU requires a valid positive window no longer than 120 seconds. Each resource independently requires a finite nonnegative quantity; malformed CPU/window does not invalidate otherwise valid memory, and malformed memory does not invalidate otherwise valid CPU. Coverage, eligibility, and counters are per subject **and resource**, not combined CPU/memory success. Missing or zero denominators make ratio rules inapplicable, never substitute a value.

Use UTC source/receipt timestamps for provenance and a monotonic local clock for scheduling/deadlines. Reject future-dated samples beyond five seconds of receipt time, backwards source timestamps, and detected local wall-clock jumps exceeding five seconds relative to monotonic elapsed time. A detected local clock jump invalidates utilization evidence for the run. Do not silently correct provider timestamps. These fixed tolerances are versioned policy constants.

## Inventory checks and stable baseline

For each namespace slot, read a complete Pod/ReplicaSet/Deployment inventory before metrics, retrieve PodMetrics, then read a complete inventory again. All namespace work shares the one global slot deadline; a namespace's complete bracket must finish before that boundary for its samples to count. Metric receipt alone before the deadline is insufficient. Process namespaces synchronously in requested order; never overlap slots or add catch-up requests. Report slots missed by later namespaces instead of hiding them. Project each page immediately. Partial inventories cannot establish ownership or stability; do not reuse an earlier cycle's inventory to manufacture a complete bracket.

Verify the same Pod UID, controller UIDs, container name, restart count, running start time, readiness, and normalized allocation before and after metrics. CPU's interval start and memory's point timestamp must pass creation/startup gates. After any observed identity/execution/allocation change, reject samples whose applicable interval/point predates the first complete post-change inventory; new snapshot evidence needs a subsequent matching bracket. Do not treat an unchanged bracket as proof of historical stability.

Resource versions are opaque equality tokens. If a resource version changes, compare the allowlisted relevant fields. Metadata-only or unrelated status updates do not invalidate evidence. A change followed by a reversal entirely between reads may be undetectable; report this non-transactional limitation. **Baseline** means the completed initial inventory pass before `t0`; **bracket** means inventory → metrics → inventory within one slot. Baseline contains no counted usage sample and is not itself proof of stable evidence.

## One observation timeline

**Dated setup clarification, 2026-09-30:** [ADR 0008](adr/0008-restricted-kubeconfig-and-bounded-transport.md#bounded-execution-amendment--2026-09-30) qualifies cancellation during synchronous trusted-file/native TLS-context setup. Its elapsed time still consumes the total run budget without reset, but executing native setup is not hard-preemptible. Stop further work on expiry once control returns. Setup never contributes observations; all numeric gates, slots, baseline/closure and coverage semantics below remain unchanged. M3 supplies inventory only; M4 implements PodMetrics and this collection/evidence timeline.

1. Start the total run timer before authentication. Observation setup has one initial inventory pass over the explicit namespaces, with a 60-second budget after authentication. If none completes, fail. A successfully inventoried empty namespace counts as complete. Failed baseline namespaces are reported and are not silently retried into the baseline.
2. Set one global monotonic `t0` when setup ends. Freeze the baseline subjects and requested schedule. Subjects in successful baseline namespaces must already pass lifecycle/warm-up checks at `t0` to qualify for whole-run overprovisioning. Continue collecting later subjects for inventory and individually eligible immediate findings, without adding them to the baseline.
3. For observation duration `D`, schedule `N = D / 60` half-open slots `[t0 + 60*k, t0 + 60*(k+1))`, for `k = 0 .. N-1`. Each subject/resource can contribute at most one distinct accepted sample per slot. Complete its full bracket before the right boundary. A response at the boundary belongs to no previous slot; cancel unfinished work, record missing, and start the next scheduled cycle without overlap/catch-up.
4. At `t0 + D`, stop metric polling and perform final inventory within its separate 60-second budget. Final inventory adds no sample/slot. Missing final inventory, subject disappearance, or changed baseline identity/allocation/lifecycle prevents whole-run candidates for affected subjects. Closure changes after D conservatively suppress candidates too; disclose the closure time separately from the observed interval.
5. Evaluate evidence and finalize within the reserved 15 seconds and total deadline. Observation duration measures the planned interval only; authentication, baseline, closure, and report writing do not count toward D. Waiting between scheduled polls is bounded by the same deadline.

Default D = 1800 gives **30 slots and at least 27 valid distinct observations per resource**; D = 3600 gives 60 slots and at least 54. In general require `ceil(0.90 * N)`. Never use 31 baseline-plus-poll samples, decrease N after missing work, or count final inventory as utilization evidence.

The earliest CPU source interval can precede `t0` if its lifecycle/window/freshness gates pass and no relevant change is observed. Record actual source interval separately from the scheduled interval. Baseline/bracketing cannot establish a transaction or guarantee allocation stability before/among reads; no confidence claim may imply otherwise.

## Required behavior by condition

| Condition | Required behavior |
| --- | --- |
| Container startup | Require a non-deleting Pod in phase `Running`, Pod `Ready=True`, container `ready=true`, `container_started` explicitly `True`, and a running start timestamp in both reads. False, ABSENT, INVALID, and UNAVAILABLE do not establish startup eligibility. CPU interval start or memory point timestamp must be at least 120 seconds after the later of container start and latest Pod Ready transition; Ready transition/flags must agree across the bracket. Missing timestamps or readiness loss means abstention. Readiness/warm-up eligibility lost anywhere in the run suppresses whole-run candidates, even if it later recovers. |
| Pod created during observation | Inventory/configuration findings remain possible. Snapshot risk rules may apply once a later sample passes all lifecycle gates. No overprovisioning candidate in that run: the subject lacks a full baseline-to-end observation. |
| Container restart | Reject the observation whose bracket changes restart count/start time. Do not combine execution segments. Suppress whole-run overprovisioning for that subject; later immediate evidence can qualify only after a complete post-change inventory checkpoint, matching subsequent bracket, and warm-up. Do not reset t0 or the run baseline. Earlier valid immediate evidence remains historical with its timestamp and restart caveat. |
| Deployment rollout or uncertain rollout stability | Detect template/generation changes, unobserved generation, mismatch between desired and updated/available replicas, or multiple active ReplicaSet UIDs in observed Pods. Such observations do not prove rollout causality (scaling/readiness can also change counters); report `DEPLOYMENT_UNSTABLE`, keep eligible per-Pod immediate findings, and suppress whole-run candidates for that Deployment. Never emit a uniform Deployment resize recommendation. |
| Allocation change | Compare normalized Pod CPU/memory requests/limits, unsupported-resource flags, and relevant status allocation fields. Reject the affected bracket and whole-run overprovisioning for that subject. Later immediate findings require the post-change checkpoint and matching bracket; never reset the run baseline or compare pre-change CPU windows with post-change allocations. |
| Stale metrics | Reject source age at receipt over the fixed 120-second bound; equality qualifies. Future skew up to five seconds is tolerated, never used to extend deadlines. CPU windows must independently satisfy interval/lifecycle checks. Fresh retrieval does not refresh a source sample. |
| Missing observation | Record an unknown scheduled slot and cause; never zero, interpolate, or reduce the denominator. An eligible snapshot elsewhere can still support a timestamped immediate finding. |
| Duplicate observation | Deduplicate per subject/resource/source timestamp. Equal repeated values/window add no coverage. Conflicting values (or CPU window) invalidate all uses of that resource/key, including any previously counted slot/finding derived from it, and suppress whole-run candidates for the affected subject/resource. Recompute affected counts and immediate findings from remaining valid evidence. |
| Identity ambiguity | Reject the sample if owner resolution, name-to-UID continuity, container membership, or lifecycle identity is uncertain. Suppress whole-run overprovisioning for the affected subject; no name-prefix/label guesses. |
| Shortened observation | A run ending before its configured duration cannot produce overprovisioning candidates, even if its observed prefix looks complete. Preserve eligible configuration and snapshot findings, mark the run incomplete (or interrupted), and retain the originally scheduled denominator. |

Known unsupported Pod-level budgets, special container types, and owners produce explicit unsupported skips. Active/inconsistent resizing, malformed allocations, unresolved ownership, missing lifecycle evidence, unknown enums, or client-version gaps cause insufficient-evidence abstention rather than being disguised as supported exclusions. Independently interpretable regular containers may remain eligible. Use `ALLOCATION_UNKNOWN` for uncertain/unstable allocation semantics, `MALFORMED_VALUE` for invalid quantities, `IDENTITY_AMBIGUOUS` for unresolved owners, and `LIFECYCLE_UNKNOWN` for missing required lifecycle facts.

## Snapshot and bounded observation modes

Snapshot is the default mode: one global cycle of at most 60 seconds, with one inventory/metrics/inventory bracket per namespace, no observation baseline or closing pass, and exactly one scheduled slot per subject/resource encountered. Configuration findings need a valid supported allocation/ownership record, not utilization. Immediate utilization rules (`REQUEST_BELOW_OBSERVED_USAGE`, `MEMORY_LIMIT_HEADROOM_LOW`) need one individually eligible sample. If none qualifies, abstain. These rules may also use eligible individual samples during observation mode; its 90%/duration/gap gates apply only to whole-run overprovisioning, not to immediate findings.

Observation mode adds overprovisioning candidates only when all of the following hold:

1. The configured duration completes: default/minimum 30 minutes, hard maximum 60 minutes. Shorter requested durations are invalid, rather than quietly weakening the rule.
2. The subject is eligible in the baseline at `t0`, remains eligible through final closure, and has no observed restart, readiness loss, allocation/identity change, or Deployment instability.
3. At least 90% of its scheduled slots have valid distinct samples for the resource. A duplicate, late, failed, or missed slot remains unfilled.
4. No gap between accepted metric receipt times exceeds 120 seconds, including boundary gaps from `t0` to first accepted receipt and last receipt to `t0 + D`. Equality qualifies. This is an elapsed-time check, not permission for two consecutive missing slots; late/early polling within slots can affect it independently of the count threshold.
5. The maximum accepted sampled usage divided by the stable positive request is strictly below the configured threshold.

The timeline above is authoritative. A shortened run or failed closing inventory cannot qualify regardless of a complete-looking prefix. Scheduled-slot coverage is successful sampling, not continuous temporal/business-cycle coverage. Neither 90% coverage nor 30 minutes of low usage proves safe lower requests.

## Configuration and reporting

Rule ratios and observation duration are configurable through the [complete CLI configuration contract](cli-contract.md#complete-configuration-surface). Under approved D1, the following eligibility values are fixed versioned policy, not user inputs. Every report includes these exact keys under `configuration.evidence`; changing them requires policy review, not an undocumented override.

| Report key | Type | Fixed value | Meaning |
| --- | --- | --- | --- |
| `poll_interval_seconds` | Integer | 60 | Scheduled polling interval |
| `startup_gate_seconds` | Integer | 120 | Age after later of running start and Ready transition |
| `max_source_age_seconds` | Integer | 120 | Maximum timestamp age at metric receipt |
| `max_cpu_window_seconds` | Integer | 120 | CPU window in `(0, 120]`; not a memory averaging window |
| `max_gap_seconds` | Integer | 120 | Maximum gap between accepted receipts including endpoints |
| `min_coverage_fraction` | Decimal string | `0.90` | Whole-run required fraction; round count upward |
| `max_future_skew_seconds` | Integer | 5 | Maximum tolerated future source timestamp |
| `max_wall_clock_jump_seconds` | Integer | 5 | Maximum tolerated wall/monotonic delta discrepancy |

Report `evidence_policy_version`, bounds, planned/actual duration, per-resource slot counts, actual source interval, coverage, and abstention reasons, including when no finding is emitted. `scheduled_count = valid_count + missing_count`; duplicate/rejected counts are subsets of missing slots, not extra scheduled observations. Within one subject/resource slot, use one primary outcome in priority order: rejected (invalid/conflicting/late bracket), duplicate (equal previously accepted sample), missing (no sample/unfinished request/unvisited/future slot on early stop), valid. Multiple quality codes may explain one primary outcome. In observation, a late-discovered subject still has N scheduled slots; its pre-discovery slots are missing and it is ineligible for whole-run candidates. Snapshot has one slot. Summary sample counters count subject/resource slots, never raw API objects or replica counts.

Aggregate repeated triggers only within one subject/rule/resource/execution-and-allocation segment, with extrema and first/last triggering times. Different segments need separate tool-generated finding IDs and separate evidence; never merge pre/post-restart or different allocations into one ratio. No finding per poll is needed. Configuration findings and correctly supported immediate findings may coexist with abstained whole-run rules. No findings never implies healthy or efficient workloads.

The closed quality/skip vocabulary is: `UNSUPPORTED_OWNER`, `UNSUPPORTED_ALLOCATION`, `UNSUPPORTED_CONTAINER`, `RULE_NOT_APPLICABLE`, `DENOMINATOR_ABSENT_OR_ZERO`, `STARTUP_OR_NOT_READY`, `LIFECYCLE_UNKNOWN`, `ALLOCATION_UNKNOWN`, `POD_CREATED_DURING_RUN`, `RESTART_OBSERVED`, `DEPLOYMENT_UNSTABLE`, `ALLOCATION_CHANGED`, `STALE_SAMPLE`, `FUTURE_SAMPLE`, `CLOCK_ANOMALY`, `INVALID_WINDOW`, `MALFORMED_VALUE`, `MISSING_OBSERVATION`, `DUPLICATE_OBSERVATION`, `CONFLICTING_OBSERVATION`, `IDENTITY_AMBIGUOUS`, `INVENTORY_INCOMPLETE`, `LATE_BRACKET`, `INSUFFICIENT_COVERAGE`, `GAP_EXCEEDED`, `SHORTENED_RUN`, `SUBJECT_DISAPPEARED`, `FINAL_INVENTORY_FAILED`. Source/operational errors use the distinct CLI error vocabulary. A successfully evaluated non-triggering rule has no finding and is not a skipped rule.
