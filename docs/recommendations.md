# v0.1 evidence and recommendation methodology

Status: **Accepted architecture contract — frozen on 2026-09-28; not implemented.** Threshold defaults are accepted engineering hypotheses for testing, not calibrated production guidance.

## What the inputs mean

CPU requests influence scheduling and CPU allocation under contention; they are not ceilings. CPU limits can throttle execution. Memory requests influence scheduling, while memory limits can lead to OOM termination. Usage above a request alone does not prove an application is unhealthy. See [Kubernetes resource semantics](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/).

The Metrics API reports CPU averaged over a measurement window and a memory working-set estimate at a timestamp. It is not a historical metrics store. Preserve these distinctions in evidence; sampled working set does not establish a safe memory limit. See the [resource metrics pipeline](https://kubernetes.io/docs/tasks/debug/debug-cluster/resource-metrics-pipeline/) and [PodMetrics schema](https://kubernetes.io/docs/reference/external-api/metrics.v1beta1/).

## Rules

| Finding | Trigger | Human recommendation |
| --- | --- | --- |
| `REQUEST_MISSING` | CPU or memory request absent in the observed Pod | Review explicit requests and admission defaults for scheduling predictability |
| `MEMORY_LIMIT_MISSING` | Memory limit absent | Review memory containment policy and workload needs; no universal limit prescribed |
| `CPU_REQUEST_OVERPROVISIONING_CANDIDATE` | Maximum eligible sampled CPU / positive CPU request < configured ratio (default 0.30) over an eligible observation run | Investigate lower requests using representative history and performance tests |
| `MEMORY_REQUEST_OVERPROVISIONING_CANDIDATE` | Maximum eligible sampled working set / positive memory request < configured ratio (default 0.30) over an eligible observation run | Investigate memory allocation across startup, peaks, and workload cycles |
| `REQUEST_BELOW_OBSERVED_USAGE` | Valid CPU or memory observation exceeds its positive request | Review contention exposure and scheduling assumptions; this is not proof of resource starvation |
| `MEMORY_LIMIT_HEADROOM_LOW` | Valid working set / positive memory limit ≥ configured ratio (default 0.90) | Investigate peaks and OOM evidence through approved operational tools; OpenKube does not request logs/events |

Missing CPU limits are not automatically a defect. Near-limit CPU observations cannot establish throttling without throttling metrics. Absent/zero denominators never produce ratios. Unsupported or malformed allocation suppresses the affected rule and produces a coverage explanation.

## Threshold configuration

The 30% and 90% ratios are hypotheses, not universal Kubernetes best practices. All rules initially use version `1.0.0`; behavior/default changes increment the rule version. Actual configured values are separate from the version and must appear in every threshold-based finding and the report's effective configuration.

| Configuration key | Default | Valid range and comparison |
| --- | --- | --- |
| `cpu_overprovisioning_ratio` | `0.30` | Finite decimal strictly between 0 and 1; candidate when maximum usage/request is strictly less. |
| `memory_overprovisioning_ratio` | `0.30` | Finite decimal strictly between 0 and 1; same strict comparison. |
| `memory_limit_headroom_ratio` | `0.90` | Finite decimal greater than 0 and at most 1; trigger when usage/limit is greater than or equal. |

Reject invalid values before API access. `REQUEST_BELOW_OBSERVED_USAGE` uses a fixed semantic boundary of usage/request > 1, reported as threshold `1.00`; absence rules have null thresholds. All three heuristic ratios are independently configurable. Test exact equality, just below/above, custom settings, absent/zero denominators, and invalid values using synthetic fixtures. Changing a threshold never relaxes evidence gates or permits resize/savings claims.

The [complete configuration table](cli-contract.md#complete-configuration-surface) defines types, defaults, precedence, security implications, and reportability. Under approved D1, eligibility limits are fixed versioned policy; no per-rule enable/disable options, tunable polling, configurable confidence, or automatic threshold calibration is included.

## Evidence requirements

The [evidence eligibility contract](evidence-eligibility.md) is authoritative for startup, Pods created mid-run, restarts, rollouts, allocation changes, stale/missing/duplicate observations, identity ambiguity, and shortened runs. Default observation is 30 minutes at one-minute intervals, at least 90% valid scheduled slots, no gap over two intervals, and source freshness within two minutes. Minimum configured duration is 30 minutes; maximum is 60 minutes. Actual shorter/interrupted runs cannot produce overprovisioning candidates. Deduplicate source timestamps, preserve unknowns, and abstain from every utilization rule whose required evidence is insufficient.

Baseline is inventory only; default observation has exactly 30 slots and requires at least 27 valid distinct observations **per subject/resource**, plus the separate gap/stability/closure gates. There is no 31st baseline sample. CPU intervals and memory points independently pass the 120-second startup gate. CPU windows are positive and at most 120 seconds; source timestamp age is at most 120 seconds; the maximum accepted-receipt gap including observation endpoints is 120 seconds. These checks do not imply continuous coverage. Snapshot needs one eligible observation per resource and never emits an overprovisioning candidate.

Snapshot mode can produce configuration findings and immediate risk observations. It must not emit an overprovisioning candidate from one low observation. A missing or failed poll is unknown, never zero. Observation time and coverage describe only the sampled interval, not the application's business cycle.

## Explanation and confidence

Each finding includes the subject, source, units, time interval, sample count, missing-data count, exact rule and threshold, observed allocation, evidence values, and limitations. Recommendations identify an investigation action and always state: **Human review required before any workload change.**

Separate evidence quality from recommendation confidence. A missing request can be directly observed with complete inventory, but that does not establish a correct replacement value. Utilization-based recommendations in v0.1 have LOW confidence in a sizing decision; insufficient evidence produces abstention with a reason. Do not present HIGH confidence optimization advice.

Deployment reports retain per-container and per-Pod findings. Do not sum different containers into a fictitious container or use an average across replicas to hide peaks. A Deployment summary must show eligible and skipped replica counts; heterogeneous allocations and rollouts prevent a uniform workload recommendation.

No P95, numerical resize target, or production-safe recommended value is emitted in v0.1. Say “CPU overprovisioning candidate,” never “Reduce CPU request to 350m.” Deriving a target requires a separately reviewed historical method, representative coverage, headroom policy, rollout segmentation, autoscaler interactions, and application validation. Do not calculate monetary savings or claim reclaimable infrastructure capacity or reliability improvements. Lower requested resources would not by itself establish infrastructure savings.

## Measurements without invented outcomes

The run report measures the exact counters in the [conceptual report contract](data-and-egress.md#scope-source-inventory-and-coverage-records). Count infrastructure by unique run-local identity and sampling by subject/resource slots. Evaluated/skipped container sets may overlap because rules differ; rejected/duplicate slots are subsets of missing. Never combine those as disjoint totals or add per-run counts into an implied global total. Report coverage even when no finding is emitted.

Report allocation and usage as observed values with timestamps. “Allocated minus sampled usage” may be described as observed headroom, never reclaimable waste. v0.1 does not report estimated safe resource reduction, money saved, acceptance rate, or reliability improvements. These require later evidence and, for acceptance rates, an explicit feedback mechanism. All examples and fixtures must be labeled synthetic.
