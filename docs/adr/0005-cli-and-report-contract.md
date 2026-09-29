# ADR 0005: Bounded local runs and explicit report contracts

- Status: Accepted
- Date: 2026-09-28
- Accepted: 2026-09-28
- Authority: Explicit user approval of D1–D3 and authorization to accept ADRs after final architecture review; Milestone 1 is not authorized.

## Context

Automation must distinguish successful analysis, incomplete evidence, fatal failure, and undelivered output. A local report can expose sensitive infrastructure identifiers. Undefined limits and schemas would make collector and reporter behavior difficult to validate consistently.

## Decision

Adopt the [CLI acceptance contract](../cli-contract.md): explicit local context/namespaces, snapshot default, bounded observation, fixed exit codes/status semantics, total/per-operation deadlines, transport/retention/output caps, and no silent truncation. Return findings independently of exit success; a finding is not a process failure and an empty report is not proof of health.

Two scope reductions are **explicitly approved by the user on 2026-09-28**, replacing the earlier draft:

- **D1:** ten configuration inputs only: context, namespaces, kubeconfig path, mode, observation duration, output format/path, and three heuristic ratios. Safety/evidence constants are fixed and versioned, with no lowerable caps, stricter eligibility overrides, or configuration framework. Report effective constants without exposing credential/path inputs. Add inputs only for a concrete implementation requirement not reasonably handled by the contract, with documented review.
- **D2:** six exits only: 0 complete, 2 invalid configuration, 3 failed (including internal errors), 4 incomplete, 5 output delivery failure, 130 interrupted. No separate internal-error exit. Distinguish causes through closed errors; authentication aborts, authorization/API failures can yield partial success, and insufficient applicable evidence means incomplete. Output failure overrides the exit without changing analysis status. Additional exits require a future documented reason and contract review.

The [review ledger](../consistency-review.md) records D1–D3 approval and the final freeze. D3 permits necessary names in potentially sensitive reports but prohibits Kubernetes UIDs in every output/log/persistent artifact; identity correlation remains memory-only. Exact fields, nulls, counters, limitations, and versions live in the data contract, while the CLI contract owns inputs/exits and the evidence contract owns timing. Do not maintain competing schema or timing definitions in implementation modules.

Version the JSON schema independently from tool/rule/data/evidence versions. Start at schema `1.0.0`; major changes alter existing meaning/types or closed enums, minor changes add reviewed optional fields, patches preserve instance semantics. Publish and test the schema with the later reporting implementation. Include effective thresholds, rule versions, policy versions, and coverage.

Use a separate closed report allowlist. Saved reports require an explicit path, restrictive permissions, no symlink following/overwrite, and atomic no-replace publication. Stdout is available but operator redirection/capture has separate permissions and egress implications. Only an explicitly requested allowlisted report may enter a temporary output file; no raw-response spool or historical cache.

## Alternatives

A single success/failure bit hides partial collection. Treating findings as failure conflates operational completion with workload configuration. Unbounded retries/polling and permissive output overwrites are easier initially but undermine availability and safe artifact handling. A persistent result service adds deployment/storage decisions without a v0.1 requirement.

## Consequences

The accepted defaults are engineering hypotheses requiring implementation tests, not performance guarantees. Some large clusters, slow helpers, or filesystems may be unsupported until controls can be enforced. Schema artifacts and tests are later implementation work. This ADR is Accepted; it does not authorize Milestone 1.
