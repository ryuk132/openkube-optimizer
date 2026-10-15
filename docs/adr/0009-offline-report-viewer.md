# ADR 0009: Offline static report viewer

- Status: Accepted
- Date: 2026-10-15
- Accepted: 2026-10-15
- Authority: Accepted by the project coordinator on 2026-10-15 as the future graphical-interface direction. Acceptance changes no v0.1 scope, accepted contract or roadmap milestone, does not bring Milestone 6 forward, and authorizes no implementation, dependency, directory or schema artifact.

## Context

Accepted [ADR 0001](0001-read-only-cli.md) defines OpenKube v0.1 as one local read-only CLI process with no always-on API or dashboard. The [frozen architecture](../architecture.md#deliberate-exclusions) excludes FastAPI, dashboards, authentication servers and any listening server; the [data and egress contract](../data-and-egress.md#expected-network-communication) excludes telemetry, upload and arbitrary URL fetches. Reports go to stdout or an explicitly selected local file in terminal or JSON format.

A future graphical interface is of interest, to help engineers read large reports. Any such interface must preserve the existing boundaries: it must not contact Kubernetes, handle credentials, add a network surface or introduce a second data contract. The JSON report is the only accepted machine-readable output. Its closed 18-group structure is defined by the [report contract](../data-and-egress.md#data-openkube-may-write-to-reports) and its versioning by the [CLI contract](../cli-contract.md#json-schema-and-error-strategy). Neither the reporting implementation nor the published schema artifact exists yet.

## Decision

Adopt, in a future separately authorized milestone, an offline static viewer for OpenKube JSON reports:

```text
OpenKube CLI
    ↓
report JSON (local file, schema_version 1.0.0)
    ↓
offline/static viewer
```

The viewer works only with a JSON report file that the user selects locally. It does not access Kubernetes, read kubeconfig or credential files, call any OpenKube API, run or require a server, upload data, emit telemetry or analytics, or persist the report.

### Contract

The versioned JSON report is the only frontend/backend contract. No new contract, endpoint, output format or report field is introduced.

- The viewer must not depend on Python domain records, private modules or any other internal backend type. Domain records hold memory-only UIDs and are never directly reportable.
- Viewer types and runtime validation derive from the published, versioned JSON Schema for `schema_version` `1.0.0`, not from hand-maintained copies of the field lists.
- Tests use the official synthetic golden reports planned with the reporting implementation.
- The viewer follows the existing compatibility policy: reject unsupported major versions and tolerate unknown optional fields within a supported major.
- Reports larger than the existing `max_report_bytes` limit are rejected, not truncated.

### Stack direction (not implemented)

Vite, React, TypeScript in strict mode, Vitest, Testing Library, ESLint and `tsc --noEmit` checks. TanStack Table may be considered later, when large tables demonstrably require virtualization. No dependency, toolchain or directory is added by this ADR. Packaging, distribution alongside the Python package, and supply-chain checks for the JavaScript toolchain require later review.

### Security

- Static application with no network requests. A restrictive Content Security Policy blocks connections and limits scripts and styles to bundled assets.
- No external CDN, fonts or remote assets.
- No tokens, kubeconfigs, secrets or credentials anywhere in the viewer, its build or its test fixtures.
- The report is held in memory only for the open session. Nothing goes to `localStorage`, `sessionStorage`, IndexedDB or any other storage.
- All report content, including names, is rendered as escaped text, never as HTML or markup.
- Reports remain potentially sensitive artifacts because they contain namespace, Deployment, Pod and container names. The viewer only displays what the report already contains.

### States

The viewer distinguishes four load states:

- `idle`: no report selected.
- `loading`: reading and validating the selected file.
- `rejected`: invalid JSON, schema mismatch, unsupported major version or size limit. It shows a fixed message and does not echo the file content.
- `loaded`: a valid report.

Within `loaded`, the viewer represents:

- `run.status` values `complete`, `incomplete`, `failed` and `interrupted`, using the CLI contract meanings.
- Unavailable, partial and failed sources from `sources[]`, including missing metrics.
- Explicit `null` values, `skipped` records, sanitized `errors` and `limitations`.

The viewer never converts null or missing data into zero. It never presents `complete` as healthy, optimized or safe to resize.

### Language

The viewer preserves the [recommendation methodology](../recommendations.md#explanation-and-confidence):

- Findings are investigation candidates.
- Allocated minus sampled usage is observed headroom.
- Every view keeps the "human review required" notice.

The viewer introduces no monetary savings, guaranteed waste, reclaimable capacity, resize targets, automatic remediation, or recommendations presented as established fact.

## Alternatives

1. **FastAPI service plus dashboard.** Rejected for now. It contradicts ADR 0001 and the architecture exclusions, and it adds authentication, tenancy and a listening surface.
2. **Local OpenKube server.** Rejected for now. It introduces a listening server and a new API contract that the accepted architecture excludes.
3. **HTML report generated by the Python backend.** Rejected. It changes the closed `output_format` enum and the CLI/report contract, and it moves presentation work into the backend.
4. **No graphical interface.** Preserves the current architecture unchanged, but does not meet the future UI objective.
5. **Offline static viewer of the JSON report.** Selected. It reuses the existing report contract, adds no network or credential path, and keeps the CLI the sole data producer.

## Consequences and dependencies

Implementation remains blocked until a consumable, versioned JSON report contract exists (a published `1.0.0` JSON Schema and official synthetic golden reports) and implementation is separately authorized.

This ADR does not require the backend to bring Milestone 6 forward. Earlier publication of the schema can be discussed separately. Until then, no frontend directory, package manifest, mock data or component should be created.

The viewer adds a second toolchain (Node/JavaScript) to the repository when implemented. That cost is accepted only with that later implementation authorization.

The viewer cannot show information the report excludes, such as cluster or context identity, ReplicaSet names, UIDs or raw objects. Multi-cluster aggregation and live views remain outside its scope. Any live or API-backed interface would need its own ADR that supersedes the relevant parts of ADR 0001.
