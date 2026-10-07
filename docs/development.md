# Local development

Milestone 1 is complete and committed. The authorized [Milestone 2 domain model](domain-model.md) adds eleven immutable records, pure quantity conversion, and synthetic unit tests; it was accepted on 2026-09-29. M3.1 adds the SDK/h11 dependencies and inert collection package; M3.2A adds restricted local document loading with direct PyYAML==6.0.3. There is no CLI entry point, Kubernetes access, eligibility/rule logic or reporting. [ADR 0006](adr/0006-python-project-foundation.md) remains Accepted on 2026-09-28; Accepted [ADR 0007](adr/0007-explicit-container-started.md) records the approved startup clarification. Milestone 3 architecture/design is complete under Accepted [ADR 0008](adr/0008-restricted-kubeconfig-and-bounded-transport.md), dated 2026-09-30; M3.2B adds explicit selection and endpoint/authentication preflight; M3.2 is complete and committed; M3.3A adds only the trusted local credential-file boundary. Credential parsing, TLS, network and M3.3B or later behavior require separate authorization.

## Environment and dependencies

Use CPython **3.13.15**, pinned in `.python-version`. The package declares `requires-python = ">=3.13"`; this is an installation constraint, not a claim that later Python versions have been tested. The foundation was checked with uv **0.12.20** on Darwin 24.6.0 / x86_64. macOS 15 / x86_64 is the development reference; Ubuntu 24.04 LTS / x86_64 under the documented resolved/procfs profile is the initial runtime validation priority. macOS is not an initial runtime transport obligation. Neither is an established OpenKube runtime environment. See the [approved reference-target contract](compatibility.md) for versions, authentication exclusions, upstream evidence, and future validation gates.

Install uv separately using its [official instructions](https://docs.astral.sh/uv/getting-started/installation/). From the repository root:

```sh
uv python install 3.13.15
uv sync --locked
```

`uv sync --locked` creates `.venv`, installs the project in editable mode, and installs the locked development group. Editable installation makes source changes available without reinstalling after each edit. The command fails if dependency declarations and the lock disagree. Do not silently select another Python version if the pinned interpreter is unavailable.

In VS Code, use **Python: Select Interpreter** and choose `.venv/bin/python`. `uv run` uses this environment without shell activation. Once synchronized, `.venv/bin/pytest` and the other installed tool executables are also usable directly without invoking uv's cache or synchronization machinery.

| File or directory | Responsibility |
| --- | --- |
| `src/openkube_optimizer/` | Installed package, side-effect-free initializers, immutable domain facts, and pure quantity conversion |
| `tests/` | Developer checks; pytest importlib mode exercises the installed package without path manipulation |
| `pyproject.toml` | Package metadata, direct dependency declarations, build backend, and tool settings |
| `.venv/` | Ignored local interpreter environment and installed packages; not a container or security boundary |
| `uv.lock` | Committed dependency resolution, including transitive dependencies and platform markers; unchanged by Milestone 2 |
| `.python-version` | Exact development interpreter selection, separate from package compatibility metadata |

The only direct development dependencies are **mypy 2.3.1**, **pytest 9.1.1**, and **Ruff 0.16.9** in the initial lock. The `dev` group is not published as runtime requirements. `uv_build==0.12.20` is pinned separately in the build-system requirements; the development lock is not a substitute for the build-backend pin. uv itself is a separately installed tool. The package version is `0.1.0.dev0`, not a released v0.1 application.

Commit `pyproject.toml`, `uv.lock`, and `.python-version`; never commit `.venv` or edit the lock by hand. Initial lock generation uses `uv lock`. Later dependency changes and upgrades must be deliberate, followed by synchronization and checks. For example, `uv lock --upgrade-package pytest` updates that tool's resolution for review. Ordinary setup should use `--locked`, not silently regenerate dependency choices.

Setup can download Python and packages from their distribution services. Tests perform no network or cluster operations. These development downloads do not add runtime telemetry or an application egress path. A lock does not reproduce the operating system or guarantee dependency security.

## Local quality checks

After synchronization, run:

```sh
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy src tests
uv run --locked pytest
uv build
```

Ruff checks its default error rules (`E4`, `E7`, `E9`, `F`) plus import sorting (`I`); its formatter uses standard defaults. mypy checks source and tests in strict mode, with one import-only `import-untyped` exception for PyYAML 6.0.3, which ships no typing metadata. The adapter graph and outcomes remain typed; no stub dependency is added. To apply formatting intentionally, use `uv run --locked ruff format .`.

The package smoke test checks installed distribution metadata. Domain tests exercise the [documented invariants](domain-model.md#tests-and-acceptance-boundary), exact/bounded conversion, safe representations/errors, and an isolated dependency-boundary import. They do not validate API integration, eligibility calculations, report safety, or complete-run UID lifetime. Review local Markdown links and cross-document status consistency when editing documentation. No documentation framework or task runner is required.

## Built-wheel verification

`uv build` writes a source distribution and wheel under ignored `dist/`. Check the wheel independently of the editable installation. For the current development version, in a macOS/Linux shell:

```sh
OPENKUBE_WHEEL="$(pwd)/dist/openkube_optimizer-0.1.0.dev0-py3-none-any.whl"
OPENKUBE_WHEEL_ENV="$(mktemp -d "${TMPDIR:-/tmp}/openkube-wheel.XXXXXX")"
uv venv --python 3.13.15 "$OPENKUBE_WHEEL_ENV"
uv export --locked --no-dev --no-emit-project --format requirements-txt --output-file "$OPENKUBE_WHEEL_ENV/runtime.txt"
uv pip sync --python "$OPENKUBE_WHEEL_ENV/bin/python" "$OPENKUBE_WHEEL_ENV/runtime.txt"
uv pip install --no-index --no-deps --python "$OPENKUBE_WHEEL_ENV/bin/python" "$OPENKUBE_WHEEL"
(
    cd "$OPENKUBE_WHEEL_ENV" || exit
    "$OPENKUBE_WHEEL_ENV/bin/python" -I -c 'import openkube_optimizer; from importlib.metadata import version; print(openkube_optimizer.__file__); assert version("openkube-optimizer") == "0.1.0.dev0"'
)
```

The printed module location should be inside the temporary environment's `site-packages`, not the repository's `src/`. `-I` ignores user site packages and Python environment variables. The fresh environment receives runtime dependencies from the lock export (with hashes), then the built wheel without dependency re-resolution. The dependency sync can download packages. The final `--no-index --no-deps` step validates the local wheel; it no longer implies a dependency-free package. Remove that specific temporary environment after inspection; it is not part of the repository.

## Repository hygiene and test data

The `.gitignore` excludes environments, bytecode, tool caches, build artifacts, and common local sensitive files. It is not a secret-protection mechanism. Do not put credentials, kubeconfigs, production objects, or real reports into the repository. Keep local editor preferences outside shared project configuration unless needed by the team.

Use synthetic data only when later tests require data. **Do not create `tests/fixtures/` until there is a concrete fixture to add.** The foundation introduces no placeholder application modules, Kubernetes client, CLI framework, CI, containers, or pre-commit configuration.

## Foundation validation and Milestone 1 completion

Foundation validation completed on 2026-09-28 with CPython 3.13.15 and uv 0.12.20 on Darwin 24.6.0 / x86_64:

| Executed check | Result |
| --- | --- |
| `uv python install 3.13.15` | Exact approved interpreter installed; no substitution |
| `uv lock` | Resolved 14 entries, including the project and platform-conditional dependencies |
| `uv sync --locked` | Created a fresh `.venv`; installed the project and 12 development/transitive packages |
| `.venv/bin/ruff check .` | Passed |
| `.venv/bin/ruff format --check .` | Passed |
| `.venv/bin/mypy src tests` | Passed in strict mode for both Python files |
| `.venv/bin/pytest` | One smoke test passed |
| `uv build` | Built the source distribution, then the wheel from that source distribution |
| Clean-wheel installation and isolated import | Passed outside the checkout using a temporary environment, `uv --no-cache venv`, and `uv --no-cache pip install --no-index --no-deps`; temporary environment removed afterward |
| Wheel metadata and contents | Correct version, Apache-2.0 license/attribution, no runtime requirements or entry points; initializer is the only Python module |
| Git ignore/tracking and source-distribution checks | Environments/caches/build artifacts ignored; no ignored artifacts tracked or bundled |
| Scope and documentation checks | Only a docstring in the initializer and one smoke test; no fixtures directory; all local Markdown link targets exist; accepted ADRs 0001–0005 byte-for-byte unchanged |

Quality tools were executed directly from the newly locked/synchronized `.venv` to avoid unnecessary access to uv's external cache under the agent filesystem sandbox. Initial cache/network restrictions required approved retries for interpreter installation, lock generation, and downloading the official license text. Environment synchronization and building also used approved cache access. No validation failure remains; no application compatibility or security behavior was tested.

At the original Milestone 1 handoff, project files were untracked and the user deferred staging/committing. The user subsequently completed the foundation commit (`1e52383`, `First Commit`) before authorizing Milestone 2. Its new changes must not be staged, committed, or pushed without separate authorization.

The user approved the [initial reference contract](compatibility.md), including its terminology and restricted authentication profile. Foundation implementation, license selection, reference-target documentation, and ADR 0006 review complete Milestone 1. Closure revalidation on 2026-09-28 passed: `uv sync --locked`, Ruff lint/format, strict mypy (two files), pytest (one test), build and isolated clean-wheel installation/import, 109 local documentation links and 32 anchors, and repository/ADR integrity checks. Source, tests, package metadata, the lock, evidence/rule documentation, and ADRs 0001–0005 remained unchanged during that closure. These are historical foundation results; Milestone 2 has since been separately authorized, implemented, and accepted on 2026-09-29. No cluster compatibility, authentication, or application-filesystem guarantee has been established. Required runtime integration checks remain in later milestones; no SDK is installed.

## Milestone 2 validation — accepted 2026-09-29

Validation on 2026-09-29 passed with the existing CPython 3.13.15 environment and unchanged toolchain:

| Executed check | Result |
| --- | --- |
| `uv sync --locked` | Passed using approved external-cache access after the sandbox blocked the initial attempt; lock unchanged |
| `.venv/bin/ruff check .` | Passed |
| `.venv/bin/ruff format --check .` | Passed |
| `.venv/bin/mypy src tests` | Strict checking passed for all seven source/test files |
| `.venv/bin/pytest -q` | 115 cases passed, including the existing packaging smoke test and domain import-boundary test |
| `uv build` | Source distribution and wheel built with the existing pinned backend |
| Wheel inspection | All four package source modules included; no runtime requirements or entry points |
| Local Markdown link/anchor check | 135 local targets and 40 anchors passed across 23 Markdown files |
| Scope and Git integrity | Eleven approved records only; no AnalysisSettings or later application modules; no fixtures directory; toolchain/lock and Accepted ADRs 0001–0006 unchanged; no staged or ignored tracked files |

The documentation/integrity checks used read-only Python/AST/path checks, wheel inspection, and Git comparisons; no additional validation framework or dependencies were added. Quantity/type checks and dependency-boundary tests are reproducible through pytest. No cluster, authentication, runtime report/filesystem, or complete-run UID-lifetime validation was performed. ADR 0007 and Milestone 2 were explicitly accepted on 2026-09-29; no staging, commit, push, or Milestone 3 work was performed.

Administrative closeout on 2026-09-29 reran `uv sync --locked`, Ruff lint and formatting checks, strict mypy (seven files), pytest (115 passing cases, including static and isolated-import dependency checks), package build, documentation links/consistency (135 local targets, 40 anchors), wheel/dependency inspection, and `git diff --check`. All passed. Snapshot comparison confirmed that closeout changed only acceptance/status documentation: domain implementation/tests and ADR 0007's technical scope, decision, and rationale were unchanged. `pyproject.toml`, `uv.lock`, and ADRs 0001–0006 remain unchanged from the foundation commit; no runtime or Kubernetes SDK dependency exists. Git status contains only the accepted Milestone 2 changes and their administrative closeout, with no staged files. Milestone 3 has not started.

## Milestone 3 design and feasibility — 2026-09-30

Historical design/consistency snapshot before the separately authorized slice below.

Accepted [ADR 0008](adr/0008-restricted-kubeconfig-and-bounded-transport.md) completes M3 design; the documentation consistency pass is complete. M3 implementation, dependencies, RBAC/cluster work and Git publication remain separately authorized actions. Earlier validation sections above are historical snapshots, not the current SDK investigation status.

The [compatibility evidence](compatibility.md#disposable-feasibility-evidence--2026-09-30) records disposable Ubuntu transport/credential probes, separate from foundation/domain checks. Generated SDK dispatch, Varlink deadlines, bounded synthetic TCP/TLS/HTTP, CA snapshots and descriptor-backed credential loading were exercised outside this repository. No Kubernetes authentication/RBAC/platform integration or report filesystem support was established. Synthetic timing observations are not hard native setup cancellation or worst-case CPU/memory proofs.

The accepted runtime target is Ubuntu 24.04 LTS x86_64 with active trusted resolved Varlink and procfs; macOS is development-only. M3 inventory is Pods/Deployments/ReplicaSets; M4 adds PodMetrics. Intended `kubernetes==36.0.3` and approved `h11==0.16.0` are not installed in the project; runtime dependencies and lock remain unchanged. No pyOpenSSL or direct cryptography dependency is required.

Local trusted-file/native TLS setup is guarded and counted against existing total budgets, not hard-preemptible; controlled resolution through HTTP has the transport deadline. Follow ADR 0008 for stable trusted credentials, rejecting callbacks, no copies and cleanup rather than copying disposable probes into application code. This documentation-only pass runs link/anchor, contract preservation, historical ADR, dependency and Git checks; no application test/build rerun is required.

## Milestone 3 slice 1 — dependencies and import boundary

Explicitly authorized after the committed ADR 0008 documentation pass. Direct runtime requirements are exactly `kubernetes==36.0.3` and `h11==0.16.0`; no existing dependency versions were upgraded. The SDK adds requests, aiohttp, PyYAML and their dependencies transitively; these are not direct selections or authorization to use their transport/authentication behavior. No pyOpenSSL, cryptography or cloud SDK is added. See `uv.lock` for exact transitive versions.

Only `collection/__init__.py` is introduced in application source, with a package-boundary docstring and no executable behavior. The documented kubernetes/projection/ownership modules remain absent until needed. Domain source and M2 tests remain unchanged. Six new boundary cases check static SDK confinement, pure-layer independence, relative/from import scanning, exact dependency imports/metadata, and isolated import behavior. The tests use fresh child interpreters as test isolation only, never as an application transport design. They require no cluster, DNS, kubeconfig or network access.

OpenKube imports are tested with external imports, environment lookups, non-module file reads, sockets, subprocesses and thread starts blocked. The package/collection/domain imports pass without importing kubernetes or h11. Static checks are regression guards, not a security sandbox or a proof about future dynamically executed imports. Existing M2 tests cover rejecting arbitrary nested objects and safe domain representations; no serializer or raw SDK field is added.

The installed SDK is not side-effect-free: top-level import loads config/auth modules, reads `KUBECONFIG` into a default-location constant, attempts optional Google-auth imports, and imports urllib3, whose IPv6 capability probe attempts a local socket/bind. The offline test rejects socket creation before it occurs and records the attempt; it does not perform the bind. Python's macOS pydoc/sysconfig path also reads system-version metadata and environment settings. The test permits that specific OS metadata read, never credential files. No kubeconfig/auth loader, exec-provider execution, DNS/connection, subprocess/thread start or Configuration construction/default setter was observed; `_default` remains None. h11 imports successfully without activating these paths. aiohttp is installed transitively but is not imported by the tested synchronous SDK import; optional Google auth is unavailable in the locked environment.

These findings cover the pinned packages on development CPython 3.13.15, not arbitrary environments or future SDK usage. Python audit hooks cannot prove the absence of all native-library file access. The future adapter must keep SDK imports/activation inside its explicit I/O boundary and enforce ADR 0008 preflight controls; installing a helper-capable dependency does not authorize invoking helpers or global Configuration. No Kubernetes/platform/runtime compatibility is established.

Slice validation on development CPython 3.13.15: `uv add --no-sync` generated the lock; `uv sync --locked` passed; Ruff lint/format passed; strict mypy passed for nine files; all 121 pytest cases passed (115 unchanged existing cases and six new boundary cases). `uv build` produced the source distribution and wheel. A clean external environment received the locked runtime export and built wheel; isolated OpenKube/SDK import checks and `uv pip check` passed. Wheel metadata contains only the two approved requirements, Python >=3.13 and no CLI entry points. No existing dependency version or M2 source/test file changed. The initial uv cache sandbox denial required an authorized retry; no unresolved validation failure remains.


## Milestone 3.2A — restricted document loading

Authorized on 2026-10-04 from `d2ffe24`. PyYAML==6.0.3 is now direct, with no new locked package or version change. Earlier slice validation sections remain historical snapshots. Only `collection/kubeconfig.py` loads the caller's explicit trusted local `Path`; it performs no default-path lookup, selection, authentication or SDK activation. At this historical M3.2A gate, M3.2B was not yet authorized; its later authorization is recorded below.

Internal policy `kubeconfig-input-v1` applies ADR 0008's 1 MiB actual-byte cap (one-byte overflow detection), one document and container depth 32, root at depth 1. Trusted symlinks are accepted after regular-file checks, including the opened descriptor. Filesystem locality/trust is a caller assumption, not inferred from regular-file metadata; remote filesystems and malicious host races remain outside the profile. Native reads are not hard-cancellable.

PyYAML's BaseLoader supplies parsing events only; OpenKube rejects anchors, aliases, explicit tags, merge/duplicate keys and excess depth before constructing affected containers/values. No YAML constructors or implicit scalar resolver are used: scalars remain strings, including numeric/boolean/null/date-looking text. Later selected-field preflight must interpret these deliberately. The minimal structure requires a mapping, exact `apiVersion: v1` / `kind: Config`, and `clusters`, `contexts`, `users` lists; their contents and current-context are not selected or validated here.

The internal redacted holder has no public mapping/serialization API. Keep its private document inside the adapter. Fixed failure outcomes distinguish invalid local input, oversize, invalid UTF-8, malformed YAML, unsupported YAML features and invalid document structure; they carry no source errors, paths or snippets. Reference release does not promise zeroization. Synthetic tests cover byte/depth boundaries, forbidden YAML, descriptor cleanup, redaction and isolated imports/loads with environment, SDK and network activation blocked; these guards are not a security sandbox or runtime-support claim.


## Milestone 3.2B — explicit restricted preflight

Implemented from committed M3.2A `b2b33e4`, with validation on 2026-10-05. No dependency or lock changes. Following the authorized M3.2C origin correction, `collection/preflight.py` consumes the private document plus the exact caller-supplied context; the loader retains the lexical absolute kubeconfig parent at load time. It indexes contexts, clusters and users in that order, rejecting malformed mapping/name entries and duplicate names across each collection. It inspects only selected payloads; current-context and namespace never supply selection/scope. Unsupported unselected payloads remain inert.

Selected mappings use closed key allowlists: context has cluster/user and optional ignored namespace; cluster has server/certificate-authority only; user has either token only or client-certificate/client-key only. Unknown selected fields, including extensions outside these allowlists, fail closed. No raw selected mapping is passed to a client. Eight added fixed failure categories distinguish missing context/cluster/user, invalid named entries, invalid context/cluster/endpoint and unsupported or invalid authentication, without copying input or source errors.

Policy `endpoint-preflight-v1` accepts literal `https://`, ASCII multi-label DNS names (253/63-byte bounds), optional decimal port 1–65535 and an optional fixed prefix. The original hostname case, explicit authority and prefix (including a trailing slash) are retained; absent port means 443. No IP literals/numeric host forms, IDN, trailing-dot host, userinfo, query, fragment, whitespace/control, backslash or percent encoding. Initial prefix segments use ASCII unreserved characters only; empty interior segments, dot segments and parameter delimiters are rejected. No resolution or request construction occurs.

The authorized M3.2C transport envelope requires nonempty opaque tokens containing only visible ASCII U+0021–U+007E. Accepted text is retained exactly: no trimming, normalization, JWT parsing, claim inspection or expiry inference. Relative CA/certificate/key references are joined lexically to the kubeconfig parent captured at load time; later CWD changes do not affect them, and a selected symlink uses its lexical parent. No tilde/environment expansion, symlink resolution, stat/open, certificate parsing or SSL/SDK construction occurs for credential references. Later loading must establish identity/content/trust.

Three private keyword-only, immutable slots records hold connection facts and one of token or certificate-reference authentication. They have fixed redacted representations, no instance dictionaries/dataclass mapping conversion, and reject pickle/state extraction. These are accidental-disclosure guards, not protection from deliberate in-process reflection; tokens remain accessible to the eventual transport and no zeroization is promised. Records contain no raw mappings or namespace scope and must never be logged, persisted or reported. No runtime compatibility follows from synthetic preflight tests. M3.2 is complete and committed at `69e12fd`; M3.3A file-boundary implementation is separately authorized. Credential parsing, TLS and M3.3B or later work remain unauthorized.

## Milestone 3.3A — trusted local credential-file boundary

Implemented from clean `main` at `69e12fd`, with unchanged dependencies. `collection/credentials.py` consumes only the private preflight result. On Linux it opens each selected path with O_PATH/CLOEXEC, classifies through fstat, reopens the pinned regular object through procfs, and checks device/inode/mode/size/mtime/ctime before and after bounded inspection. `credential-input-v1` permits at most 1 MiB per CA/certificate/key file with one-byte overflow detection and short-read handling. No resolve/realpath/readlink or pathname fallback is used. Native reads are not hard-cancellable; metadata is diagnostic rather than an immutable-snapshot guarantee.

The private owner retains CA snapshot bytes and optional client certificate/key read descriptors, with no credential paths, token copy or client inspection-byte copies. Success transfers descriptor ownership to explicit close/context exit; failure closes partial ownership. Close is idempotent, clears retained references, and does not retry Linux close errors. Ordinary repr/state/pickle/reduction/copy/vars/asdict/JSON disclosure is guarded, without an in-process sandbox or zeroization claim.

`tests/unit/test_credentials.py` covers synthetic limits, short reads, overflow despite metadata, nonregular inputs, identity/stability, trusted symlinks, pathname replacement, cleanup, serialization and isolated side-effect guards with negative canaries. Native file-boundary cases require actual Linux O_PATH/procfs and are explicitly skipped on macOS; owner/isolation/profile-rejection checks still run there. Synthetic Unix sockets are test fixtures only. No real credentials, certificate/key parsing, SSLContext, OpenSSL loading, DNS, transport, Kubernetes client, CLI or report integration is included. M3.3B requires separate authorization.

Development validation on macOS/CPython 3.13.15 passes lint/format, strict mypy, locked sync, build, clean-wheel import/profile-rejection guards and dependency inspection. The full suite has 484 passing cases and 48 explicitly skipped native Linux cases; all pre-existing tests remain unchanged. Native O_PATH/procfs opening, identity, bounded-read and partial-failure acceptance is pending a disposable Linux environment; a stopped Docker daemon was observed, not a failed Linux mechanism. This slice is not ready for M3.3B until that acceptance evidence is obtained.
