# Local development

Milestone 1 is complete and committed. The authorized [Milestone 2 domain model](domain-model.md) adds eleven immutable records, pure quantity conversion, and synthetic unit tests; it was accepted on 2026-09-29. There is no CLI entry point, runtime dependency, Kubernetes access, eligibility/rule logic, or reporting. [ADR 0006](adr/0006-python-project-foundation.md) remains Accepted on 2026-09-28; Accepted [ADR 0007](adr/0007-explicit-container-started.md) records the approved startup clarification. Milestone 3 is not authorized.

## Environment and dependencies

Use CPython **3.13.15**, pinned in `.python-version`. The package declares `requires-python = ">=3.13"`; this is an installation constraint, not a claim that later Python versions have been tested. The foundation was checked with uv **0.12.20** on Darwin 24.6.0 / x86_64. macOS 15 / x86_64 is the development reference; Ubuntu 24.04 LTS / x86_64 is a planned validation target. Neither is an established OpenKube runtime environment. See the [approved reference-target contract](compatibility.md) for versions, authentication exclusions, upstream evidence, and future validation gates.

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

Ruff checks its default error rules (`E4`, `E7`, `E9`, `F`) plus import sorting (`I`); its formatter uses standard defaults. mypy checks source and tests in strict mode, without ignored imports or other exceptions. To apply formatting intentionally, use `uv run --locked ruff format .`.

The package smoke test checks installed distribution metadata. Domain tests exercise the [documented invariants](domain-model.md#tests-and-acceptance-boundary), exact/bounded conversion, safe representations/errors, and an isolated dependency-boundary import. They do not validate API integration, eligibility calculations, report safety, or complete-run UID lifetime. Review local Markdown links and cross-document status consistency when editing documentation. No documentation framework or task runner is required.

## Built-wheel verification

`uv build` writes a source distribution and wheel under ignored `dist/`. Check the wheel independently of the editable installation. For the current development version, in a macOS/Linux shell:

```sh
OPENKUBE_WHEEL="$(pwd)/dist/openkube_optimizer-0.1.0.dev0-py3-none-any.whl"
OPENKUBE_WHEEL_ENV="$(mktemp -d "${TMPDIR:-/tmp}/openkube-wheel.XXXXXX")"
uv venv --python 3.13.15 "$OPENKUBE_WHEEL_ENV"
uv pip install --no-index --no-deps --python "$OPENKUBE_WHEEL_ENV/bin/python" "$OPENKUBE_WHEEL"
(
    cd "$OPENKUBE_WHEEL_ENV" || exit
    "$OPENKUBE_WHEEL_ENV/bin/python" -I -c 'import openkube_optimizer; from importlib.metadata import version; print(openkube_optimizer.__file__); assert version("openkube-optimizer") == "0.1.0.dev0"'
)
```

The printed module location should be inside the temporary environment's `site-packages`, not the repository's `src/`. `-I` ignores user site packages and Python environment variables. The fresh environment is unseeded; installing the wheel with `--no-index --no-deps` proves the current package requires no downloaded runtime dependency. Remove that specific temporary environment after inspection; it is not part of the repository.

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
