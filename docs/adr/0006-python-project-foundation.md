# ADR 0006: Python project foundation

- Status: Accepted
- Date: 2026-09-28
- Accepted: 2026-09-28
- Authority: The user approved the toolchain, Apache-2.0 license, foundation implementation, and reference-target contract, and explicitly authorized acceptance after verifying this ADR against the implemented and validated foundation. Acceptance does not authorize Milestone 2 or a Git commit.

## Context

OpenKube needs a reproducible local environment, an installable Python package, and small quality checks before application development. The accepted architecture favors simple modules and introduces dependencies only for concrete needs. This foundation does not change ADRs 0001–0005 or implement their application behavior.

## Decision

- Use CPython 3.13, pinning development to 3.13.15 in `.python-version`. Declare `requires-python = ">=3.13"`; this installation constraint is not a claim of tested compatibility with later Python versions.
- Use uv for interpreter/environment/dependency management. Commit `uv.lock`, exclude `.venv`, and use `uv sync --locked` and `uv run --locked` for normal development. Record the validated uv version in the development guide.
- Use `uv_build==0.12.20` as an explicitly pinned build backend, separate from development/runtime dependencies. Keep package metadata and tool settings in `pyproject.toml`.
- Preserve the accepted `src/openkube_optimizer/` layout and distribution name `openkube-optimizer`. Use development version `0.1.0.dev0`. Add no CLI entry point or runtime dependencies.
- Use one development dependency group: pytest, Ruff, and mypy, with exact resolved versions in the lock file. Use pytest importlib mode against the installed package, Ruff's default error rules plus import sorting and its formatter, and strict mypy checking for source and tests.
- Add only a side-effect-free package initializer and one package/import metadata smoke test. Create synthetic fixture files and their directory only when a later milestone needs them. Never use production data or credentials in tests.
- License the project under Apache License 2.0 with attribution `Copyright 2026 Luis Assis`.

## Alternatives

Python 3.14 is a reasonable future baseline; 3.13 matches the existing developer environment's minor version and requires no newer language features. Standard `venv` plus pip and pip-tools would work but require more separate workflows. Hatchling is an alternative backend for more specialized packaging needs. A flat package layout is simpler initially but makes accidental checkout imports easier. unittest avoids a test dependency; pytest offers concise assertions and later parameterized boundary tests. Flake8/isort and Black could replace Ruff at the cost of additional tools. Pyright is a viable alternative to mypy; maintaining two canonical type checkers has no current benefit. MIT is a shorter permissive license; the user chose Apache-2.0.

## Consequences and validation

The lock records dependency resolution, not an entire operating system. Interpreter and build backend pins are separate and require deliberate maintenance. Package checks do not establish Kubernetes compatibility, security controls, or analysis correctness. Dependencies may need downloading during setup; tests need no cluster or network access.

Run lock synchronization, Ruff lint/format checks, strict mypy, pytest, and package builds. Verify the built wheel in a fresh environment outside the checkout. Keep generated environments, caches, and build artifacts out of version control. The [development guide](../development.md) records commands and validation evidence.

The approved [reference-target contract](../compatibility.md) records the selected client/Kubernetes/Metrics API versions, development reference, planned platform validation, and restricted authentication profile. These are initial references/planned validation targets, not established OpenKube runtime support. Only repository foundation behavior has been locally validated. No Kubernetes SDK, CLI framework, fixture directory, application model, CI, container, or pre-commit configuration is introduced. Later milestones require separate authorization.

## Acceptance review

Reviewed the actual package metadata, interpreter/backend pins, lock file, source/test layout, license, and quality-tool settings against this decision. The package contains only a side-effect-free initializer, one installed-package smoke test, and no runtime dependencies or entry points. Lock synchronization, Ruff, strict mypy, pytest, source/wheel builds, and clean-wheel import checks pass as recorded in the development guide. ADRs 0001–0005 retain their original contents. The lock is ready for version control; staging and the first commit remain explicitly deferred for user review. Milestone 1 implementation/documentation is complete; acceptance is not a runtime compatibility claim.
