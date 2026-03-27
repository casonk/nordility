# AGENTS.md

## Purpose

`nordility` is a small Python package for automating NordVPN actions. It exposes:

- a CLI entry point: `nordility`
- a core client: `nordility.client.NordVPNClient`
- compatibility helpers re-exported from `nordility.__init__`

The codebase is intentionally small and dependency-light. Keep changes narrow and preserve the existing public API unless the task explicitly requires a breaking change.

## Repository Layout

- `src/nordility/client.py`: core behavior, backend resolution, command construction, group pools, compatibility wrappers
- `src/nordility/cli.py`: `argparse` CLI
- `src/nordility/__main__.py`: `python -m nordility` entry point
- `src/nordility/__init__.py`: public re-exports
- `tests/test_client.py`: unit tests for backend selection and command generation
- `docs/contributor-architecture-blueprint.md`: repo architecture overview
- `docs/diagrams/repo-architecture.puml`: architecture diagram source
- `docs/diagrams/repo-architecture.drawio`: draw.io architecture source
- `README.md`: install, CLI, and API usage
- `pyproject.toml`: package metadata and console script definition

## Setup And Commands

From a fresh checkout, the package is not importable unless you either install it or set `PYTHONPATH=src`.

Recommended local setup:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Verified repo-root commands:

```bash
PYTHONPATH=src python -m nordility --help
PYTHONPATH=src python -m unittest discover -s tests
```

If you install the package in editable mode, the CLI also works as:

```bash
nordility --help
```

## Architecture Notes

There are two execution backends:

- `windows`: launches `NordVPN.exe` with the original flag-based workflow
- `cli`: runs the `nordvpn` terminal client

Backend resolution is centralized in `resolve_backend()`. `auto` selects:

- `windows` when the executable ends with `.exe`
- `cli` otherwise

Group naming matters:

- internal group constants use underscore-separated names such as `United_States`
- the `windows` backend preserves underscores
- the `cli` backend converts underscores to spaces before execution

`client.py` is written to be testable through dependency injection:

- `launcher` for Windows-style `subprocess.Popen`
- `runner` for CLI-style `subprocess.run`
- `sleeper` for wait behavior
- `rng` for deterministic group selection in tests

Prefer extending that pattern instead of introducing hard-to-mock direct process calls in new code.

## Change Guidance

When modifying behavior, preserve these expectations unless the task says otherwise:

- keep runtime dependencies at zero unless there is a strong reason to add one
- preserve the existing compatibility helpers: `connect_vpn_server`, `disconnect_vpn_server`, `change_vpn_server`
- preserve the current CLI verbs: `connect`, `disconnect`, `change`, `list-groups`
- keep user-facing success strings stable when possible; tests and callers may rely on them
- keep environment variable support intact: `NORDILITY_EXECUTABLE`, `NORDVPN_EXECUTABLE`, `NORDILITY_BACKEND`
- update the architecture docs when changing public flow or backend semantics: `docs/contributor-architecture-blueprint.md` and `docs/diagrams/repo-architecture.puml`
- keep `docs/diagrams/repo-architecture.drawio` in sync with the PlantUML source when adjusting the flow

If you add a command, backend option, or public function, update both `README.md` and tests in the same change.

## Testing Expectations

Add or update unit tests for any behavior change in:

- backend resolution
- command construction
- error handling
- group formatting or selection
- CLI-visible behavior

This project currently uses the standard library `unittest` framework. Match the existing test style unless the task explicitly asks for a test framework migration.

## Practical Notes For Agents

- Use `PYTHONPATH=src` for ad hoc local runs from the repo root.
- This project is cross-platform in intent, but the original workflow is Windows-first.
- Avoid writing tests that require a real NordVPN installation or network access.
- Favor small, explicit changes over abstractions; the current code is intentionally direct.

## Agent Memory

Use `./CHATHISTORY.md` as the standard local handoff file for this repo.

- It is local-only and gitignored.
- Read it after `AGENTS.md` when resuming work.
- Keep entries brief and focused on backend behavior, tests, blockers, and next steps.
