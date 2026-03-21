# Contributor Architecture Blueprint

This document is a concise map of how CLI requests and Python API calls flow through `nordility`.

## Visual Diagram

- PlantUML source: `docs/diagrams/repo-architecture.puml`
- PlantUML renders:
  - `docs/diagrams/repo-architecture.puml.png`
  - `docs/diagrams/repo-architecture.puml.svg`

Render with any local PlantUML installation:

```bash
plantuml -tpng -tsvg docs/diagrams/repo-architecture.puml
```

## High-Level Layers

1. Entry Surface (`src/nordility/cli.py`, `src/nordility/__main__.py`, `src/nordility/__init__.py`)
   - The CLI exposes `connect`, `disconnect`, `change`, and `list-groups`.
   - `python -m nordility` delegates to the same CLI entry point.
   - `nordility.__init__` re-exports the compatibility helpers and the core client.
2. Configuration Layer (`src/nordility/client.py`)
   - `resolve_executable()` chooses the executable from explicit arguments, then `NORDILITY_EXECUTABLE`, then `NORDVPN_EXECUTABLE`, then the default Windows path.
   - `resolve_backend()` normalizes `auto`, `windows`, and `cli`, with optional override through `NORDILITY_BACKEND`.
   - `auto` resolves to `windows` when the executable ends in `.exe`; otherwise it resolves to `cli`.
3. Core Client Layer (`src/nordility/client.py`)
   - `NordVPNClient` owns command building, group selection, wait handling, and backend dispatch.
   - `connect()` and `disconnect()` build backend-specific commands and return `CommandResult`.
   - `change()` selects an explicit or random group and applies default waits of 10 seconds for `fast` and 30 seconds for `full`.
   - `list_groups()` and `pick_group()` expose the built-in country pools.
4. Backend Execution Layer (`src/nordility/client.py`)
   - The `windows` backend launches `NordVPN.exe` via `subprocess.Popen`.
   - The `cli` backend runs the `nordvpn` terminal CLI via `subprocess.run`.
   - Internal group constants keep underscore-separated names such as `United_States`.
   - The `cli` backend translates underscores to spaces before execution; the `windows` backend preserves the original group name.
5. Error + Result Layer (`src/nordility/client.py`, `src/nordility/cli.py`)
   - `CommandResult` carries the executed command, message, group, return code, stdout, and stderr.
   - `ConfigurationError` handles invalid backend or speed values.
   - `CommandExecutionError` wraps process-launch and non-zero exit failures.
   - The CLI prints success messages on stdout and errors on stderr, returning exit code `1` for `NordilityError`.
6. Testing Layer (`tests/test_client.py`)
   - Tests use standard-library `unittest`.
   - The client is built for injection of `launcher`, `runner`, `sleeper`, and `rng`, which keeps tests deterministic and avoids requiring a real NordVPN installation.

## Request Flow

### CLI Flow

`nordility` or `python -m nordility`  
-> `build_parser()` parses flags and subcommands  
-> `main()` configures logging and instantiates `NordVPNClient`  
-> `NordVPNClient` resolves executable and backend  
-> command builders produce backend-specific command tuples  
-> backend execution launches the process  
-> `CommandResult` or `NordilityError` returns to the CLI  
-> CLI prints the final message and exits with an appropriate status

### Python API Flow

Compatibility helpers:

- `connect_vpn_server()`
- `disconnect_vpn_server()`
- `change_vpn_server()`

Each helper:

- creates a fresh `NordVPNClient`
- delegates to the corresponding client method
- returns either a status string or the full `CommandResult`
- preserves legacy string-return behavior when `status=True`

## Core Invariants

- Public backends are limited to `auto`, `windows`, and `cli`.
- Internal group pools use underscore-separated country names.
- `cli` execution converts underscores to spaces at the final command boundary only.
- Windows execution is launch-oriented and can sleep after `Popen`; CLI execution is synchronous and raises on non-zero exit.
- The compatibility helper names and CLI verbs are part of the public surface and should remain stable unless a breaking change is intentional.

## Key Entry Points

- CLI entry point: `src/nordility/cli.py`
- Module entry point: `src/nordility/__main__.py`
- Core client + wrappers: `src/nordility/client.py`
- Public package surface: `src/nordility/__init__.py`
- Current unit tests: `tests/test_client.py`

## Testing Strategy

- Primary local command from a raw checkout:

```bash
PYTHONPATH=src python -m unittest discover -s tests
```

- Ad hoc CLI verification from a raw checkout:

```bash
PYTHONPATH=src python -m nordility --help
```

Focus tests on:

- backend resolution
- command tuple construction
- underscore-to-space group formatting
- default wait and random-group behavior
- error propagation and CLI-visible behavior
