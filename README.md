# nordility

`nordility` is a standalone extraction of the `nordility.py` tooling from `citegres`, repackaged as a small Python project that is explicitly focused on automating NordVPN actions.

It keeps the original workflow:

- connect to NordVPN
- disconnect from NordVPN
- rotate to a new country/server group

It also adds a usable CLI, packaging metadata, and a small test suite.

## Contributor Docs

- Architecture blueprint: `docs/contributor-architecture-blueprint.md`
- Diagram source: `docs/diagrams/repo-architecture.puml`
- Rendered diagram targets:
  - `docs/diagrams/repo-architecture.puml.png`
  - `docs/diagrams/repo-architecture.puml.svg`

## Features

- Windows-first support for the original `NordVPN.exe` automation flow
- Optional support for the `nordvpn` terminal CLI through a selectable backend
- Fast and full country pools for randomized server rotation
- No third-party runtime dependencies
- Compatibility helpers that preserve the original function names

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Configure

By default, `nordility` uses:

- Windows backend: `C:/Program Files/NordVPN/NordVPN.exe`
- CLI backend: `nordvpn`

You can override the executable with either environment variable:

```bash
export NORDILITY_EXECUTABLE="C:/Program Files/NordVPN/NordVPN.exe"
export NORDILITY_BACKEND="windows"
```

The accepted backends are:

- `auto`
- `windows`
- `cli`

`auto` infers `windows` for `.exe` executables and `cli` otherwise.

## Usage

```bash
nordility connect
nordility disconnect
nordility change --speed fast
nordility change --group United_States
nordility list-groups --speed full
```

If you do not install the package, you can still run it from the repo root:

```bash
PYTHONPATH=src python -m nordility change --speed fast
```

## Python API

```python
from nordility import change_vpn_server, connect_vpn_server, disconnect_vpn_server

print(connect_vpn_server())
print(change_vpn_server(speed="fast"))
print(disconnect_vpn_server())
```

For more control, use `NordVPNClient` directly.
