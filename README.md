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
- Draw.io source: `docs/diagrams/repo-architecture.drawio`
- Rendered diagram targets:
  - `docs/diagrams/repo-architecture.puml.png`
  - `docs/diagrams/repo-architecture.puml.svg`

## Features

- Platform-agnostic VPN automation through two interchangeable backends: the
  original `NordVPN.exe` flow on Windows, and the `nordvpn` terminal CLI on
  Linux and macOS
- Backend auto-detection, so the same commands work unchanged on each platform
- Fast and full country pools for randomized server rotation
- A NordVPN/WireGuard watch service that keeps private WireGuard access working
  after external NordVPN reconnects or rotates
- A local web control surface for private Caddy/mTLS access from Safari
- No third-party runtime dependencies
- Compatibility helpers that preserve the original function names

## Platform support

`nordility` began as a Windows-first tool wrapping `NordVPN.exe`. It is now
platform-agnostic: the package installs and the CLI runs on Linux, macOS and
Windows, verified on each by CI on every push.

What limits a given command is rarely `nordility` itself. It drives whichever
NordVPN executable is present, so support follows two separate questions: does
this package run here, and is there a NordVPN binary for it to drive?

| Feature | Linux | macOS | Windows |
| --- | :---: | :---: | :---: |
| Package installs, CLI runs, `--help` works | yes | yes | yes |
| `NordVPN.exe` backend | — | — | yes |
| `nordvpn` CLI backend | yes | if present | — |
| `web` over TCP (status only) | yes | yes | yes |
| `web --unix-socket` (privileged actions) | yes | yes | no |
| `login --token` via KeePass | yes | no | no |
| `watch-wireguard` and its systemd units | yes | no | no |

Backend selection is by executable path, not by OS: a path ending in `.exe`
selects the Windows backend, anything else selects the CLI backend. So macOS
resolves to the CLI backend and works wherever a `nordvpn` binary is on `PATH`
— NordVPN ships that CLI for Linux, so on macOS this depends on what you have
installed rather than on anything here.

The rest is the host OS having a facility or not. `web --unix-socket` needs
`AF_UNIX`, which Windows does not provide; run `web` without it for the
status-only TCP interface. `watch-wireguard` repairs Linux policy-routing rules
and installs systemd units, so it is inherently Linux-only. `login --token`
guards on `sys.platform` for the PTY and core-dump hardening it relies on.

Where a feature is unavailable the CLI reports it and exits, rather than
failing obscurely.

## Install

```bash
python -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e .
```

## Configure

By default, `nordility` uses:

- Windows backend: `C:/Program Files/NordVPN/NordVPN.exe`
- CLI backend: `nordvpn`

You can override the executable with either environment variable. On Linux or
macOS:

```bash
export NORDILITY_EXECUTABLE="/usr/bin/nordvpn"
export NORDILITY_BACKEND="cli"
```

On Windows:

```powershell
$env:NORDILITY_EXECUTABLE = "C:/Program Files/NordVPN/NordVPN.exe"
$env:NORDILITY_BACKEND = "windows"
```

Neither is usually needed: `auto` infers the backend from the executable path.

The accepted backends are:

- `auto`
- `windows`
- `cli`

`auto` infers `windows` for `.exe` executables and `cli` otherwise.

For auto-pass-backed login defaults, copy [`config/auto-pass.example.ini`](config/auto-pass.example.ini) to `config/auto-pass.ini`. The CLI will use that file as the default `--keepass-profile` and `--keepass-entry` source for `login`, `connect --auto-login`, and `change --auto-login`.

Literal `--token` input is intentionally unsupported because it exposes the
credential in the caller's process arguments. On Linux, KeePass-resolved
tokens pass over a private stdin pipe to `nordility.token_login`; that helper
validates the root-owned official CLI, disables core dumps/process dumpability,
and launches `nordvpn login --token` in a PTY with no positional credential.
It verifies consent is disabled, waits for NordVPN 5.2's exact prompt and
disabled `ECHO`/`ECHONL`, and only then reads, forwards, and wipes the token
while discarding all child output. Prompt drift fails closed; there is no
credential-bearing fallback. The token is also redacted from caller errors and
results.

## Usage

```bash
nordility connect
nordility login
nordility disconnect
nordility change --speed fast
nordility change --group United_States
nordility watch-wireguard --once
nordility web --host 127.0.0.1 --port 5300  # status only; actions disabled
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

## NordVPN/WireGuard Watch Service

NordVPN reconnects and server rotations can flush Linux policy-routing rules.
If this host is also serving a private WireGuard tunnel, that can route phone
handshake replies through `nordlynx` instead of the real gateway.

Run one repair pass:

```bash
PYTHONPATH=src python -m nordility --backend cli watch-wireguard --once
```

Install the resident systemd watcher:

```bash
sudo ./scripts/install_wireguard_watch_service.sh
sudo systemctl status nordility-wireguard-watch.service --no-pager
```

The watcher detects NordVPN status/NordLynx endpoint changes and routing drift,
starts `wg0` via `wg-quick@wg0.service` if `/etc/wireguard/wg0.conf` exists
but the interface is down, then derives a config-owned interface allowlist
before it reads or resets peer endpoints. It reapplies the user-managed
WireGuard socket fwmark plus:

```bash
ip rule add fwmark 51820 lookup main priority 100 protocol 196
```

It only changes WireGuard interfaces backed by `/etc/wireguard/<iface>.conf`,
and it rejects the daemon-managed `nordlynx` name even if a confusingly named
config file exists. A repair is reported as successful only when the interface
fwmark mutation succeeds and the exact priority-`100`, fwmark-`51820`,
lookup-`main`, protocol-`196` rule is already present or is added successfully.
The numeric protocol tag is Nordility's ownership marker, so rollback deletes
only the rule Nordility created. Rules at another priority, for another mark,
table, or protocol, or with a partial mark mask do not satisfy that check.
Before installing the global rule, Nordility inventories every active
WireGuard fwmark and refuses a collision on any interface outside the explicit
mutation allowlist. A newly added rule is rolled back if no target interface
can be marked.

Interface startup is systemd-only. Nordility does not fall back to raw
`wg-quick up`, because doing so would bypass security drop-ins attached to the
`wg-quick@<interface>.service` activation boundary.

## Private Web Control

The privileged web control surface is served only over a root-created Unix
socket intended for `wiring-harness` Caddy/mTLS:

```bash
sudo ./scripts/install_web_service.sh
sudo systemctl status nordility-web.service --no-pager
```

Default backend:

- Local upstream: `unix//run/nordility/web.sock` (`root:caddy`, mode `0660`)
- Private Caddy URL: `https://nordility.clockwork.internal`

TCP mode is deliberately status-only: `POST /api/action` returns `403` even on
loopback. Unix-socket actions additionally require the exact configured HTTPS
`Origin`, matching `Host`, and `application/json`; this prevents loopback
bypass and browser CSRF from replacing Caddy/mTLS as the authorization boundary.

The page exposes power on/off, fast/full rotation, and built-in country
selection. Installed root services deliberately do not accept `--auto-login`
or KeePass options: authenticate the official NordVPN client separately before
starting them. After each VPN action the web service runs the same WireGuard
repair path used by the watcher so `wg0` remains available for phone access.

All three systemd installers stage an explicit Python-module allowlist at
`/opt/nordility` with root ownership and non-writable modes. Root services never
execute Python from the user-writable Git checkout.

After adding `nordility.clockwork.internal` to the local `wiring-harness`
service registry, refresh the shared certificate SANs and Caddy config:

```toml
[[services]]
name        = "nordility"
description = "NordVPN outbound control surface"
owner_repo  = "./util-repos/nordility"
hostname    = "nordility.clockwork.internal"
access_mode = "shared-mtls"
ingress     = "wiring-harness-caddy"
unix_socket = "/run/nordility/web.sock"
```

```bash
cd ../wiring-harness
WH_WG_IP=10.99.0.1 bash scripts/setup-mtls.sh --refresh-server
sudo python3 scripts/setup_caddy.py --provision
```

## Tests

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests -v
bash tests/test_token_login_podman.sh
```

The container test runs the Linux-only helper against a deliberately delayed
no-echo prompt and checks that accepted and rejected credentials do not escape
through process arguments, the environment, or helper output.
