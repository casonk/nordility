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

- Windows-first support for the original `NordVPN.exe` automation flow
- Optional support for the `nordvpn` terminal CLI through a selectable backend
- Fast and full country pools for randomized server rotation
- A NordVPN/WireGuard watch service that keeps private WireGuard access working
  after external NordVPN reconnects or rotates
- A local web control surface for private Caddy/mTLS access from Safari
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

For auto-pass-backed login defaults, copy [auto-pass.example.ini](/mnt/4tb-m2/git/util-repos/nordility/config/auto-pass.example.ini) to `config/auto-pass.ini`. The CLI will use that file as the default `--keepass-profile` and `--keepass-entry` source for `login`, `connect --auto-login`, and `change --auto-login`.

## Usage

```bash
nordility connect
nordility disconnect
nordility change --speed fast
nordility change --group United_States
nordility watch-wireguard --once
nordility web --host 127.0.0.1 --port 5300
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
but the interface is down, then reapplies the user-managed WireGuard socket
fwmark plus:

```bash
ip rule add fwmark 51820 lookup main priority 100
```

It only changes WireGuard interfaces backed by `/etc/wireguard/<iface>.conf`,
so NordVPN's daemon-managed `nordlynx` fwmark is left alone.

## Private Web Control

The web control surface is a localhost service intended to sit behind
`wiring-harness` Caddy/mTLS:

```bash
sudo ./scripts/install_web_service.sh
sudo systemctl status nordility-web.service --no-pager
```

Default backend:

- Local URL: `http://127.0.0.1:5300`
- Private Caddy URL: `https://nordility.clockwork.internal`

The page exposes power on/off, fast/full rotation, and built-in country
selection. The installed service enables `--auto-login` by default, so a
logged-out NordVPN client is re-authenticated through the repo's auto-pass /
KeePass token defaults. After each VPN action it runs the same WireGuard repair
path used by the watcher so `wg0` remains available for phone access.

After adding `nordility.clockwork.internal` to the local `wiring-harness`
service registry, refresh the shared certificate SANs and Caddy config:

```bash
cd ../wiring-harness
WH_WG_IP=10.99.0.1 bash scripts/setup-mtls.sh --refresh-server
sudo python3 scripts/setup_caddy.py --provision
```
