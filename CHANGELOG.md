# Changelog

All notable changes to `nordility` are documented here.

## Unreleased

- Fixed the CLI being unusable on Windows. `web.py` subclassed
  `socketserver.UnixStreamServer` at module scope, which only exists where
  `AF_UNIX` does, so importing the module raised `AttributeError` and
  `nordility --help` could not start — despite the README documenting a
  Windows-first `NordVPN.exe` backend that never touches a Unix socket. The
  class is now defined only where its base exists, and `--unix-socket` reports
  a clear message on platforms without `AF_UNIX` instead of failing at import.
- Declared `Operating System :: Microsoft :: Windows` alongside the existing
  POSIX classifier, matching the documented Windows backend.
- Added the shared `install-check` workflow, which installs the package on
  Linux, macOS and Windows and runs the console script. It is what found the
  import failure above.

- Added `watch-wireguard` plus a systemd installer so NordVPN reconnects/rotates
  automatically re-apply the WireGuard fwmark and policy-routing rule needed for
  private tunnel replies.
- Taught the WireGuard watcher to start configured `wg0` when the interface is
  down but `/etc/wireguard/wg0.conf` is present.
- Hardened WireGuard repair so config ownership is checked before any peer
  endpoint refresh, with `nordlynx` denied even if a same-named config exists.
- Made routing restoration fail closed unless the interface fwmark succeeds
  and an exact priority/fwmark/main-table policy rule exists or is added;
  policy-rule checks no longer use substring matching.
- Added complete WireGuard-fwmark collision detection and rollback of a newly
  created global rule when no authorized interface can be marked.
- Tagged Nordility's exact policy rule with routing protocol `196`, so
  verification rejects foreign rules and rollback deletes only owned state.
- Removed literal CLI token arguments and added a Linux PTY helper that invokes
  `nordvpn login --token` without a positional credential, requires the exact
  NordVPN 5.2 prompt with terminal echo disabled, and only then reads,
  forwards, and wipes the private-stdin token while suppressing child output.
- Added an adversarial Linux Podman regression that widens the prompt/echo race
  and checks process metadata, output suppression, and failed-child cleanup.
- Staged root services from an exact root-owned `/opt/nordility` module
  allowlist instead of executing the user-writable checkout; installed services
  require a separately authenticated Nord client and do not use auto-pass.
- Moved privileged web actions from loopback TCP to a `root:caddy` Unix socket
  with exact HTTPS Origin/Host and JSON checks; TCP mode is status-only.
- Added a private web control surface for NordVPN power, rotation, and country
  selection behind wiring-harness Caddy/mTLS.
- Added the portfolio-standard governance, continuity, and contributor baseline files.
