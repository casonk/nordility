# Changelog

All notable changes to `nordility` are documented here.

## Unreleased

- Added `watch-wireguard` plus a systemd installer so NordVPN reconnects/rotates
  automatically re-apply the WireGuard fwmark and policy-routing rule needed for
  private tunnel replies.
- Taught the WireGuard watcher to start configured `wg0` when the interface is
  down but `/etc/wireguard/wg0.conf` is present.
- Added a private localhost web control surface for NordVPN power, rotation,
  country selection, and auto-pass-backed auto-login behind wiring-harness
  Caddy/mTLS.
- Added the portfolio-standard governance, continuity, and contributor baseline files.
