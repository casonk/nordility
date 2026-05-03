#!/usr/bin/env bash
# install_wireguard_watch_service.sh - install the NordVPN/WireGuard repair watcher

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_NAME="nordility-wireguard-watch.service"
UNIT_DIR="/etc/systemd/system"
PYTHON_BIN="${PYTHON_BIN:-python3}"
INTERVAL_SECONDS="5"
STABILIZE_SECONDS="2"
WIREGUARD_FWMARK="51820"
WIREGUARD_INTERFACE="wg0"
IP_RULE_PRIORITY="100"
RENDER_ONLY=0
ENABLE_NOW=1

usage() {
  cat <<'EOF'
Usage: install_wireguard_watch_service.sh [options]

Install a systemd service that runs:
  python3 -m nordility watch-wireguard

The service watches NordVPN status/NordLynx changes and re-applies the
WireGuard socket fwmark plus ip rule needed to keep private WireGuard responses
off NordVPN's nordlynx route.

Options:
  --render-only                 Print the service unit instead of installing it.
  --no-enable                   Install the unit without enabling/starting it.
  --unit-dir DIR                Target systemd unit directory. Default: /etc/systemd/system
  --python-bin PATH             Python executable for ExecStart. Default: python3
  --interval SECONDS            Watch polling interval. Default: 5
  --stabilize-wait SECONDS      Wait after NordVPN state changes. Default: 2
  --wireguard-fwmark FWMARK     WireGuard socket fwmark. Default: 51820
  --wireguard-interface IFACE   Interface to start if down. Default: wg0
  --ip-rule-priority PRIORITY   Policy-routing rule priority. Default: 100
  --help                        Show this help text.

Typical flow:
  sudo ./scripts/install_wireguard_watch_service.sh
  sudo systemctl status nordility-wireguard-watch.service --no-pager
EOF
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --render-only)
      RENDER_ONLY=1
      shift
      ;;
    --no-enable)
      ENABLE_NOW=0
      shift
      ;;
    --unit-dir)
      UNIT_DIR="$2"
      shift 2
      ;;
    --python-bin)
      PYTHON_BIN="$2"
      shift 2
      ;;
    --interval)
      INTERVAL_SECONDS="$2"
      shift 2
      ;;
    --stabilize-wait)
      STABILIZE_SECONDS="$2"
      shift 2
      ;;
    --wireguard-fwmark)
      WIREGUARD_FWMARK="$2"
      shift 2
      ;;
    --wireguard-interface)
      WIREGUARD_INTERFACE="$2"
      shift 2
      ;;
    --ip-rule-priority)
      IP_RULE_PRIORITY="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

render_unit() {
  cat <<EOF
[Unit]
Description=Nordility NordVPN/WireGuard routing watcher
Documentation=file://${REPO_ROOT}/README.md
Wants=network-online.target
After=network-online.target nordvpnd.service wg-quick@wg0.service

[Service]
Type=simple
WorkingDirectory=${REPO_ROOT}
Environment=PYTHONPATH=${REPO_ROOT}/src
ExecStart=${PYTHON_BIN} -m nordility --backend cli watch-wireguard --interval ${INTERVAL_SECONDS} --stabilize-wait ${STABILIZE_SECONDS} --wireguard-interface ${WIREGUARD_INTERFACE} --wireguard-fwmark ${WIREGUARD_FWMARK} --ip-rule-priority ${IP_RULE_PRIORITY}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

if (( RENDER_ONLY == 1 )); then
  render_unit
  exit 0
fi

[[ "${EUID}" -eq 0 ]] || fail "run as root (sudo) to install the systemd service"
command -v systemctl >/dev/null 2>&1 || fail "systemctl not found"

tmp_unit="$(mktemp)"
trap 'rm -f "${tmp_unit}"' EXIT
render_unit > "${tmp_unit}"

install -D -m 0644 "${tmp_unit}" "${UNIT_DIR}/${UNIT_NAME}"
systemctl daemon-reload

if (( ENABLE_NOW == 1 )); then
  systemctl enable "${UNIT_NAME}"
  systemctl restart "${UNIT_NAME}"
  printf 'enabled and restarted %s\n' "${UNIT_NAME}"
else
  printf 'installed %s/%s\n' "${UNIT_DIR}" "${UNIT_NAME}"
fi
