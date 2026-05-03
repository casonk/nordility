#!/usr/bin/env bash
# install_web_service.sh - install the local Nordility web control service

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_NAME="nordility-web.service"
UNIT_DIR="/etc/systemd/system"
PYTHON_BIN="${PYTHON_BIN:-python3}"
HOST="127.0.0.1"
PORT="5300"
WIREGUARD_INTERFACE="wg0"
WIREGUARD_FWMARK="51820"
IP_RULE_PRIORITY="100"
KEEPASS_PROFILE="${KEEPASS_PROFILE:-}"
KEEPASS_ENTRY="${KEEPASS_ENTRY:-}"
AUTO_LOGIN=1
RENDER_ONLY=0
ENABLE_NOW=1

usage() {
  cat <<'EOF'
Usage: install_web_service.sh [options]

Install a systemd service that runs the local Nordility web control surface.
The service binds to 127.0.0.1 and is intended to be exposed through the
wiring-harness shared Caddy/mTLS entrypoint.

Options:
  --render-only                 Print the service unit instead of installing it.
  --no-enable                   Install the unit without enabling/starting it.
  --unit-dir DIR                Target systemd unit directory. Default: /etc/systemd/system
  --python-bin PATH             Python executable for ExecStart. Default: python3
  --host HOST                   Bind host. Default: 127.0.0.1
  --port PORT                   Bind port. Default: 5300
  --wireguard-interface IFACE   Interface to start after VPN actions if down. Default: wg0
  --wireguard-fwmark FWMARK     WireGuard socket fwmark. Default: 51820
  --ip-rule-priority PRIORITY   Policy-routing rule priority. Default: 100
  --no-auto-login               Do not use auto-pass/KeePass to recover a logged-out client.
  --keepass-profile PROFILE     Override the auto-pass profile for NordVPN token lookup.
  --keepass-entry ENTRY         Override the KeePassXC entry for NordVPN token lookup.
  --help                        Show this help text.

Typical flow:
  sudo ./scripts/install_web_service.sh
  sudo systemctl status nordility-web.service --no-pager
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
    --host)
      HOST="$2"
      shift 2
      ;;
    --port)
      PORT="$2"
      shift 2
      ;;
    --wireguard-interface)
      WIREGUARD_INTERFACE="$2"
      shift 2
      ;;
    --wireguard-fwmark)
      WIREGUARD_FWMARK="$2"
      shift 2
      ;;
    --ip-rule-priority)
      IP_RULE_PRIORITY="$2"
      shift 2
      ;;
    --no-auto-login)
      AUTO_LOGIN=0
      shift
      ;;
    --keepass-profile)
      KEEPASS_PROFILE="$2"
      shift 2
      ;;
    --keepass-entry)
      KEEPASS_ENTRY="$2"
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
  local auto_login_args=()
  if (( AUTO_LOGIN == 1 )); then
    auto_login_args=(--auto-login)
    if [[ -n "${KEEPASS_ENTRY}" ]]; then
      auto_login_args+=(--keepass-entry "${KEEPASS_ENTRY}")
    fi
    if [[ -n "${KEEPASS_PROFILE}" ]]; then
      auto_login_args+=(--keepass-profile "${KEEPASS_PROFILE}")
    fi
  fi
  cat <<EOF
[Unit]
Description=Nordility web control surface
Documentation=file://${REPO_ROOT}/README.md
Wants=network-online.target
After=network-online.target nordvpnd.service wg-quick@wg0.service nordility-wireguard-watch.service

[Service]
Type=simple
WorkingDirectory=${REPO_ROOT}
Environment=PYTHONPATH=${REPO_ROOT}/src
ExecStart=${PYTHON_BIN} -m nordility --backend cli web --host ${HOST} --port ${PORT} --wireguard-interface ${WIREGUARD_INTERFACE} --wireguard-fwmark ${WIREGUARD_FWMARK} --ip-rule-priority ${IP_RULE_PRIORITY}${auto_login_args[*]:+ ${auto_login_args[*]}}
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
