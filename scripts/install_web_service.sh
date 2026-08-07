#!/usr/bin/env bash
# install_web_service.sh - install the local Nordility web control service

set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -P "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=scripts/lib/install_runtime.sh
source "${SCRIPT_DIR}/lib/install_runtime.sh"
UNIT_NAME="nordility-web.service"
UNIT_DIR="/etc/systemd/system"
PYTHON_BIN="${PYTHON_BIN:-python3}"
SOCKET_PATH="/run/nordility/web.sock"
SOCKET_GROUP="caddy"
TRUSTED_ORIGIN="https://nordility.clockwork.internal"
WIREGUARD_INTERFACE="wg0"
WIREGUARD_FWMARK="51820"
IP_RULE_PRIORITY="100"
RENDER_ONLY=0
ENABLE_NOW=1

usage() {
  cat <<'EOF'
Usage: install_web_service.sh [options]

Install a systemd service that runs the local Nordility web control surface on
a root-owned Unix socket for the wiring-harness shared Caddy/mTLS entrypoint.

Options:
  --render-only                 Print the service unit instead of installing it.
  --no-enable                   Install the unit without enabling/starting it.
  --unit-dir DIR                Target systemd unit directory. Default: /etc/systemd/system
  --python-bin PATH             Python executable for ExecStart. Default: python3
  --trusted-origin ORIGIN       Exact HTTPS Caddy origin allowed to mutate state.
                                Default: https://nordility.clockwork.internal
  --wireguard-interface IFACE   Interface to start after VPN actions if down. Default: wg0
  --wireguard-fwmark FWMARK     WireGuard socket fwmark. Default: 51820
  --ip-rule-priority PRIORITY   Policy-routing rule priority. Default: 100
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
    --trusted-origin)
      TRUSTED_ORIGIN="$2"
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
Description=Nordility web control surface
Documentation=https://github.com/casonk/nordility
Wants=network-online.target
After=network-online.target nordvpnd.service wg-quick@wg0.service nordility-wireguard-watch.service

[Service]
Type=simple
Group=${SOCKET_GROUP}
RuntimeDirectory=nordility
RuntimeDirectoryMode=0750
UMask=0007
WorkingDirectory=${NORDILITY_RUNTIME_ROOT}
Environment=PYTHONPATH=${NORDILITY_RUNTIME_SOURCE_ROOT}
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=${PYTHON_BIN} -m nordility --backend cli web --unix-socket ${SOCKET_PATH} --trusted-origin ${TRUSTED_ORIGIN} --wireguard-interface ${WIREGUARD_INTERFACE} --wireguard-fwmark ${WIREGUARD_FWMARK} --ip-rule-priority ${IP_RULE_PRIORITY}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

nordility_require_single_line "unit directory" "${UNIT_DIR}"
nordility_require_single_line "web socket" "${SOCKET_PATH}"
nordility_require_single_line "web socket group" "${SOCKET_GROUP}"
nordility_require_single_line "trusted web origin" "${TRUSTED_ORIGIN}"
nordility_require_single_line "WireGuard interface" "${WIREGUARD_INTERFACE}"
nordility_require_single_line "WireGuard fwmark" "${WIREGUARD_FWMARK}"
nordility_require_single_line "ip rule priority" "${IP_RULE_PRIORITY}"
[[ "${TRUSTED_ORIGIN}" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || \
  fail "trusted web origin must be one HTTPS origin without a path"

if (( RENDER_ONLY == 1 )); then
  PYTHON_BIN="$(nordility_python_for_render "${PYTHON_BIN}")"
  render_unit
  exit 0
fi

[[ "${EUID}" -eq 0 ]] || fail "run as root (sudo) to install the systemd service"
command -v systemctl >/dev/null 2>&1 || fail "systemctl not found"
nordility_require_install_tools
PYTHON_BIN="$(nordility_secure_python "${PYTHON_BIN}")"
getent group "${SOCKET_GROUP}" >/dev/null 2>&1 || fail "required group not found: ${SOCKET_GROUP}"
nordility_stage_runtime "${REPO_ROOT}"

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
