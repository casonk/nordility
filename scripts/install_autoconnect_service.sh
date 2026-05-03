#!/usr/bin/env bash
# install_autoconnect_service.sh - install the nordility boot auto-connect service

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_NAME="nordility-autoconnect.service"
UNIT_DIR="/etc/systemd/system"
PYTHON_BIN="${PYTHON_BIN:-python3}"
GROUP=""
KEEPASS_PROFILE="${KEEPASS_PROFILE:-}"
KEEPASS_ENTRY="${KEEPASS_ENTRY:-}"
AUTO_LOGIN=1
RENDER_ONLY=0
ENABLE_NOW=1

usage() {
  cat <<'EOF'
Usage: install_autoconnect_service.sh [options]

Install a one-shot systemd service that runs:
  nordility connect [--group GROUP] [--auto-login ...]

on every boot after the network is online.  The service is Type=oneshot with
RemainAfterExit=yes so systemd reports it as active once the connect succeeds.

Options:
  --render-only                 Print the service unit instead of installing it.
  --no-enable                   Install the unit without enabling/starting it.
  --unit-dir DIR                Target systemd unit directory. Default: /etc/systemd/system
  --python-bin PATH             Python executable for ExecStart. Default: python3
  --group GROUP                 Country or server group to connect to (e.g. United_States).
                                Omit to let nordvpn pick the server automatically.
  --no-auto-login               Do not use auto-pass/KeePass to recover a logged-out client.
  --keepass-profile PROFILE     Override the auto-pass profile for NordVPN token lookup.
  --keepass-entry ENTRY         Override the KeePassXC entry for NordVPN token lookup.
  --help                        Show this help text.

Typical flow:
  sudo ./scripts/install_autoconnect_service.sh
  sudo systemctl status nordility-autoconnect.service --no-pager
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
    --group)
      GROUP="$2"
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
  local connect_args=()
  if [[ -n "${GROUP}" ]]; then
    connect_args+=(--group "${GROUP}")
  fi
  if (( AUTO_LOGIN == 1 )); then
    connect_args+=(--auto-login)
    if [[ -n "${KEEPASS_ENTRY}" ]]; then
      connect_args+=(--keepass-entry "${KEEPASS_ENTRY}")
    fi
    if [[ -n "${KEEPASS_PROFILE}" ]]; then
      connect_args+=(--keepass-profile "${KEEPASS_PROFILE}")
    fi
  fi
  cat <<EOF
[Unit]
Description=Nordility boot auto-connect
Documentation=file://${REPO_ROOT}/README.md
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${REPO_ROOT}
Environment=PYTHONPATH=${REPO_ROOT}/src
ExecStart=${PYTHON_BIN} -m nordility --backend cli connect${connect_args[*]:+ ${connect_args[*]}}

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
  printf 'enabled and started %s\n' "${UNIT_NAME}"
else
  printf 'installed %s/%s\n' "${UNIT_DIR}" "${UNIT_NAME}"
fi
