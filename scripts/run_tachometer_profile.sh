#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo_root/config/tachometer/profile.toml"

find_tachometer_src() {
  local dir="$repo_root"
  while [ "$dir" != "/" ]; do
    if [ -d "$dir/util-repos/tachometer/src" ]; then
      printf "%s\n" "$dir/util-repos/tachometer/src"
      return 0
    fi
    dir="$(dirname "$dir")"
  done
  return 1
}

run_tachometer() {
  if command -v tachometer >/dev/null 2>&1; then
    tachometer "$@"
    return 0
  fi
  local tachometer_src
  if ! tachometer_src="$(find_tachometer_src)"; then
    printf "tachometer is not installed and util-repos/tachometer/src was not found from %s\n" "$repo_root" >&2
    return 1
  fi
  PYTHONPATH="$tachometer_src${PYTHONPATH:+:$PYTHONPATH}" python3 -m tachometer "$@"
}

subcommand="${1:-snapshot}"
shift || true

case "$subcommand" in
  snapshot|summarize)
    run_tachometer "$subcommand" --manifest "$manifest" "$@"
    ;;
  run)
    run_tachometer run --manifest "$manifest" "$@"
    ;;
  *)
    printf "Usage: %s [snapshot|summarize|run -- <command...>]\n" "${BASH_SOURCE[0]##*/}" >&2
    exit 2
    ;;
esac
