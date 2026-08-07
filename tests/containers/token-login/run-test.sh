#!/bin/sh

set -eu

test_token='v1.Sample_TOKEN-+~AZ09'

printf '%s\n' "$test_token" \
    | python3 -m nordility.token_login /usr/bin/nordvpn > /tmp/helper.out 2>&1 &
helper_pid=$!

sleep 0.5
helper_cmd=$(tr '\000' ' ' < "/proc/$helper_pid/cmdline")
helper_env=$({ tr '\000' '\n' < "/proc/$helper_pid/environ"; } 2>/dev/null || true)
case "$helper_cmd$helper_env" in
    *"$test_token"*)
        echo "token exposed in helper process metadata" >&2
        exit 1
        ;;
esac

child_pid=$(pgrep -P "$helper_pid" -x nordvpn | head -n 1)
child_cmd=$(tr '\000' ' ' < "/proc/$child_pid/cmdline")
child_env=$({ tr '\000' '\n' < "/proc/$child_pid/environ"; } 2>/dev/null || true)
case "$child_cmd$child_env" in
    *"$test_token"*)
        echo "token exposed in NordVPN process metadata" >&2
        exit 1
        ;;
esac

wait "$helper_pid"
if grep -F "$test_token" /tmp/helper.out >/dev/null; then
    echo "token escaped through helper output" >&2
    exit 1
fi

failed_token='valid-printable-but-rejected'
if printf '%s\n' "$failed_token" \
    | python3 -m nordility.token_login /usr/bin/nordvpn > /tmp/rejected.out 2>&1; then
    echo "helper accepted a token rejected by the CLI" >&2
    exit 1
fi
if grep -F "$failed_token" /tmp/rejected.out >/dev/null; then
    echo "rejected token escaped through helper output" >&2
    exit 1
fi

echo "Nordility PTY token handoff passed"
