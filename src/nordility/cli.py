from __future__ import annotations

import argparse
import logging
import sys

from nordility.client import NordVPNClient, NordilityError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Automate NordVPN connect/disconnect/rotation tasks."
    )
    parser.add_argument(
        "--executable", help="Path to NordVPN.exe or the nordvpn CLI executable."
    )
    parser.add_argument(
        "--backend",
        choices=("auto", "windows", "cli"),
        default="auto",
        help="Execution backend. Defaults to auto-detection.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        help="Logger verbosity.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    login_parser = subparsers.add_parser(
        "login", help="Log in to NordVPN using a token."
    )
    login_token_group = login_parser.add_mutually_exclusive_group()
    login_token_group.add_argument("--token", help="NordVPN access token.")
    login_token_group.add_argument(
        "--keepass-entry",
        default="Nord_VPN#access-token",
        metavar="ENTRY",
        help="KeePassXC entry path whose Token attribute holds the access token. "
        "Default: Nord_VPN#access-token",
    )

    connect_parser = subparsers.add_parser("connect", help="Connect to NordVPN.")
    connect_parser.add_argument(
        "--group", help="Country or server group name, for example United_States."
    )
    connect_parser.add_argument(
        "--wait",
        type=float,
        default=0,
        help="Seconds to sleep after launching the command.",
    )
    connect_parser.add_argument(
        "--auto-login",
        action="store_true",
        help="If the client is logged out, re-authenticate via KeePass before connecting.",
    )
    connect_parser.add_argument(
        "--keepass-entry",
        default="Nord_VPN#access-token",
        metavar="ENTRY",
        help="KeePassXC entry to use for auto-login. Default: Nord_VPN#access-token",
    )

    disconnect_parser = subparsers.add_parser("disconnect", help="Disconnect NordVPN.")
    disconnect_parser.add_argument(
        "--wait",
        type=float,
        default=0,
        help="Seconds to sleep after launching the command.",
    )

    change_parser = subparsers.add_parser(
        "change", help="Rotate to a new NordVPN country/server group."
    )
    change_parser.add_argument(
        "--speed",
        choices=("fast", "full"),
        default="fast",
        help="Country pool to choose from.",
    )
    change_parser.add_argument("--group", help="Explicit country or server group name.")
    change_parser.add_argument(
        "--wait",
        type=float,
        help="Seconds to sleep after launching the command. Defaults to 10 for fast or 30 for full.",
    )
    change_parser.add_argument(
        "--auto-login",
        action="store_true",
        help="If the client is logged out, re-authenticate via KeePass before connecting.",
    )
    change_parser.add_argument(
        "--keepass-entry",
        default="Nord_VPN#access-token",
        metavar="ENTRY",
        help="KeePassXC entry to use for auto-login. Default: Nord_VPN#access-token",
    )
    change_parser.add_argument(
        "--restore-wireguard",
        action="store_true",
        help=(
            "After switching NordVPN servers, force a handshake refresh on any active "
            "WireGuard interfaces discovered via 'wg show interfaces'. No-op if none found."
        ),
    )

    list_parser = subparsers.add_parser(
        "list-groups", help="List built-in server groups."
    )
    list_parser.add_argument(
        "--speed",
        choices=("fast", "full"),
        default="fast",
        help="Country pool to print.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(message)s")

    client = NordVPNClient(executable=args.executable, backend=args.backend)

    try:
        if args.command == "login":
            result = client.login(
                token=args.token if args.token else None,
                keepass_entry=args.keepass_entry if not args.token else None,
            )
            print(result.message)
            return 0
        if args.command == "connect":
            result = client.connect(
                group=args.group,
                wait_seconds=args.wait,
                auto_login=args.auto_login,
                keepass_entry=args.keepass_entry,
            )
            print(result.message)
            return 0
        if args.command == "disconnect":
            result = client.disconnect(wait_seconds=args.wait)
            print(result.message)
            return 0
        if args.command == "change":
            result = client.change(
                speed=args.speed,
                group=args.group,
                wait_seconds=args.wait,
                auto_login=args.auto_login,
                keepass_entry=args.keepass_entry,
                restore_wireguard=args.restore_wireguard,
            )
            print(result.message)
            return 0
        if args.command == "list-groups":
            for group in client.list_groups(speed=args.speed):
                print(group)
            return 0
    except NordilityError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    parser.error(f"Unhandled command: {args.command}")
    return 2
