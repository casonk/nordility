from __future__ import annotations

import argparse
import configparser
import logging
import sys
from pathlib import Path

from nordility.client import (
    DEFAULT_KEEPASS_ENTRY,
    DEFAULT_KEEPASS_PROFILE,
    NordilityError,
    NordVPNClient,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_AUTO_PASS_CONFIG_PATH = _REPO_ROOT / "config" / "auto-pass.ini"


def _load_repo_auto_pass_config() -> dict[str, str]:
    if not _AUTO_PASS_CONFIG_PATH.exists():
        return {}

    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    try:
        with _AUTO_PASS_CONFIG_PATH.open(encoding="utf-8") as handle:
            parser.read_file(handle)
    except (OSError, configparser.Error) as exc:
        raise NordilityError(f"invalid config/auto-pass.ini: {exc}") from exc

    defaults: dict[str, str] = {}
    if parser.has_section("auto_pass"):
        profile = parser.get("auto_pass", "profile", fallback="").strip()
        if profile:
            defaults["profile"] = profile
    if parser.has_section("nordility"):
        keepass_entry = parser.get("nordility", "keepass_entry", fallback="").strip()
        if keepass_entry:
            defaults["keepass_entry"] = keepass_entry
    return defaults


def _resolve_keepass_defaults() -> tuple[str, str]:
    defaults = _load_repo_auto_pass_config()
    return (
        defaults.get("profile") or DEFAULT_KEEPASS_PROFILE,
        defaults.get("keepass_entry") or DEFAULT_KEEPASS_ENTRY,
    )


def build_parser() -> argparse.ArgumentParser:
    keepass_profile_default, keepass_entry_default = _resolve_keepass_defaults()

    parser = argparse.ArgumentParser(
        description="Automate NordVPN connect/disconnect/rotation tasks."
    )
    parser.add_argument("--executable", help="Path to NordVPN.exe or the nordvpn CLI executable.")
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

    login_parser = subparsers.add_parser("login", help="Log in to NordVPN using a token.")
    login_token_group = login_parser.add_mutually_exclusive_group()
    login_token_group.add_argument("--token", help="NordVPN access token.")
    login_token_group.add_argument(
        "--keepass-entry",
        default=keepass_entry_default,
        metavar="ENTRY",
        help="KeePassXC entry path whose Token attribute holds the access token. "
        f"Default: {keepass_entry_default}",
    )
    login_parser.add_argument(
        "--keepass-profile",
        default=keepass_profile_default,
        help=(
            "auto-pass profile to use when resolving --keepass-entry. "
            f"Default: {keepass_profile_default}"
        ),
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
        default=keepass_entry_default,
        metavar="ENTRY",
        help=f"KeePassXC entry to use for auto-login. Default: {keepass_entry_default}",
    )
    connect_parser.add_argument(
        "--keepass-profile",
        default=keepass_profile_default,
        help=(
            "auto-pass profile to use when resolving --keepass-entry. "
            f"Default: {keepass_profile_default}"
        ),
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
        default=keepass_entry_default,
        metavar="ENTRY",
        help=f"KeePassXC entry to use for auto-login. Default: {keepass_entry_default}",
    )
    change_parser.add_argument(
        "--keepass-profile",
        default=keepass_profile_default,
        help=(
            "auto-pass profile to use when resolving --keepass-entry. "
            f"Default: {keepass_profile_default}"
        ),
    )
    change_parser.add_argument(
        "--restore-wireguard",
        action="store_true",
        help=(
            "After switching NordVPN servers, force a handshake refresh on any active "
            "WireGuard interfaces discovered via 'wg show interfaces'. On Linux (cli "
            "backend) also re-applies the socket fwmark and ip rule so WireGuard "
            "responses continue to route via the real internet gateway instead of "
            "nordlynx. No-op if no WireGuard interfaces are found."
        ),
    )
    change_parser.add_argument(
        "--wireguard-fwmark",
        type=int,
        default=51820,
        metavar="FWMARK",
        help=(
            "Socket fwmark value used by the WireGuard interface (decimal). "
            "Used with --restore-wireguard on Linux to re-apply the ip routing rule. "
            "Default: 51820 (0xca54)."
        ),
    )

    list_parser = subparsers.add_parser("list-groups", help="List built-in server groups.")
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
                keepass_profile=args.keepass_profile,
            )
            print(result.message)
            return 0
        if args.command == "connect":
            result = client.connect(
                group=args.group,
                wait_seconds=args.wait,
                auto_login=args.auto_login,
                keepass_entry=args.keepass_entry,
                keepass_profile=args.keepass_profile,
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
                keepass_profile=args.keepass_profile,
                restore_wireguard=args.restore_wireguard,
                wireguard_fwmark=args.wireguard_fwmark,
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
