from __future__ import annotations

import logging
import os
import random
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

LOGGER = logging.getLogger("nordility")

DEFAULT_WINDOWS_EXECUTABLE = "C:/Program Files/NordVPN/NordVPN.exe"

FULL_GROUPS = (
    "Albania",
    "Germany",
    "Poland",
    "Argentina",
    "Greece",
    "Portugal",
    "Australia",
    "Hong_Kong",
    "Romania",
    "Austria",
    "Hungary",
    "Serbia",
    "Belgium",
    "Iceland",
    "Singapore",
    "Bosnia_And_Herzegovina",
    "Indonesia",
    "Slovakia",
    "Brazil",
    "Ireland",
    "Slovenia",
    "Bulgaria",
    "Israel",
    "South_Africa",
    "Canada",
    "Italy",
    "Chile",
    "Japan",
    "Spain",
    "Colombia",
    "Latvia",
    "Sweden",
    "Costa_Rica",
    "Lithuania",
    "Switzerland",
    "Croatia",
    "Luxembourg",
    "Taiwan",
    "Cyprus",
    "Malaysia",
    "Thailand",
    "Czech_Republic",
    "Mexico",
    "Turkey",
    "Denmark",
    "Moldova",
    "Ukraine",
    "Estonia",
    "Netherlands",
    "United_Kingdom",
    "Finland",
    "New_Zealand",
    "United_States",
    "France",
    "North_Macedonia",
    "Vietnam",
    "Georgia",
    "Norway",
)

FAST_GROUPS = (
    "Germany",
    "Poland",
    "Greece",
    "Austria",
    "Hungary",
    "Belgium",
    "Brazil",
    "Ireland",
    "Canada",
    "Italy",
    "Japan",
    "Spain",
    "Colombia",
    "Sweden",
    "Switzerland",
    "Luxembourg",
    "Mexico",
    "Denmark",
    "Netherlands",
    "United_Kingdom",
    "Finland",
    "United_States",
    "France",
    "Norway",
)

GROUPS_BY_SPEED = {
    "fast": FAST_GROUPS,
    "full": FULL_GROUPS,
}

NOT_LOGGED_IN_MARKERS = (
    "not logged in",
    "please log in",
    "you are not logged in",
)
ENTRY_NOT_FOUND_MARKERS = (
    "not found",
    "no entry",
    "could not find",
)

_AUTO_PASS_ROOT = Path(__file__).resolve().parent.parent.parent.parent / "auto-pass"
DEFAULT_KEEPASS_ENTRY = "vpn/provider#access-token"
DEFAULT_KEEPASS_PROFILE = ""
DEFAULT_WIREGUARD_FWMARK = 51820
DEFAULT_WIREGUARD_IP_RULE_PRIORITY = 100
DEFAULT_WIREGUARD_IP_RULE_PROTOCOL = 196
DEFAULT_WIREGUARD_INTERFACES = ("wg0",)
_DAEMON_MANAGED_WIREGUARD_INTERFACES = frozenset({"nordlynx"})
_REDACTED_ARGUMENT = "<redacted>"

_NORDVPN_STATUS_SIGNATURE_PREFIXES = (
    "status:",
    "hostname:",
    "server:",
    "ip:",
    "country:",
    "city:",
    "current technology:",
    "current protocol:",
)
_NORDVPN_STATUS_DYNAMIC_PREFIXES = (
    "transfer:",
    "uptime:",
)


def _redact_command(command: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return a display-safe argv and the secret values removed from it."""
    redacted: list[str] = []
    secrets: list[str] = []
    redact_next = False
    for argument in command:
        if redact_next:
            secrets.append(argument)
            redacted.append(_REDACTED_ARGUMENT)
            redact_next = False
        elif argument == "--token":
            redacted.append(argument)
            redact_next = True
        elif argument.startswith("--token="):
            _, value = argument.split("=", 1)
            secrets.append(value)
            redacted.append(f"--token={_REDACTED_ARGUMENT}")
        else:
            redacted.append(argument)
    return tuple(redacted), tuple(secret for secret in secrets if secret)


def _redact_text(value: str, secrets: tuple[str, ...]) -> str:
    for secret in secrets:
        value = value.replace(secret, _REDACTED_ARGUMENT)
    return value


def _candidate_keepass_entries(entry: str) -> tuple[str, ...]:
    normalized = entry.strip()
    if not normalized:
        return ()
    candidates = [normalized]
    if "/" not in normalized:
        candidates.append(f"nordvpn/{normalized}")
    return tuple(dict.fromkeys(candidates))


def _resolve_keepass_token(
    keepass_entry: str,
    keepass_profile: str | None = DEFAULT_KEEPASS_PROFILE,
) -> str:
    """Resolve the NordVPN access token from a KeePassXC entry via auto-pass.

    Reads the ``Password`` field of the entry. By default the entry is
    ``vpn/provider#access-token``; set ``keepass_profile`` or configure
    ``config/auto-pass.ini`` to specify the KeePass vault profile.
    """
    _src = str(_AUTO_PASS_ROOT / "src")
    if _src not in sys.path:
        sys.path.insert(0, _src)
    from auto_pass.envfile import load_config_environment  # noqa: PLC0415
    from auto_pass.keepassxc import (
        KeepassCommandError,  # noqa: PLC0415
        resolve_keepassxc_entry,  # noqa: PLC0415
    )

    _ap_env = _AUTO_PASS_ROOT / "config" / "auto-pass.env.local"
    if _ap_env.is_file():
        load_config_environment(_ap_env, profile=keepass_profile)
    last_error: KeepassCommandError | None = None
    for candidate in _candidate_keepass_entries(keepass_entry):
        try:
            result = resolve_keepassxc_entry(candidate, attrs_map={"token": "password"})
        except KeepassCommandError as exc:
            last_error = exc
            lowered = str(exc).lower()
            if any(marker in lowered for marker in ENTRY_NOT_FOUND_MARKERS):
                continue
            raise
        return result.get("token", "")
    if last_error is not None:
        raise last_error
    return ""


def _is_not_logged_in(error_message: str) -> bool:
    lowered = error_message.lower()
    return any(marker in lowered for marker in NOT_LOGGED_IN_MARKERS)


def _discover_wireguard_interfaces(
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> list[str]:
    """Return names of active WireGuard interfaces, or [] if none or wg unavailable."""
    try:
        result = runner(["wg", "show", "interfaces"], capture_output=True, text=True, check=False)
        if result.returncode != 0 or not result.stdout.strip():
            return []
        return result.stdout.strip().split()
    except (OSError, FileNotFoundError):
        return []


def _get_wireguard_peer_endpoints(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    interface: str,
) -> dict[str, str]:
    """Return {pubkey: endpoint} for peers that have a known endpoint on *interface*.

    Tries ``wg show`` without privilege first; retries with ``sudo -n`` if
    the call returns non-zero (``wg show <iface> endpoints`` requires root on
    most Linux systems).
    """
    cmd = ["wg", "show", interface, "endpoints"]
    try:
        result = runner(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            result = runner(["sudo", "-n"] + cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            return {}
        peers: dict[str, str] = {}
        for line in result.stdout.strip().splitlines():
            parts = line.strip().split("\t", 1)
            if len(parts) == 2 and parts[1] != "(none)":
                peers[parts[0]] = parts[1]
        return peers
    except (OSError, FileNotFoundError):
        return {}


def _restore_wireguard_routing(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    interfaces: list[str],
    fwmark: int = DEFAULT_WIREGUARD_FWMARK,
    ip_rule_priority: int = DEFAULT_WIREGUARD_IP_RULE_PRIORITY,
) -> list[str]:
    """Re-apply the WireGuard socket fwmark and the matching ip rule on each interface.

    NordVPN's disconnect phase (triggered during server rotation) flushes ip
    rules, including any rule that routes WireGuard-marked packets to the main
    routing table instead of nordlynx.  This function re-applies both pieces:

    1. ``wg set <iface> fwmark <fwmark>`` — sets the socket-level SO_MARK so
       WireGuard's outgoing UDP packets carry the mark at routing-decision time.
    2. ``ip rule add fwmark <fwmark> lookup main priority <p>`` — ensures a
       policy-routing rule exists that sends marked packets via the main table
       (real internet gateway) before NordVPN's higher-numbered rules can
       redirect them through nordlynx.

    Both commands are tried without privilege first then retried via
    ``sudo -n`` if the first attempt returns non-zero (matching the pattern
    used by :func:`_refresh_wireguard_peers`).

    Returns the list of interfaces where the fwmark was successfully set *and*
    the exact global policy rule was already present or was added successfully.
    The ip rule is global (not per-interface) and is added at most once.  A
    successful interface mutation alone is not reported as a routing restore.
    """
    if not interfaces:
        return []

    requested_interfaces = tuple(dict.fromkeys(interfaces))
    fwmark_hex = hex(fwmark)
    fwmark_assignments = _wireguard_fwmark_assignments(runner)
    if fwmark_assignments is None:
        LOGGER.warning(
            "Could not enumerate all WireGuard fwmarks; refusing global routing-rule mutation"
        )
        return []

    missing_interfaces = [
        interface for interface in requested_interfaces if interface not in fwmark_assignments
    ]
    if missing_interfaces:
        LOGGER.warning(
            "Refusing WireGuard routing restore because target interface(s) were not "
            "present in the authoritative fwmark inventory: %s",
            ", ".join(missing_interfaces),
        )
        return []

    collisions = sorted(
        interface
        for interface, assigned_mark in fwmark_assignments.items()
        if interface not in requested_interfaces and assigned_mark == fwmark
    )
    if collisions:
        LOGGER.warning(
            "Refusing global fwmark %s rule because non-authorized WireGuard "
            "interface(s) already use that mark: %s",
            fwmark_hex,
            ", ".join(collisions),
        )
        return []

    rule_state = _ip_rule_priority_state(
        runner,
        fwmark=fwmark,
        ip_rule_priority=ip_rule_priority,
    )
    if rule_state == "unavailable":
        LOGGER.warning("ip not available; skipping routing rule")
        return []
    if rule_state == "conflict":
        LOGGER.warning(
            "Refusing WireGuard routing restore: priority %d contains a non-owned rule",
            ip_rule_priority,
        )
        return []

    rule_created = False
    if rule_state == "absent":
        add_cmd = [
            "ip",
            "rule",
            "add",
            "fwmark",
            str(fwmark),
            "lookup",
            "main",
            "priority",
            str(ip_rule_priority),
            "protocol",
            str(DEFAULT_WIREGUARD_IP_RULE_PROTOCOL),
        ]
        try:
            add_result = runner(add_cmd, capture_output=True, text=True, check=False)
            if add_result.returncode != 0:
                add_result = runner(
                    ["sudo", "-n"] + add_cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                )
        except (OSError, FileNotFoundError):
            LOGGER.warning("ip not available; skipping routing rule")
            return []
        if add_result.returncode != 0:
            LOGGER.warning(
                "Could not add ip rule for fwmark %s (priority %d)",
                fwmark_hex,
                ip_rule_priority,
            )
            return []
        rule_created = True
        if (
            _ip_rule_priority_state(
                runner,
                fwmark=fwmark,
                ip_rule_priority=ip_rule_priority,
            )
            != "owned"
        ):
            LOGGER.warning(
                "Could not verify exclusive ownership of ip rule priority %d",
                ip_rule_priority,
            )
            _delete_owned_ip_rule(
                runner,
                fwmark=fwmark,
                ip_rule_priority=ip_rule_priority,
            )
            return []
    else:
        LOGGER.debug(
            "Exact exclusive ip rule for fwmark %s at priority %d already present; skipping",
            fwmark_hex,
            ip_rule_priority,
        )

    # Re-read the complete assignment set after installing the global rule so
    # an interface racing into the same mark cannot silently inherit the
    # main-table bypass before any authorized interface is changed.
    verified_assignments = _wireguard_fwmark_assignments(runner)
    post_add_collisions = (
        []
        if verified_assignments is None
        else sorted(
            interface
            for interface, assigned_mark in verified_assignments.items()
            if interface not in requested_interfaces and assigned_mark == fwmark
        )
    )
    if verified_assignments is None or post_add_collisions:
        if post_add_collisions:
            LOGGER.warning(
                "WireGuard fwmark collision appeared during routing restore: %s",
                ", ".join(post_add_collisions),
            )
        else:
            LOGGER.warning("Could not re-verify WireGuard fwmarks after policy-rule setup")
        if rule_created:
            _delete_owned_ip_rule(
                runner,
                fwmark=fwmark,
                ip_rule_priority=ip_rule_priority,
            )
        return []

    marked: list[str] = []
    for iface in requested_interfaces:
        cmd = ["wg", "set", iface, "fwmark", str(fwmark)]
        try:
            result = runner(cmd, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                result = runner(["sudo", "-n"] + cmd, capture_output=True, text=True, check=False)
            if result.returncode == 0:
                marked.append(iface)
            else:
                LOGGER.warning("Could not set fwmark %s on %s", fwmark_hex, iface)
        except (OSError, FileNotFoundError):
            LOGGER.warning("wg not available; skipping fwmark for %s", iface)

    if rule_created and not marked:
        _delete_owned_ip_rule(
            runner,
            fwmark=fwmark,
            ip_rule_priority=ip_rule_priority,
        )
    return marked


def _user_managed_wireguard_interfaces(
    interfaces: list[str],
    config_dir: Path | None = None,
) -> list[str]:
    """Filter to WireGuard interfaces owned by local config files.

    NordVPN's NordLynx interface is also a WireGuard interface, but it is
    daemon-managed and normally has no ``/etc/wireguard/nordlynx.conf``.  Only
    user-managed interfaces should have their peer endpoints or socket fwmark
    overwritten.  Known daemon-owned names are denied even if a confusingly
    named local config file exists.
    """
    eligible = _non_daemon_wireguard_interfaces(interfaces)
    if config_dir is None:
        return [iface for iface in eligible if Path(f"/etc/wireguard/{iface}.conf").exists()]
    return [iface for iface in eligible if (config_dir / f"{iface}.conf").exists()]


def _non_daemon_wireguard_interfaces(interfaces: list[str]) -> list[str]:
    """Exclude provider-daemon interfaces at every privileged mutation boundary."""
    return [
        iface for iface in interfaces if iface.lower() not in _DAEMON_MANAGED_WIREGUARD_INTERFACES
    ]


def _wireguard_config_exists(interface: str, config_dir: Path | None = None) -> bool:
    if config_dir is None:
        return Path(f"/etc/wireguard/{interface}.conf").exists()
    return (config_dir / f"{interface}.conf").exists()


def _start_wireguard_interface(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    interface: str,
) -> bool:
    # The systemd unit is the activation boundary for generated mesh profiles:
    # its drop-ins install/verify fail-closed policy before WireGuard appears.
    # A raw wg-quick fallback would bypass that boundary.
    commands = (["systemctl", "start", f"wg-quick@{interface}.service"],)
    for cmd in commands:
        try:
            result = runner(cmd, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                result = runner(["sudo", "-n"] + cmd, capture_output=True, text=True, check=False)
        except (OSError, FileNotFoundError):
            continue
        if result.returncode == 0:
            return True
    return False


def _ensure_wireguard_interfaces(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    interfaces: tuple[str, ...] = DEFAULT_WIREGUARD_INTERFACES,
    config_dir: Path | None = None,
) -> list[str]:
    if not interfaces:
        return []

    active = set(_discover_wireguard_interfaces(runner))
    started: list[str] = []
    for iface in interfaces:
        if iface.lower() in _DAEMON_MANAGED_WIREGUARD_INTERFACES:
            LOGGER.warning("Refusing to start provider-managed WireGuard interface: %s", iface)
            continue
        if iface in active:
            continue
        if not _wireguard_config_exists(iface, config_dir=config_dir):
            LOGGER.debug("WireGuard config for %s not found; not starting", iface)
            continue
        LOGGER.info("Starting WireGuard interface: %s", iface)
        if _start_wireguard_interface(runner, iface):
            started.append(iface)
            active.add(iface)
        else:
            LOGGER.warning("Could not start WireGuard interface: %s", iface)
    return started


def _refresh_wireguard_peers(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    interfaces: list[str],
    config_dir: Path | None = None,
    require_config: bool = True,
) -> list[str]:
    """Force a handshake re-initiation for peers on user-managed interfaces.

    Re-sets each peer's endpoint to its current value, which causes the
    WireGuard kernel module to immediately initiate a new handshake instead
    of waiting for the next keepalive interval.  The discovered interface list
    is filtered again at this mutation boundary so callers cannot accidentally
    refresh NordVPN's daemon-managed ``nordlynx`` interface.

    Returns the list of interface names where at least one peer was refreshed.
    ``wg set`` requires root on Linux. nordility tries ``sudo -n wg set``
    (non-interactive sudo) so the command works automatically when the
    following sudoers rule is present::

        <user>  ALL=(ALL) NOPASSWD: /usr/bin/wg set *

    Without that rule the refresh is silently skipped — add it with::

        echo "$USER  ALL=(ALL) NOPASSWD: $(which wg) set *" \\
            | sudo tee /etc/sudoers.d/nordility-wg
        sudo chmod 440 /etc/sudoers.d/nordility-wg
    """
    refreshed: list[str] = []
    user_managed_interfaces = (
        _user_managed_wireguard_interfaces(interfaces, config_dir=config_dir)
        if require_config
        else _non_daemon_wireguard_interfaces(interfaces)
    )
    for iface in user_managed_interfaces:
        peers = _get_wireguard_peer_endpoints(runner, iface)
        if not peers:
            continue
        any_set = False
        for pubkey, endpoint in peers.items():
            cmd = ["wg", "set", iface, "peer", pubkey, "endpoint", endpoint]
            try:
                result = runner(cmd, capture_output=True, text=True, check=False)
                if result.returncode != 0:
                    # Retry with sudo -n (non-interactive; no-op if no sudoers rule).
                    result = runner(
                        ["sudo", "-n"] + cmd,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                if result.returncode == 0:
                    any_set = True
            except (OSError, FileNotFoundError):
                pass
        if any_set:
            refreshed.append(iface)
    return refreshed


@dataclass(frozen=True)
class WireGuardRestoreSummary:
    interfaces: tuple[str, ...] = ()
    started: tuple[str, ...] = ()
    refreshed: tuple[str, ...] = ()
    routing_candidates: tuple[str, ...] = ()
    routing_restored: tuple[str, ...] = ()

    def message_suffix(self) -> str:
        parts: list[str] = []
        if self.started:
            parts.append(f"; WireGuard started on {', '.join(self.started)}")
        if self.refreshed:
            parts.append(f"; WireGuard refreshed on {', '.join(self.refreshed)}")
        if self.routing_restored:
            parts.append(f"; routing restored on {', '.join(self.routing_restored)}")
        return "".join(parts)

    def describe(self) -> str:
        if not self.interfaces and not self.started:
            return "no active WireGuard interfaces found"
        parts: list[str] = []
        if self.interfaces:
            parts.append(f"interfaces: {', '.join(self.interfaces)}")
        if self.started:
            parts.append(f"started: {', '.join(self.started)}")
        if self.refreshed:
            parts.append(f"refreshed: {', '.join(self.refreshed)}")
        if self.routing_restored:
            parts.append(f"routing restored: {', '.join(self.routing_restored)}")
        elif self.routing_candidates:
            parts.append(f"routing candidates checked: {', '.join(self.routing_candidates)}")
        return "; ".join(parts)


def restore_wireguard_after_nordvpn(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    backend: str = "cli",
    fwmark: int = DEFAULT_WIREGUARD_FWMARK,
    ip_rule_priority: int = DEFAULT_WIREGUARD_IP_RULE_PRIORITY,
    wireguard_config_dir: Path | None = None,
    ensure_interfaces: tuple[str, ...] = DEFAULT_WIREGUARD_INTERFACES,
) -> WireGuardRestoreSummary:
    """Refresh only explicitly allowlisted WireGuard interfaces after NordVPN changes."""
    started = _ensure_wireguard_interfaces(
        runner,
        interfaces=ensure_interfaces,
        config_dir=wireguard_config_dir,
    )
    interfaces = _discover_wireguard_interfaces(runner)
    if not interfaces:
        LOGGER.debug("No active WireGuard interfaces discovered; skipping restore.")
        return WireGuardRestoreSummary(started=tuple(started))

    allowed_interfaces = set(ensure_interfaces)
    authorized_active_interfaces = [
        interface for interface in interfaces if interface in allowed_interfaces
    ]
    user_managed_interfaces = _user_managed_wireguard_interfaces(
        authorized_active_interfaces, config_dir=wireguard_config_dir
    )
    refresh_candidates = (
        user_managed_interfaces
        if backend == "cli"
        else _non_daemon_wireguard_interfaces(authorized_active_interfaces)
    )
    refreshed: list[str] = []
    if refresh_candidates:
        LOGGER.info(
            "Refreshing user-managed WireGuard handshakes on: %s",
            ", ".join(refresh_candidates),
        )
        refreshed = _refresh_wireguard_peers(
            runner,
            refresh_candidates,
            config_dir=wireguard_config_dir,
            require_config=backend == "cli",
        )
    else:
        LOGGER.debug("No user-managed WireGuard interfaces found; skipping peer refresh.")

    routing_candidates: list[str] = []
    routing_restored: list[str] = []
    if backend == "cli":
        routing_candidates = user_managed_interfaces
        if routing_candidates:
            LOGGER.info("Restoring WireGuard routing on: %s", ", ".join(routing_candidates))
            routing_restored = _restore_wireguard_routing(
                runner,
                routing_candidates,
                fwmark=fwmark,
                ip_rule_priority=ip_rule_priority,
            )
        else:
            LOGGER.debug("No user-managed WireGuard interfaces found; skipping routing restore.")

    return WireGuardRestoreSummary(
        interfaces=tuple(interfaces),
        started=tuple(started),
        refreshed=tuple(refreshed),
        routing_candidates=tuple(routing_candidates),
        routing_restored=tuple(routing_restored),
    )


def _stable_nordvpn_status(status_output: str) -> str:
    stable_lines: list[str] = []
    fallback_lines: list[str] = []
    for raw_line in status_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith(_NORDVPN_STATUS_DYNAMIC_PREFIXES):
            continue
        if lowered.startswith(_NORDVPN_STATUS_SIGNATURE_PREFIXES):
            stable_lines.append(line)
        else:
            fallback_lines.append(line)
    return "\n".join(stable_lines or fallback_lines)


def _run_for_signature(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    command: list[str],
) -> str:
    try:
        result = runner(command, capture_output=True, text=True, check=False)
    except (OSError, FileNotFoundError) as exc:
        return f"{' '.join(command)}\nerror={type(exc).__name__}:{exc}"

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()
    if len(command) >= 2 and command[1] == "status":
        stdout = _stable_nordvpn_status(stdout)
    return "\n".join(
        part
        for part in (
            " ".join(command),
            f"returncode={result.returncode}",
            stdout,
            f"stderr={stderr}" if stderr else "",
        )
        if part
    )


def _nordvpn_connection_signature(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    executable: str = "nordvpn",
) -> str:
    """Return a stable signature for NordVPN connection changes.

    The status command can contain counters such as uptime/transfer totals, so
    only stable status fields are included.  NordLynx endpoint/fwmark values
    are included because server rotation can be visible there before all
    high-level status text settles.
    """
    parts = [
        _run_for_signature(runner, [executable, "status"]),
        _run_for_signature(runner, ["wg", "show", "nordlynx", "endpoints"]),
        _run_for_signature(runner, ["wg", "show", "nordlynx", "fwmark"]),
    ]
    return "\n---\n".join(parts)


def _parse_ip_rule_number(value: str) -> int | None:
    try:
        return int(value, 0)
    except ValueError:
        return None


def _wireguard_fwmark_assignments(
    runner: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, int | None] | None:
    """Return the complete active WireGuard interface-to-fwmark inventory.

    ``wg show all fwmark`` is deliberately queried as one authoritative
    snapshot.  A partial or malformed response is treated as unavailable:
    creating a global fwmark rule without knowing every current mark could
    make an unrelated tunnel inherit NordVPN's main-table bypass.
    """
    command = ["wg", "show", "all", "fwmark"]
    try:
        result = runner(command, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            result = runner(
                ["sudo", "-n"] + command,
                capture_output=True,
                text=True,
                check=False,
            )
    except (OSError, FileNotFoundError):
        return None
    if result.returncode != 0:
        return None

    assignments: dict[str, int | None] = {}
    for raw_line in result.stdout.splitlines():
        parts = raw_line.split()
        if len(parts) != 2:
            return None
        interface, raw_mark = parts
        if interface in assignments:
            return None
        if raw_mark.lower() == "off":
            assignments[interface] = None
            continue
        mark = _parse_ip_rule_number(raw_mark)
        if mark is None or not 0 <= mark <= 0xFFFFFFFF:
            return None
        assignments[interface] = mark
    return assignments


def _ip_rule_line_matches(
    line: str,
    fwmark: int,
    ip_rule_priority: int,
) -> bool:
    """Return whether one normalized ``ip rule show`` line matches exactly.

    Marks may be rendered in decimal or hexadecimal, optionally with the full
    32-bit mask.  Partial masks are not equivalent to an exact fwmark match.
    ``table main`` and ``lookup main`` are accepted as equivalent iproute2
    spellings.
    """
    tokens = line.split()
    if not tokens:
        return False

    priority_token = tokens[0][:-1] if tokens[0].endswith(":") else tokens[0]
    if not priority_token.isdecimal() or int(priority_token) != ip_rule_priority:
        return False

    # The repair command creates one global rule with no inverse, address,
    # interface, UID, protocol, or port selectors.  Treating a narrower (or
    # inverted) rule as equivalent would report routing restored while some
    # WireGuard transport packets still follow NordVPN's policy table.
    if (
        len(tokens) != 9
        or tokens[1:3] != ["from", "all"]
        or tokens[3] != "fwmark"
        or tokens[5] not in {"lookup", "table"}
        or tokens[6] != "main"
        or tokens[7:] != ["proto", str(DEFAULT_WIREGUARD_IP_RULE_PROTOCOL)]
    ):
        return False

    mark_parts = tokens[4].split("/", 1)
    mark_value = _parse_ip_rule_number(mark_parts[0])
    if mark_value != fwmark:
        return False
    return len(mark_parts) == 1 or _parse_ip_rule_number(mark_parts[1]) == 0xFFFFFFFF


def _ip_rule_has_fwmark(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    fwmark: int = DEFAULT_WIREGUARD_FWMARK,
    ip_rule_priority: int = DEFAULT_WIREGUARD_IP_RULE_PRIORITY,
) -> bool:
    return (
        _ip_rule_priority_state(
            runner,
            fwmark=fwmark,
            ip_rule_priority=ip_rule_priority,
        )
        == "owned"
    )


def _ip_rule_priority_state(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    fwmark: int = DEFAULT_WIREGUARD_FWMARK,
    ip_rule_priority: int = DEFAULT_WIREGUARD_IP_RULE_PRIORITY,
) -> str:
    """Return unavailable, absent, owned, or conflict for one reserved priority."""
    try:
        result = runner(["ip", "rule", "show"], capture_output=True, text=True, check=False)
    except (OSError, FileNotFoundError):
        return "unavailable"
    if result.returncode != 0:
        return "unavailable"

    rules_at_priority: list[str] = []
    for line in result.stdout.splitlines():
        tokens = line.split()
        if not tokens:
            continue
        priority_token = tokens[0][:-1] if tokens[0].endswith(":") else tokens[0]
        if priority_token.isdecimal() and int(priority_token) == ip_rule_priority:
            rules_at_priority.append(line)

    if not rules_at_priority:
        return "absent"
    if len(rules_at_priority) == 1 and _ip_rule_line_matches(
        rules_at_priority[0],
        fwmark=fwmark,
        ip_rule_priority=ip_rule_priority,
    ):
        return "owned"
    return "conflict"


def _ip_rule_owned_rule_count(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    fwmark: int = DEFAULT_WIREGUARD_FWMARK,
    ip_rule_priority: int = DEFAULT_WIREGUARD_IP_RULE_PRIORITY,
) -> int | None:
    try:
        result = runner(["ip", "rule", "show"], capture_output=True, text=True, check=False)
    except (OSError, FileNotFoundError):
        return None
    if result.returncode != 0:
        return None
    return sum(
        _ip_rule_line_matches(
            line,
            fwmark=fwmark,
            ip_rule_priority=ip_rule_priority,
        )
        for line in result.stdout.splitlines()
    )


def _delete_owned_ip_rule(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    fwmark: int = DEFAULT_WIREGUARD_FWMARK,
    ip_rule_priority: int = DEFAULT_WIREGUARD_IP_RULE_PRIORITY,
) -> bool:
    """Delete only Nordility's exact protocol-tagged policy rule."""
    command = [
        "ip",
        "rule",
        "del",
        "fwmark",
        str(fwmark),
        "lookup",
        "main",
        "priority",
        str(ip_rule_priority),
        "protocol",
        str(DEFAULT_WIREGUARD_IP_RULE_PROTOCOL),
    ]
    try:
        result = runner(command, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            result = runner(
                ["sudo", "-n"] + command,
                capture_output=True,
                text=True,
                check=False,
            )
    except (OSError, FileNotFoundError):
        result = None

    if result is None or result.returncode != 0:
        LOGGER.error(
            "Failed to roll back global WireGuard fwmark rule at priority %d",
            ip_rule_priority,
        )
        return False
    remaining_owned_rules = _ip_rule_owned_rule_count(
        runner,
        fwmark=fwmark,
        ip_rule_priority=ip_rule_priority,
    )
    if remaining_owned_rules is None or remaining_owned_rules != 0:
        LOGGER.error(
            "Protocol-tagged WireGuard fwmark rule may remain after rollback at priority %d",
            ip_rule_priority,
        )
        return False
    return True


def _wireguard_interface_has_fwmark(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    interface: str,
    fwmark: int = DEFAULT_WIREGUARD_FWMARK,
) -> bool:
    command = ["wg", "show", interface, "fwmark"]
    try:
        result = runner(command, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            result = runner(["sudo", "-n"] + command, capture_output=True, text=True, check=False)
    except (OSError, FileNotFoundError):
        return False
    if result.returncode != 0:
        return False
    value = result.stdout.strip().lower()
    return value in {hex(fwmark), str(fwmark)}


def _wireguard_routing_is_restored(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    interfaces: list[str] | None = None,
    fwmark: int = DEFAULT_WIREGUARD_FWMARK,
    ip_rule_priority: int = DEFAULT_WIREGUARD_IP_RULE_PRIORITY,
    wireguard_config_dir: Path | None = None,
    allowed_interfaces: tuple[str, ...] = DEFAULT_WIREGUARD_INTERFACES,
) -> bool:
    interfaces = interfaces if interfaces is not None else _discover_wireguard_interfaces(runner)
    allowed = set(allowed_interfaces)
    routing_candidates = _user_managed_wireguard_interfaces(
        [interface for interface in interfaces if interface in allowed],
        config_dir=wireguard_config_dir,
    )
    if not routing_candidates:
        return True
    if not _ip_rule_has_fwmark(
        runner,
        fwmark=fwmark,
        ip_rule_priority=ip_rule_priority,
    ):
        return False
    assignments = _wireguard_fwmark_assignments(runner)
    if assignments is None:
        return False
    routing_candidate_set = set(routing_candidates)
    if any(
        interface not in routing_candidate_set and assigned_mark == fwmark
        for interface, assigned_mark in assignments.items()
    ):
        return False
    return all(assignments.get(interface) == fwmark for interface in routing_candidates)


def watch_nordvpn_wireguard(
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    sleeper: Callable[[float], None] = time.sleep,
    executable: str = "nordvpn",
    backend: str = "cli",
    interval_seconds: float = 5,
    stabilize_seconds: float = 2,
    fwmark: int = DEFAULT_WIREGUARD_FWMARK,
    ip_rule_priority: int = DEFAULT_WIREGUARD_IP_RULE_PRIORITY,
    wireguard_config_dir: Path | None = None,
    ensure_interfaces: tuple[str, ...] = DEFAULT_WIREGUARD_INTERFACES,
    once: bool = False,
    max_iterations: int | None = None,
) -> list[WireGuardRestoreSummary]:
    """Watch NordVPN state and keep local WireGuard routing repaired.

    The watcher is intentionally polling-based so it remains dependency-free
    and works under systemd.  It reacts to NordVPN status/NordLynx changes and
    to missing WireGuard fwmark/ip-rule state.
    """
    if backend != "cli":
        raise ConfigurationError("watch-wireguard is only supported with the cli backend")
    if interval_seconds <= 0:
        raise ConfigurationError("--interval must be greater than 0")
    if stabilize_seconds < 0:
        raise ConfigurationError("--stabilize-wait must be greater than or equal to 0")
    denied_interfaces = [
        iface
        for iface in ensure_interfaces
        if iface.lower() in _DAEMON_MANAGED_WIREGUARD_INTERFACES
    ]
    if denied_interfaces:
        raise ConfigurationError(
            "refusing provider-managed WireGuard interface(s): " + ", ".join(denied_interfaces)
        )

    events: list[WireGuardRestoreSummary] = []

    def repair(reason: str) -> None:
        LOGGER.info("WireGuard repair triggered: %s", reason)
        summary = restore_wireguard_after_nordvpn(
            runner,
            backend=backend,
            fwmark=fwmark,
            ip_rule_priority=ip_rule_priority,
            wireguard_config_dir=wireguard_config_dir,
            ensure_interfaces=ensure_interfaces,
        )
        LOGGER.info("WireGuard repair result: %s", summary.describe())
        events.append(summary)

    repair("startup")
    if once:
        return events

    last_signature = _nordvpn_connection_signature(runner, executable=executable)
    iterations = 0

    while max_iterations is None or iterations < max_iterations:
        sleeper(interval_seconds)
        iterations += 1

        current_signature = _nordvpn_connection_signature(runner, executable=executable)
        if current_signature != last_signature:
            LOGGER.info(
                "NordVPN connection state changed; waiting %.1fs before repair",
                stabilize_seconds,
            )
            if stabilize_seconds:
                sleeper(stabilize_seconds)
            current_signature = _nordvpn_connection_signature(runner, executable=executable)
            last_signature = current_signature
            repair("nordvpn state changed")
            continue

        interfaces = _discover_wireguard_interfaces(runner)
        configured_down = [
            iface
            for iface in ensure_interfaces
            if iface not in interfaces
            and _wireguard_config_exists(iface, config_dir=wireguard_config_dir)
        ]
        if configured_down:
            repair(f"wireguard interface down: {', '.join(configured_down)}")
            continue

        if not _wireguard_routing_is_restored(
            runner,
            interfaces=interfaces,
            fwmark=fwmark,
            ip_rule_priority=ip_rule_priority,
            wireguard_config_dir=wireguard_config_dir,
            allowed_interfaces=ensure_interfaces,
        ):
            repair("wireguard routing drift")

    return events


class NordilityError(RuntimeError):
    pass


class ConfigurationError(NordilityError, ValueError):
    pass


class CommandExecutionError(NordilityError):
    pass


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    message: str
    group: str | None = None
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""


def resolve_executable(executable: str | None) -> str:
    if executable:
        return executable
    return (
        os.getenv("NORDILITY_EXECUTABLE")
        or os.getenv("NORDVPN_EXECUTABLE")
        or shutil.which("nordvpn")
        or DEFAULT_WINDOWS_EXECUTABLE
    )


def resolve_backend(executable: str, backend: str) -> str:
    configured = os.getenv("NORDILITY_BACKEND")
    backend = configured or backend
    if backend not in {"auto", "windows", "cli"}:
        raise ConfigurationError(f"Unsupported backend: {backend}")
    if backend != "auto":
        return backend
    return "windows" if executable.lower().endswith(".exe") else "cli"


def _format_group(group: str, backend: str) -> str:
    return group if backend == "windows" else group.replace("_", " ")


class NordVPNClient:
    def __init__(
        self,
        executable: str | None = None,
        backend: str = "auto",
        launcher: Callable[..., subprocess.Popen] = subprocess.Popen,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        sleeper: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        self.executable = resolve_executable(executable)
        self.backend = resolve_backend(self.executable, backend)
        self._launcher = launcher
        self._runner = runner
        self._sleeper = sleeper
        self._rng = rng or random.Random()

    def login(
        self,
        token: str | None = None,
        keepass_entry: str | None = None,
        keepass_profile: str | None = DEFAULT_KEEPASS_PROFILE,
    ) -> CommandResult:
        resolved_token = token or (
            _resolve_keepass_token(keepass_entry, keepass_profile) if keepass_entry else ""
        )
        if not resolved_token:
            raise ConfigurationError(
                "NordVPN login requires a token from the configured KeePass entry."
            )
        result = self._execute_token_login(resolved_token)
        return CommandResult(
            command=result.command,
            message="NordVPN Logged In",
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    def connect(
        self,
        group: str | None = None,
        wait_seconds: float = 0,
        auto_login: bool = False,
        keepass_entry: str | None = None,
        keepass_profile: str | None = DEFAULT_KEEPASS_PROFILE,
    ) -> CommandResult:
        command = self._build_connect_command(group)
        try:
            result = self._execute(command, wait_seconds)
        except CommandExecutionError as exc:
            if auto_login and _is_not_logged_in(str(exc)):
                LOGGER.info("Not logged in; attempting auto-login from KeePass.")
                self.login(
                    keepass_entry=keepass_entry,
                    keepass_profile=keepass_profile,
                )
                result = self._execute(command, wait_seconds)
            else:
                raise
        if group:
            return CommandResult(
                command=result.command,
                message=f"VPN Connected to {group}",
                group=group,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
            )
        return CommandResult(
            command=result.command,
            message="VPN Connected",
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    def disconnect(self, wait_seconds: float = 0) -> CommandResult:
        command = self._build_disconnect_command()
        result = self._execute(command, wait_seconds)
        return CommandResult(
            command=result.command,
            message="VPN Disconnected",
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    def change(
        self,
        speed: str = "fast",
        group: str | None = None,
        wait_seconds: float | None = None,
        auto_login: bool = False,
        keepass_entry: str | None = None,
        keepass_profile: str | None = DEFAULT_KEEPASS_PROFILE,
        restore_wireguard: bool = False,
        wireguard_fwmark: int = 51820,
    ) -> CommandResult:
        chosen_group = group or self.pick_group(speed)
        if wait_seconds is None:
            wait_seconds = 10 if speed == "fast" else 30
        command = self._build_connect_command(chosen_group)
        try:
            result = self._execute(command, wait_seconds)
        except CommandExecutionError as exc:
            if auto_login and _is_not_logged_in(str(exc)):
                LOGGER.info("Not logged in; attempting auto-login from KeePass.")
                self.login(
                    keepass_entry=keepass_entry,
                    keepass_profile=keepass_profile,
                )
                result = self._execute(command, wait_seconds)
            else:
                raise

        wg_suffix = ""
        if restore_wireguard:
            wg_suffix = restore_wireguard_after_nordvpn(
                self._runner,
                backend=self.backend,
                fwmark=wireguard_fwmark,
            ).message_suffix()

        return CommandResult(
            command=result.command,
            message=f"VPN Connection Successfully Redirected to {chosen_group}{wg_suffix}",
            group=chosen_group,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    def list_groups(self, speed: str = "fast") -> tuple[str, ...]:
        return GROUPS_BY_SPEED[self._normalize_speed(speed)]

    def pick_group(self, speed: str = "fast") -> str:
        groups = self.list_groups(speed)
        return self._rng.choice(groups)

    def _build_connect_command(self, group: str | None = None) -> tuple[str, ...]:
        if self.backend == "windows":
            if group:
                return (self.executable, "-c", "-g", group)
            return (self.executable, "-c")
        if group:
            return (self.executable, "connect", _format_group(group, self.backend))
        return (self.executable, "connect")

    def _build_disconnect_command(self) -> tuple[str, ...]:
        if self.backend == "windows":
            return (self.executable, "-d")
        return (self.executable, "disconnect")

    def _build_login_command(self) -> tuple[str, ...]:
        executable = shutil.which(self.executable) or self.executable
        return (sys.executable, "-m", "nordility.token_login", executable)

    def _execute_token_login(self, token: str) -> CommandResult:
        if self.backend != "cli":
            raise ConfigurationError(
                "programmatic token login is supported only by the hardened Linux CLI helper"
            )
        command = self._build_login_command()
        LOGGER.info("Running NordVPN login through the no-echo PTY helper")
        try:
            completed = self._runner(
                command,
                input=f"{token}\n",
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            raise CommandExecutionError(_redact_text(str(exc), (token,))) from exc
        if completed.returncode != 0:
            raise CommandExecutionError(
                _redact_text(completed.stderr.strip(), (token,))
                or f"NordVPN login helper failed with exit code {completed.returncode}"
            )
        return CommandResult(
            command=command,
            message="Command completed",
            returncode=completed.returncode,
            stdout=_redact_text(completed.stdout, (token,)),
            stderr=_redact_text(completed.stderr, (token,)),
        )

    def _execute(self, command: tuple[str, ...], wait_seconds: float) -> CommandResult:
        display_command, secret_arguments = _redact_command(command)
        LOGGER.info("Running NordVPN command: %s", " ".join(display_command))
        if self.backend == "windows":
            try:
                self._launcher(command)
            except OSError as exc:
                raise CommandExecutionError(_redact_text(str(exc), secret_arguments)) from exc
            if wait_seconds > 0:
                self._sleeper(wait_seconds)
            return CommandResult(command=display_command, message="Command launched")

        completed = self._runner(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise CommandExecutionError(
                _redact_text(completed.stderr.strip(), secret_arguments)
                or f"NordVPN command failed with exit code {completed.returncode}"
            )
        if wait_seconds > 0:
            self._sleeper(wait_seconds)
        return CommandResult(
            command=display_command,
            message="Command completed",
            returncode=completed.returncode,
            stdout=_redact_text(completed.stdout, secret_arguments),
            stderr=_redact_text(completed.stderr, secret_arguments),
        )

    @staticmethod
    def _normalize_speed(speed: str) -> str:
        normalized = speed.lower()
        if normalized not in GROUPS_BY_SPEED:
            raise ConfigurationError(f"Unsupported speed: {speed}")
        return normalized


def login_vpn_server(
    token: str | None = None,
    keepass_entry: str | None = DEFAULT_KEEPASS_ENTRY,
    keepass_profile: str | None = DEFAULT_KEEPASS_PROFILE,
    status: bool = True,
    executable: str | None = None,
    backend: str = "auto",
) -> str | CommandResult:
    client = NordVPNClient(executable=executable, backend=backend)
    try:
        result = client.login(
            token=token,
            keepass_entry=keepass_entry,
            keepass_profile=keepass_profile,
        )
        return result.message if status else result
    except NordilityError as exc:
        LOGGER.error("%s\nexception in login_vpn_server", exc)
        if status:
            return "NordVPN Login Failed"
        raise


def connect_vpn_server(
    status: bool = True,
    executable: str | None = None,
    backend: str = "auto",
    group: str | None = None,
    wait_seconds: float = 0,
) -> str | CommandResult:
    client = NordVPNClient(executable=executable, backend=backend)
    try:
        result = client.connect(group=group, wait_seconds=wait_seconds)
        return result.message if status else result
    except NordilityError as exc:
        LOGGER.error("%s\nexception in connect_vpn_server", exc)
        if status:
            return "VPN Failed to Connect"
        raise


def disconnect_vpn_server(
    status: bool = True,
    executable: str | None = None,
    backend: str = "auto",
    wait_seconds: float = 0,
) -> str | CommandResult:
    client = NordVPNClient(executable=executable, backend=backend)
    try:
        result = client.disconnect(wait_seconds=wait_seconds)
        return result.message if status else result
    except NordilityError as exc:
        LOGGER.error("%s\nexception in disconnect_vpn_server", exc)
        if status:
            return "VPN Failed to Disconnect"
        raise


def change_vpn_server(
    speed: str = "fast",
    fast_reset: float = 10,
    default_reset: float = 30,
    status: bool = True,
    executable: str | None = None,
    backend: str = "auto",
    group: str | None = None,
    restore_wireguard: bool = False,
    wireguard_fwmark: int = 51820,
) -> str | CommandResult:
    client = NordVPNClient(executable=executable, backend=backend)
    try:
        wait_seconds = fast_reset if speed == "fast" else default_reset
        result = client.change(
            speed=speed,
            group=group,
            wait_seconds=wait_seconds,
            restore_wireguard=restore_wireguard,
            wireguard_fwmark=wireguard_fwmark,
        )
        return result.message if status else result
    except NordilityError as exc:
        LOGGER.error("%s\nexception in change_vpn_server", exc)
        failed_group = group or "selected group"
        if status:
            return f"VPN Connection Failed to Redirect to {failed_group}"
        raise
