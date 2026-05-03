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
DEFAULT_KEEPASS_PROFILE = "infra"
DEFAULT_WIREGUARD_FWMARK = 51820
DEFAULT_WIREGUARD_IP_RULE_PRIORITY = 100
DEFAULT_WIREGUARD_INTERFACES = ("wg0",)

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
    ``vpn/provider#access-token`` from the ``infra`` profile.
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

    Returns the list of interfaces where the fwmark was successfully set.
    The ip rule is global (not per-interface) and is added at most once.
    """
    restored: list[str] = []
    fwmark_hex = hex(fwmark)

    for iface in interfaces:
        cmd = ["wg", "set", iface, "fwmark", str(fwmark)]
        try:
            result = runner(cmd, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                result = runner(["sudo", "-n"] + cmd, capture_output=True, text=True, check=False)
            if result.returncode == 0:
                restored.append(iface)
            else:
                LOGGER.warning("Could not set fwmark %s on %s", fwmark_hex, iface)
        except (OSError, FileNotFoundError):
            LOGGER.warning("wg not available; skipping fwmark for %s", iface)

    if not restored:
        return restored

    # The ip rule is global — add it once after confirming at least one interface
    # had its fwmark set successfully.
    try:
        show = runner(["ip", "rule", "show"], capture_output=True, text=True, check=False)
        if show.returncode == 0 and fwmark_hex in show.stdout:
            LOGGER.debug("ip rule for fwmark %s already present; skipping", fwmark_hex)
            return restored
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
        ]
        add_result = runner(add_cmd, capture_output=True, text=True, check=False)
        if add_result.returncode != 0:
            add_result = runner(
                ["sudo", "-n"] + add_cmd, capture_output=True, text=True, check=False
            )
        if add_result.returncode != 0:
            LOGGER.warning(
                "Could not add ip rule for fwmark %s (priority %d)", fwmark_hex, ip_rule_priority
            )
    except (OSError, FileNotFoundError):
        LOGGER.warning("ip not available; skipping routing rule")

    return restored


def _user_managed_wireguard_interfaces(
    interfaces: list[str],
    config_dir: Path | None = None,
) -> list[str]:
    """Filter to WireGuard interfaces owned by local config files.

    NordVPN's NordLynx interface is also a WireGuard interface, but it is
    daemon-managed and normally has no ``/etc/wireguard/nordlynx.conf``.  Only
    user-managed interfaces should have their socket fwmark overwritten.
    """
    if config_dir is None:
        return [iface for iface in interfaces if Path(f"/etc/wireguard/{iface}.conf").exists()]
    return [iface for iface in interfaces if (config_dir / f"{iface}.conf").exists()]


def _wireguard_config_exists(interface: str, config_dir: Path | None = None) -> bool:
    if config_dir is None:
        return Path(f"/etc/wireguard/{interface}.conf").exists()
    return (config_dir / f"{interface}.conf").exists()


def _start_wireguard_interface(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    interface: str,
) -> bool:
    commands = (
        ["systemctl", "start", f"wg-quick@{interface}.service"],
        ["wg-quick", "up", interface],
    )
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
) -> list[str]:
    """Force a handshake re-initiation for all peers on the given interfaces.

    Re-sets each peer's endpoint to its current value, which causes the
    WireGuard kernel module to immediately initiate a new handshake instead
    of waiting for the next keepalive interval.

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
    for iface in interfaces:
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
    ensure_interfaces: tuple[str, ...] = (),
) -> WireGuardRestoreSummary:
    """Refresh WireGuard peers and restore routing after NordVPN changes state."""
    started = _ensure_wireguard_interfaces(
        runner,
        interfaces=ensure_interfaces,
        config_dir=wireguard_config_dir,
    )
    interfaces = _discover_wireguard_interfaces(runner)
    if not interfaces:
        LOGGER.debug("No active WireGuard interfaces discovered; skipping restore.")
        return WireGuardRestoreSummary(started=tuple(started))

    LOGGER.info("Refreshing WireGuard handshakes on: %s", ", ".join(interfaces))
    refreshed = _refresh_wireguard_peers(runner, interfaces)

    routing_candidates: list[str] = []
    routing_restored: list[str] = []
    if backend == "cli":
        routing_candidates = _user_managed_wireguard_interfaces(
            interfaces, config_dir=wireguard_config_dir
        )
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


def _ip_rule_has_fwmark(
    runner: Callable[..., subprocess.CompletedProcess[str]],
    fwmark: int = DEFAULT_WIREGUARD_FWMARK,
) -> bool:
    fwmark_hex = hex(fwmark)
    try:
        result = runner(["ip", "rule", "show"], capture_output=True, text=True, check=False)
    except (OSError, FileNotFoundError):
        return False
    if result.returncode != 0:
        return False
    return fwmark_hex in result.stdout or f"fwmark {fwmark}" in result.stdout


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
    wireguard_config_dir: Path | None = None,
) -> bool:
    interfaces = interfaces if interfaces is not None else _discover_wireguard_interfaces(runner)
    routing_candidates = _user_managed_wireguard_interfaces(
        interfaces, config_dir=wireguard_config_dir
    )
    if not routing_candidates:
        return True
    if not _ip_rule_has_fwmark(runner, fwmark=fwmark):
        return False
    return all(
        _wireguard_interface_has_fwmark(runner, iface, fwmark=fwmark)
        for iface in routing_candidates
    )


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
            wireguard_config_dir=wireguard_config_dir,
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
                "NordVPN login requires a token. Provide --token or --keepass-entry."
            )
        command = self._build_login_command(resolved_token)
        result = self._execute(command, 0)
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

    def _build_login_command(self, token: str) -> tuple[str, ...]:
        return (self.executable, "login", "--token", token)

    def _execute(self, command: tuple[str, ...], wait_seconds: float) -> CommandResult:
        LOGGER.info("Running NordVPN command: %s", " ".join(command))
        if self.backend == "windows":
            try:
                self._launcher(command)
            except OSError as exc:
                raise CommandExecutionError(str(exc)) from exc
            if wait_seconds > 0:
                self._sleeper(wait_seconds)
            return CommandResult(command=command, message="Command launched")

        completed = self._runner(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise CommandExecutionError(
                completed.stderr.strip()
                or f"NordVPN command failed with exit code {completed.returncode}"
            )
        if wait_seconds > 0:
            self._sleeper(wait_seconds)
        return CommandResult(
            command=command,
            message="Command completed",
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
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
