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

_AUTO_PASS_ROOT = Path(__file__).resolve().parent.parent.parent.parent / "auto-pass"


def _resolve_keepass_token(keepass_entry: str) -> str:
    """Resolve the NordVPN access token from a KeePassXC entry via auto-pass.

    Reads the ``Password`` field of the entry. By default the entry is
    ``Nord_VPN#access-token``.
    """
    _src = str(_AUTO_PASS_ROOT / "src")
    if _src not in sys.path:
        sys.path.insert(0, _src)
    from auto_pass.envfile import load_config_environment  # noqa: PLC0415
    from auto_pass.keepassxc import resolve_keepassxc_entry  # noqa: PLC0415

    _ap_env = _AUTO_PASS_ROOT / "config" / "auto-pass.env.local"
    if _ap_env.is_file():
        load_config_environment(_ap_env)
    result = resolve_keepassxc_entry(keepass_entry, attrs_map={"token": "password"})
    return result.get("token", "")


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
    ) -> CommandResult:
        resolved_token = token or (_resolve_keepass_token(keepass_entry) if keepass_entry else "")
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
    ) -> CommandResult:
        command = self._build_connect_command(group)
        try:
            result = self._execute(command, wait_seconds)
        except CommandExecutionError as exc:
            if auto_login and _is_not_logged_in(str(exc)):
                LOGGER.info("Not logged in; attempting auto-login from KeePass.")
                self.login(keepass_entry=keepass_entry)
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
        restore_wireguard: bool = False,
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
                self.login(keepass_entry=keepass_entry)
                result = self._execute(command, wait_seconds)
            else:
                raise

        wg_suffix = ""
        if restore_wireguard:
            interfaces = _discover_wireguard_interfaces(self._runner)
            if interfaces:
                LOGGER.info("Refreshing WireGuard handshakes on: %s", ", ".join(interfaces))
                refreshed = _refresh_wireguard_peers(self._runner, interfaces)
                if refreshed:
                    wg_suffix = f"; WireGuard refreshed on {', '.join(refreshed)}"
            else:
                LOGGER.debug("No active WireGuard interfaces discovered; skipping restore.")

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
    keepass_entry: str | None = "Nord_VPN#access-token",
    status: bool = True,
    executable: str | None = None,
    backend: str = "auto",
) -> str | CommandResult:
    client = NordVPNClient(executable=executable, backend=backend)
    try:
        result = client.login(token=token, keepass_entry=keepass_entry)
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
) -> str | CommandResult:
    client = NordVPNClient(executable=executable, backend=backend)
    try:
        wait_seconds = fast_reset if speed == "fast" else default_reset
        result = client.change(
            speed=speed,
            group=group,
            wait_seconds=wait_seconds,
            restore_wireguard=restore_wireguard,
        )
        return result.message if status else result
    except NordilityError as exc:
        LOGGER.error("%s\nexception in change_vpn_server", exc)
        failed_group = group or "selected group"
        if status:
            return f"VPN Connection Failed to Redirect to {failed_group}"
        raise
