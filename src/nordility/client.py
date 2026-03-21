from __future__ import annotations

import logging
import os
import random
import subprocess
import time
from dataclasses import dataclass
from typing import Callable

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

    def connect(self, group: str | None = None, wait_seconds: float = 0) -> CommandResult:
        command = self._build_connect_command(group)
        result = self._execute(command, wait_seconds)
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
    ) -> CommandResult:
        chosen_group = group or self.pick_group(speed)
        if wait_seconds is None:
            wait_seconds = 10 if speed == "fast" else 30
        command = self._build_connect_command(chosen_group)
        result = self._execute(command, wait_seconds)
        return CommandResult(
            command=result.command,
            message=f"VPN Connection Successfully Redirected to {chosen_group}",
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
                completed.stderr.strip() or f"NordVPN command failed with exit code {completed.returncode}"
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
) -> str | CommandResult:
    client = NordVPNClient(executable=executable, backend=backend)
    try:
        wait_seconds = fast_reset if speed == "fast" else default_reset
        result = client.change(speed=speed, group=group, wait_seconds=wait_seconds)
        return result.message if status else result
    except NordilityError as exc:
        LOGGER.error("%s\nexception in change_vpn_server", exc)
        failed_group = group or "selected group"
        if status:
            return f"VPN Connection Failed to Redirect to {failed_group}"
        raise
