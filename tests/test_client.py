import random
import unittest
from subprocess import CompletedProcess

from nordility.client import (
    ConfigurationError,
    FAST_GROUPS,
    NordVPNClient,
    resolve_backend,
)


class NordVPNClientTests(unittest.TestCase):
    def test_resolve_backend_auto_detects_windows(self) -> None:
        self.assertEqual(
            resolve_backend("C:/Program Files/NordVPN/NordVPN.exe", "auto"), "windows"
        )

    def test_resolve_backend_auto_detects_cli(self) -> None:
        self.assertEqual(resolve_backend("nordvpn", "auto"), "cli")

    def test_invalid_backend_raises_configuration_error(self) -> None:
        with self.assertRaises(ConfigurationError):
            resolve_backend("nordvpn", "bad-backend")

    def test_pick_group_uses_fast_pool(self) -> None:
        client = NordVPNClient(executable="nordvpn", rng=random.Random(1))
        self.assertIn(client.pick_group("fast"), FAST_GROUPS)

    def test_windows_command_uses_original_flags(self) -> None:
        launched_commands = []

        def fake_launcher(command):
            launched_commands.append(command)
            return object()

        client = NordVPNClient(
            executable="C:/Program Files/NordVPN/NordVPN.exe",
            backend="windows",
            launcher=fake_launcher,
            sleeper=lambda _: None,
        )

        result = client.connect(group="United_States", wait_seconds=0)

        self.assertEqual(
            launched_commands[0],
            ("C:/Program Files/NordVPN/NordVPN.exe", "-c", "-g", "United_States"),
        )
        self.assertEqual(result.message, "VPN Connected to United_States")

    def test_cli_disconnect_uses_cli_verb(self) -> None:
        recorded = {}

        def fake_runner(command, capture_output, text, check):
            recorded["command"] = command
            return CompletedProcess(command, 0, stdout="ok", stderr="")

        client = NordVPNClient(
            executable="nordvpn",
            backend="cli",
            runner=fake_runner,
            sleeper=lambda _: None,
        )

        result = client.disconnect(wait_seconds=0)

        self.assertEqual(recorded["command"], ("nordvpn", "disconnect"))
        self.assertEqual(result.message, "VPN Disconnected")

    def test_cli_group_replaces_underscores_with_spaces(self) -> None:
        recorded = {}

        def fake_runner(command, capture_output, text, check):
            recorded["command"] = command
            return CompletedProcess(command, 0, stdout="ok", stderr="")

        client = NordVPNClient(
            executable="nordvpn",
            backend="cli",
            runner=fake_runner,
            sleeper=lambda _: None,
        )

        client.connect(group="United_States", wait_seconds=0)

        self.assertEqual(recorded["command"], ("nordvpn", "connect", "United States"))


if __name__ == "__main__":
    unittest.main()
