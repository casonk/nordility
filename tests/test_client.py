import random
import unittest
from subprocess import CompletedProcess
from unittest import mock

from nordility.client import (
    CommandExecutionError,
    ConfigurationError,
    FAST_GROUPS,
    NordVPNClient,
    _is_not_logged_in,
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

    def test_login_builds_token_command(self) -> None:
        recorded = {}

        def fake_runner(command, capture_output, text, check):
            recorded["command"] = command
            return CompletedProcess(command, 0, stdout="Welcome to NordVPN!", stderr="")

        client = NordVPNClient(
            executable="nordvpn",
            backend="cli",
            runner=fake_runner,
            sleeper=lambda _: None,
        )

        result = client.login(token="test-token-abc123")

        self.assertEqual(
            recorded["command"],
            ("nordvpn", "login", "--token", "test-token-abc123"),
        )
        self.assertEqual(result.message, "NordVPN Logged In")

    def test_login_requires_token_or_entry(self) -> None:
        client = NordVPNClient(executable="nordvpn", backend="cli")
        with self.assertRaises(ConfigurationError):
            client.login()

    def test_is_not_logged_in_detects_markers(self) -> None:
        self.assertTrue(_is_not_logged_in("Please log in."))
        self.assertTrue(_is_not_logged_in("You are not logged in."))
        self.assertTrue(_is_not_logged_in("not logged in"))
        self.assertFalse(_is_not_logged_in("Connection failed: server timeout"))

    def test_connect_auto_login_retries_after_not_logged_in(self) -> None:
        calls = []

        def fake_runner(command, capture_output, text, check):
            calls.append(command)
            if command == ("nordvpn", "connect") and len(calls) == 1:
                return CompletedProcess(command, 1, stdout="", stderr="Please log in.")
            return CompletedProcess(command, 0, stdout="ok", stderr="")

        client = NordVPNClient(
            executable="nordvpn",
            backend="cli",
            runner=fake_runner,
            sleeper=lambda _: None,
        )

        with mock.patch("nordility.client._resolve_keepass_token", return_value="tok"):
            result = client.connect(auto_login=True, keepass_entry="Nord_VPN#access-token")

        self.assertEqual(calls[0], ("nordvpn", "connect"))
        self.assertEqual(calls[1], ("nordvpn", "login", "--token", "tok"))
        self.assertEqual(calls[2], ("nordvpn", "connect"))
        self.assertEqual(result.message, "VPN Connected")


if __name__ == "__main__":
    unittest.main()
