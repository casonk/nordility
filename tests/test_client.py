import random
import unittest
from subprocess import CompletedProcess
from unittest import mock

from nordility.client import (
    FAST_GROUPS,
    ConfigurationError,
    NordVPNClient,
    _discover_wireguard_interfaces,
    _get_wireguard_peer_endpoints,
    _is_not_logged_in,
    _refresh_wireguard_peers,
    _restore_wireguard_routing,
    resolve_backend,
    resolve_executable,
)


class NordVPNClientTests(unittest.TestCase):
    def test_resolve_backend_auto_detects_windows(self) -> None:
        self.assertEqual(resolve_backend("C:/Program Files/NordVPN/NordVPN.exe", "auto"), "windows")

    def test_resolve_backend_auto_detects_cli(self) -> None:
        self.assertEqual(resolve_backend("nordvpn", "auto"), "cli")

    def test_invalid_backend_raises_configuration_error(self) -> None:
        with self.assertRaises(ConfigurationError):
            resolve_backend("nordvpn", "bad-backend")

    def test_resolve_executable_uses_which_on_linux(self) -> None:
        with (
            mock.patch("nordility.client.shutil.which", return_value="/usr/bin/nordvpn"),
            mock.patch.dict("os.environ", {}, clear=True),
        ):
            result = resolve_executable(None)
        self.assertEqual(result, "/usr/bin/nordvpn")

    def test_resolve_executable_falls_back_to_windows_path_when_not_found(self) -> None:
        with mock.patch("nordility.client.shutil.which", return_value=None):
            with mock.patch.dict("os.environ", {}, clear=True):
                result = resolve_executable(None)
        self.assertIn("NordVPN.exe", result)

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


class WireGuardRestoreTests(unittest.TestCase):
    def _make_runner(self, responses: dict[tuple, CompletedProcess]):
        """Return a fake runner that maps command tuples to CompletedProcess results."""

        def fake_runner(command, capture_output, text, check):
            key = tuple(command)
            if key in responses:
                return responses[key]
            return CompletedProcess(command, 0, stdout="", stderr="")

        return fake_runner

    def test_discover_returns_interface_names(self) -> None:
        runner = self._make_runner(
            {
                ("wg", "show", "interfaces"): CompletedProcess(
                    [], 0, stdout="wg0 wg1\n", stderr=""
                ),
            }
        )
        self.assertEqual(_discover_wireguard_interfaces(runner), ["wg0", "wg1"])

    def test_discover_returns_empty_when_no_interfaces(self) -> None:
        runner = self._make_runner(
            {
                ("wg", "show", "interfaces"): CompletedProcess([], 0, stdout="", stderr=""),
            }
        )
        self.assertEqual(_discover_wireguard_interfaces(runner), [])

    def test_discover_returns_empty_on_wg_unavailable(self) -> None:
        def failing_runner(command, **_):
            raise FileNotFoundError("wg not found")

        self.assertEqual(_discover_wireguard_interfaces(failing_runner), [])

    def test_get_peer_endpoints_parses_output(self) -> None:
        runner = self._make_runner(
            {
                ("wg", "show", "wg0", "endpoints"): CompletedProcess(
                    [],
                    0,
                    stdout="PUBKEY1\t203.0.113.1:51820\nPUBKEY2\t(none)\n",
                    stderr="",
                ),
            }
        )
        result = _get_wireguard_peer_endpoints(runner, "wg0")
        self.assertEqual(result, {"PUBKEY1": "203.0.113.1:51820"})
        self.assertNotIn("PUBKEY2", result)

    def test_get_peer_endpoints_retries_with_sudo_on_failure(self) -> None:
        calls: list[tuple] = []
        responses = {
            ("wg", "show", "wg0", "endpoints"): CompletedProcess(
                [], 1, stdout="", stderr="Operation not permitted"
            ),
            ("sudo", "-n", "wg", "show", "wg0", "endpoints"): CompletedProcess(
                [], 0, stdout="PUBKEY\t10.0.0.1:51820\n", stderr=""
            ),
        }

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            return responses.get(tuple(command), CompletedProcess(command, 0, stdout="", stderr=""))

        result = _get_wireguard_peer_endpoints(runner, "wg0")

        self.assertEqual(result, {"PUBKEY": "10.0.0.1:51820"})
        self.assertIn(("sudo", "-n", "wg", "show", "wg0", "endpoints"), calls)

    def test_refresh_peers_retries_with_sudo_on_permission_failure(self) -> None:
        real_calls: list[tuple] = []
        responses = {
            ("wg", "show", "interfaces"): CompletedProcess([], 0, stdout="wg0\n", stderr=""),
            ("wg", "show", "wg0", "endpoints"): CompletedProcess(
                [], 0, stdout="PUBKEY\t203.0.113.1:51820\n", stderr=""
            ),
            # plain wg set fails (permission denied)
            (
                "wg",
                "set",
                "wg0",
                "peer",
                "PUBKEY",
                "endpoint",
                "203.0.113.1:51820",
            ): CompletedProcess([], 1, stdout="", stderr="Operation not permitted"),
            # sudo -n wg set succeeds
            (
                "sudo",
                "-n",
                "wg",
                "set",
                "wg0",
                "peer",
                "PUBKEY",
                "endpoint",
                "203.0.113.1:51820",
            ): CompletedProcess([], 0, stdout="", stderr=""),
        }

        def runner(command, capture_output, text, check):
            real_calls.append(tuple(command))
            return responses.get(tuple(command), CompletedProcess(command, 0, stdout="", stderr=""))

        interfaces = _discover_wireguard_interfaces(runner)
        refreshed = _refresh_wireguard_peers(runner, interfaces)

        self.assertEqual(refreshed, ["wg0"])
        self.assertIn(
            (
                "sudo",
                "-n",
                "wg",
                "set",
                "wg0",
                "peer",
                "PUBKEY",
                "endpoint",
                "203.0.113.1:51820",
            ),
            real_calls,
        )
        calls = []

        def fake_runner(command, capture_output, text, check):
            calls.append(tuple(command))
            return CompletedProcess(command, 0, stdout="", stderr="")

        # Pre-populate: wg show interfaces → wg0, wg show wg0 endpoints → one peer
        real_calls: list[tuple] = []
        responses = {
            ("wg", "show", "interfaces"): CompletedProcess([], 0, stdout="wg0\n", stderr=""),
            ("wg", "show", "wg0", "endpoints"): CompletedProcess(
                [], 0, stdout="PUBKEY\t203.0.113.1:51820\n", stderr=""
            ),
        }

        def runner(command, capture_output, text, check):
            real_calls.append(tuple(command))
            key = tuple(command)
            return responses.get(key, CompletedProcess(command, 0, stdout="", stderr=""))

        interfaces = _discover_wireguard_interfaces(runner)
        refreshed = _refresh_wireguard_peers(runner, interfaces)

        self.assertEqual(refreshed, ["wg0"])
        self.assertIn(
            ("wg", "set", "wg0", "peer", "PUBKEY", "endpoint", "203.0.113.1:51820"),
            real_calls,
        )

    def test_change_with_restore_wireguard_refreshes_peers(self) -> None:
        wg_responses = {
            ("wg", "show", "interfaces"): CompletedProcess([], 0, stdout="wg0\n", stderr=""),
            ("wg", "show", "wg0", "endpoints"): CompletedProcess(
                [], 0, stdout="PUBKEY\t10.0.0.1:51820\n", stderr=""
            ),
        }

        def fake_runner(command, capture_output, text, check):
            key = tuple(command)
            if key in wg_responses:
                return wg_responses[key]
            return CompletedProcess(command, 0, stdout="ok", stderr="")

        client = NordVPNClient(
            executable="nordvpn",
            backend="cli",
            runner=fake_runner,
            sleeper=lambda _: None,
            rng=random.Random(1),
        )

        result = client.change(restore_wireguard=True)

        self.assertIn("WireGuard refreshed on wg0", result.message)

    def test_change_with_restore_wireguard_no_interfaces_is_silent(self) -> None:
        def fake_runner(command, capture_output, text, check):
            if tuple(command) == ("wg", "show", "interfaces"):
                return CompletedProcess(command, 0, stdout="", stderr="")
            return CompletedProcess(command, 0, stdout="ok", stderr="")

        client = NordVPNClient(
            executable="nordvpn",
            backend="cli",
            runner=fake_runner,
            sleeper=lambda _: None,
            rng=random.Random(1),
        )

        result = client.change(restore_wireguard=True)

        self.assertNotIn("WireGuard", result.message)


class WireGuardRoutingRestoreTests(unittest.TestCase):
    def _make_runner(self, responses: dict[tuple, CompletedProcess]):
        def fake_runner(command, capture_output, text, check):
            return responses.get(tuple(command), CompletedProcess(command, 0, stdout="", stderr=""))

        return fake_runner

    def test_sets_fwmark_and_adds_rule_when_not_present(self) -> None:
        calls: list[tuple] = []

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            if tuple(command) == ("ip", "rule", "show"):
                return CompletedProcess(command, 0, stdout="32766:\tfrom all lookup main\n", stderr="")
            return CompletedProcess(command, 0, stdout="", stderr="")

        restored = _restore_wireguard_routing(runner, ["wg0"], fwmark=51820)

        self.assertEqual(restored, ["wg0"])
        self.assertIn(("wg", "set", "wg0", "fwmark", "51820"), calls)
        self.assertIn(
            ("ip", "rule", "add", "fwmark", "51820", "lookup", "main", "priority", "100"), calls
        )

    def test_skips_ip_rule_add_when_already_present(self) -> None:
        calls: list[tuple] = []

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            if tuple(command) == ("ip", "rule", "show"):
                return CompletedProcess(
                    command, 0, stdout="100:\tfrom all fwmark 0xca6c lookup main\n", stderr=""
                )
            return CompletedProcess(command, 0, stdout="", stderr="")

        _restore_wireguard_routing(runner, ["wg0"], fwmark=51820)

        add_cmd = ("ip", "rule", "add", "fwmark", "51820", "lookup", "main", "priority", "100")
        self.assertNotIn(add_cmd, calls)

    def test_retries_fwmark_with_sudo_on_permission_failure(self) -> None:
        calls: list[tuple] = []
        responses = {
            ("wg", "set", "wg0", "fwmark", "51820"): CompletedProcess(
                [], 1, stdout="", stderr="Operation not permitted"
            ),
            ("sudo", "-n", "wg", "set", "wg0", "fwmark", "51820"): CompletedProcess(
                [], 0, stdout="", stderr=""
            ),
            ("ip", "rule", "show"): CompletedProcess([], 0, stdout="", stderr=""),
        }

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            return responses.get(tuple(command), CompletedProcess(command, 0, stdout="", stderr=""))

        restored = _restore_wireguard_routing(runner, ["wg0"], fwmark=51820)

        self.assertEqual(restored, ["wg0"])
        self.assertIn(("sudo", "-n", "wg", "set", "wg0", "fwmark", "51820"), calls)

    def test_retries_ip_rule_add_with_sudo_on_permission_failure(self) -> None:
        calls: list[tuple] = []
        responses = {
            ("ip", "rule", "show"): CompletedProcess([], 0, stdout="", stderr=""),
            ("ip", "rule", "add", "fwmark", "51820", "lookup", "main", "priority", "100"): CompletedProcess(
                [], 1, stdout="", stderr="Operation not permitted"
            ),
            (
                "sudo", "-n", "ip", "rule", "add", "fwmark", "51820", "lookup", "main", "priority", "100"
            ): CompletedProcess([], 0, stdout="", stderr=""),
        }

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            return responses.get(tuple(command), CompletedProcess(command, 0, stdout="", stderr=""))

        _restore_wireguard_routing(runner, ["wg0"], fwmark=51820)

        self.assertIn(
            ("sudo", "-n", "ip", "rule", "add", "fwmark", "51820", "lookup", "main", "priority", "100"),
            calls,
        )

    def test_returns_empty_when_fwmark_set_fails(self) -> None:
        def runner(command, capture_output, text, check):
            if "fwmark" in command and "wg" in command:
                return CompletedProcess(command, 1, stdout="", stderr="error")
            return CompletedProcess(command, 0, stdout="", stderr="")

        restored = _restore_wireguard_routing(runner, ["wg0"], fwmark=51820)

        self.assertEqual(restored, [])

    def test_change_cli_restores_routing_with_restore_wireguard(self) -> None:
        calls: list[tuple] = []
        wg_responses = {
            ("wg", "show", "interfaces"): CompletedProcess([], 0, stdout="wg0\n", stderr=""),
            ("wg", "show", "wg0", "endpoints"): CompletedProcess(
                [], 0, stdout="PUBKEY\t10.0.0.1:51820\n", stderr=""
            ),
            ("ip", "rule", "show"): CompletedProcess([], 0, stdout="", stderr=""),
        }

        def fake_runner(command, capture_output, text, check):
            calls.append(tuple(command))
            return wg_responses.get(tuple(command), CompletedProcess(command, 0, stdout="ok", stderr=""))

        client = NordVPNClient(
            executable="nordvpn",
            backend="cli",
            runner=fake_runner,
            sleeper=lambda _: None,
            rng=random.Random(1),
        )

        with mock.patch("nordility.client.Path") as mock_path:
            mock_path.return_value.exists.return_value = True
            result = client.change(restore_wireguard=True, wireguard_fwmark=51820)

        self.assertIn("WireGuard refreshed on wg0", result.message)
        self.assertIn("routing restored on wg0", result.message)
        self.assertIn(("wg", "set", "wg0", "fwmark", "51820"), calls)

    def test_change_cli_skips_routing_for_vpn_managed_interfaces(self) -> None:
        """nordlynx and other VPN-managed interfaces without /etc/wireguard/<iface>.conf
        must not have their fwmark overwritten."""
        calls: list[tuple] = []
        wg_responses = {
            ("wg", "show", "interfaces"): CompletedProcess(
                [], 0, stdout="wg0 nordlynx\n", stderr=""
            ),
            ("wg", "show", "wg0", "endpoints"): CompletedProcess(
                [], 0, stdout="PUBKEY\t10.0.0.1:51820\n", stderr=""
            ),
            ("wg", "show", "nordlynx", "endpoints"): CompletedProcess(
                [], 0, stdout="PUBKEY2\t1.2.3.4:51820\n", stderr=""
            ),
            ("ip", "rule", "show"): CompletedProcess([], 0, stdout="", stderr=""),
        }

        def fake_runner(command, capture_output, text, check):
            calls.append(tuple(command))
            return wg_responses.get(tuple(command), CompletedProcess(command, 0, stdout="ok", stderr=""))

        client = NordVPNClient(
            executable="nordvpn",
            backend="cli",
            runner=fake_runner,
            sleeper=lambda _: None,
            rng=random.Random(1),
        )

        def path_exists(path_str):
            # only wg0 has a config file; nordlynx does not
            return "wg0" in str(path_str)

        with mock.patch("nordility.client.Path") as mock_path:
            mock_path.side_effect = lambda p: mock.MagicMock(exists=lambda: path_exists(p))
            client.change(restore_wireguard=True, wireguard_fwmark=51820)

        nordlynx_fwmark = ("wg", "set", "nordlynx", "fwmark", "51820")
        self.assertNotIn(nordlynx_fwmark, calls)

    def test_change_windows_backend_skips_routing_restore(self) -> None:
        calls: list[tuple] = []
        wg_responses = {
            ("wg", "show", "interfaces"): CompletedProcess([], 0, stdout="wg0\n", stderr=""),
            ("wg", "show", "wg0", "endpoints"): CompletedProcess(
                [], 0, stdout="PUBKEY\t10.0.0.1:51820\n", stderr=""
            ),
        }

        def fake_runner(command, capture_output, text, check):
            calls.append(tuple(command))
            return wg_responses.get(tuple(command), CompletedProcess(command, 0, stdout="ok", stderr=""))

        def fake_launcher(command):
            calls.append(tuple(command))
            return object()

        client = NordVPNClient(
            executable="C:/Program Files/NordVPN/NordVPN.exe",
            backend="windows",
            launcher=fake_launcher,
            runner=fake_runner,
            sleeper=lambda _: None,
            rng=random.Random(1),
        )

        result = client.change(restore_wireguard=True, wireguard_fwmark=51820)

        self.assertNotIn("routing restored", result.message)
        self.assertNotIn(("ip", "rule", "show"), calls)


if __name__ == "__main__":
    unittest.main()
