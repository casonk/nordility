import random
import sys
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

from nordility.client import (
    FAST_GROUPS,
    CommandExecutionError,
    ConfigurationError,
    NordVPNClient,
    _discover_wireguard_interfaces,
    _get_wireguard_peer_endpoints,
    _ip_rule_has_fwmark,
    _is_not_logged_in,
    _nordvpn_connection_signature,
    _refresh_wireguard_peers,
    _restore_wireguard_routing,
    resolve_backend,
    resolve_executable,
    restore_wireguard_after_nordvpn,
    watch_nordvpn_wireguard,
)

OWNED_RULE = "100:\tfrom all fwmark 0xca6c lookup main proto 196\n"
ADD_RULE_COMMAND = (
    "ip",
    "rule",
    "add",
    "fwmark",
    "51820",
    "lookup",
    "main",
    "priority",
    "100",
    "protocol",
    "196",
)
DELETE_RULE_COMMAND = (
    "ip",
    "rule",
    "del",
    "fwmark",
    "51820",
    "lookup",
    "main",
    "priority",
    "100",
    "protocol",
    "196",
)


def routing_rule_response(command, state: dict[str, str]) -> CompletedProcess | None:
    """Model a complete WG-mark inventory and one owned policy-rule priority."""
    key = tuple(command)
    if key == ("wg", "show", "all", "fwmark"):
        return CompletedProcess(
            command,
            0,
            stdout=state.get("fwmarks", "wg0\toff\n"),
            stderr="",
        )
    if key == ("ip", "rule", "show"):
        return CompletedProcess(command, 0, stdout=state["rules"], stderr="")
    add_command = ADD_RULE_COMMAND
    if key in {add_command, ("sudo", "-n") + add_command}:
        state["rules"] += OWNED_RULE
        return CompletedProcess(command, 0, stdout="", stderr="")
    delete_command = DELETE_RULE_COMMAND
    if key in {delete_command, ("sudo", "-n") + delete_command}:
        state["rules"] = "".join(
            line for line in state["rules"].splitlines(keepends=True) if line != OWNED_RULE
        )
        return CompletedProcess(command, 0, stdout="", stderr="")
    return None


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

    def test_login_passes_token_only_over_helper_stdin(self) -> None:
        recorded = {}
        token = "test-token-abc123-secure"

        def fake_runner(command, input, capture_output, text, check):
            recorded["command"] = command
            recorded["input"] = input
            return CompletedProcess(
                command,
                0,
                stdout=f"Welcome with {token}",
                stderr=f"diagnostic {token}",
            )

        client = NordVPNClient(
            executable="nordvpn",
            backend="cli",
            runner=fake_runner,
            sleeper=lambda _: None,
        )

        with self.assertLogs("nordility", level="INFO") as captured:
            result = client.login(token=token)

        self.assertEqual(
            recorded["command"],
            (sys.executable, "-m", "nordility.token_login", "nordvpn"),
        )
        self.assertEqual(recorded["input"], f"{token}\n")
        self.assertNotIn(token, " ".join(recorded["command"]))
        self.assertEqual(result.message, "NordVPN Logged In")
        self.assertEqual(result.command, recorded["command"])
        self.assertNotIn(token, "\n".join(captured.output))
        self.assertNotIn(token, result.stdout)
        self.assertNotIn(token, result.stderr)

    def test_login_failure_redacts_token_from_exception(self) -> None:
        token = "failure-token-abc123-secure"

        def fake_runner(command, input, capture_output, text, check):
            return CompletedProcess(command, 1, stdout="", stderr=f"rejected {token}")

        client = NordVPNClient(
            executable="nordvpn",
            backend="cli",
            runner=fake_runner,
            sleeper=lambda _: None,
        )

        with self.assertRaises(CommandExecutionError) as captured:
            client.login(token=token)

        self.assertNotIn(token, str(captured.exception))
        self.assertIn("<redacted>", str(captured.exception))

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

        def fake_runner(command, capture_output, text, check, input=None):
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

        token = "keepass-token-abc123-secure"
        with mock.patch("nordility.client._resolve_keepass_token", return_value=token):
            result = client.connect(
                auto_login=True,
                keepass_entry="vpn/provider#access-token",
            )

        self.assertEqual(calls[0], ("nordvpn", "connect"))
        self.assertEqual(calls[1], (sys.executable, "-m", "nordility.token_login", "nordvpn"))
        self.assertNotIn(token, " ".join(calls[1]))
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
        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp)
            (config_dir / "wg0.conf").write_text("[Interface]\n", encoding="utf-8")
            refreshed = _refresh_wireguard_peers(
                runner,
                interfaces,
                config_dir=config_dir,
            )

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
        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp)
            (config_dir / "wg0.conf").write_text("[Interface]\n", encoding="utf-8")
            refreshed = _refresh_wireguard_peers(
                runner,
                interfaces,
                config_dir=config_dir,
            )

        self.assertEqual(refreshed, ["wg0"])
        self.assertIn(
            ("wg", "set", "wg0", "peer", "PUBKEY", "endpoint", "203.0.113.1:51820"),
            real_calls,
        )

    def test_refresh_peers_refuses_daemon_managed_nordlynx_at_mutation_boundary(self) -> None:
        calls: list[tuple] = []

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            if tuple(command) == ("wg", "show", "nordlynx", "endpoints"):
                return CompletedProcess(
                    command,
                    0,
                    stdout="NORD\t198.51.100.1:51820\n",
                    stderr="",
                )
            return CompletedProcess(command, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp)
            (config_dir / "nordlynx.conf").write_text("[Interface]\n", encoding="utf-8")
            refreshed = _refresh_wireguard_peers(
                runner,
                ["nordlynx"],
                config_dir=config_dir,
            )

        self.assertEqual(refreshed, [])
        self.assertNotIn(("wg", "show", "nordlynx", "endpoints"), calls)

    def test_change_with_restore_wireguard_refreshes_peers(self) -> None:
        rule_state = {"rules": ""}
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
            routing_response = routing_rule_response(command, rule_state)
            if routing_response is not None:
                return routing_response
            return CompletedProcess(command, 0, stdout="ok", stderr="")

        client = NordVPNClient(
            executable="nordvpn",
            backend="cli",
            runner=fake_runner,
            sleeper=lambda _: None,
            rng=random.Random(1),
        )

        with mock.patch("nordility.client.Path") as mock_path:
            mock_path.return_value.exists.return_value = True
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
        rule_state = {"rules": "32766:\tfrom all lookup main\n"}

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            routing_response = routing_rule_response(command, rule_state)
            if routing_response is not None:
                return routing_response
            return CompletedProcess(command, 0, stdout="", stderr="")

        restored = _restore_wireguard_routing(runner, ["wg0"], fwmark=51820)

        self.assertEqual(restored, ["wg0"])
        self.assertIn(("wg", "set", "wg0", "fwmark", "51820"), calls)
        self.assertIn(ADD_RULE_COMMAND, calls)

    def test_skips_ip_rule_add_when_already_present(self) -> None:
        calls: list[tuple] = []

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            if tuple(command) == ("wg", "show", "all", "fwmark"):
                return CompletedProcess(command, 0, stdout="wg0\t0xca6c\n", stderr="")
            if tuple(command) == ("ip", "rule", "show"):
                return CompletedProcess(command, 0, stdout=OWNED_RULE, stderr="")
            return CompletedProcess(command, 0, stdout="", stderr="")

        _restore_wireguard_routing(runner, ["wg0"], fwmark=51820)

        self.assertNotIn(ADD_RULE_COMMAND, calls)

    def test_ip_rule_match_requires_exact_priority_mark_mask_and_main_table(self) -> None:
        misleading_rules = """\
99: from all fwmark 0xca6c lookup main
100: from all fwmark 0xca6c0 lookup main
100: from all fwmark 0xca6c/0xffff lookup main
100: from all fwmark 0xca6c lookup 51820
100: not from all fwmark 0xca6c lookup main
100: from 192.0.2.0/24 fwmark 0xca6c lookup main
100: from all to 198.51.100.0/24 fwmark 0xca6c lookup main
100: from all fwmark 0xca6c lookup main suppress_prefixlength 0
"""
        runner = self._make_runner(
            {("ip", "rule", "show"): CompletedProcess([], 0, stdout=misleading_rules, stderr="")}
        )

        self.assertFalse(_ip_rule_has_fwmark(runner, fwmark=51820, ip_rule_priority=100))

    def test_ip_rule_match_accepts_decimal_mark_with_full_mask_and_table_alias(self) -> None:
        runner = self._make_runner(
            {
                ("ip", "rule", "show"): CompletedProcess(
                    [],
                    0,
                    stdout="100: from all fwmark 51820/0xffffffff table main proto 196\n",
                    stderr="",
                )
            }
        )

        self.assertTrue(_ip_rule_has_fwmark(runner, fwmark=51820, ip_rule_priority=100))

    def test_ip_rule_match_rejects_foreign_protocol_tag(self) -> None:
        runner = self._make_runner(
            {
                ("ip", "rule", "show"): CompletedProcess(
                    [],
                    0,
                    stdout="100: from all fwmark 0xca6c lookup main proto static\n",
                    stderr="",
                )
            }
        )

        self.assertFalse(_ip_rule_has_fwmark(runner, fwmark=51820, ip_rule_priority=100))

    def test_wrong_priority_rule_does_not_skip_exact_rule_add(self) -> None:
        calls: list[tuple] = []
        rule_state = {"rules": "101: from all fwmark 0xca6c lookup main\n"}

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            routing_response = routing_rule_response(command, rule_state)
            if routing_response is not None:
                return routing_response
            return CompletedProcess(command, 0, stdout="", stderr="")

        restored = _restore_wireguard_routing(
            runner,
            ["wg0"],
            fwmark=51820,
            ip_rule_priority=100,
        )

        self.assertEqual(restored, ["wg0"])
        self.assertIn(ADD_RULE_COMMAND, calls)

    def test_same_priority_conflict_fails_before_wireguard_mutation(self) -> None:
        calls: list[tuple] = []

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            if tuple(command) == ("wg", "show", "all", "fwmark"):
                return CompletedProcess(command, 0, stdout="wg0\toff\n", stderr="")
            if tuple(command) == ("ip", "rule", "show"):
                return CompletedProcess(
                    command,
                    0,
                    stdout="100:\tfrom all lookup main\n",
                    stderr="",
                )
            return CompletedProcess(command, 0, stdout="", stderr="")

        restored = _restore_wireguard_routing(runner, ["wg0"], fwmark=51820)

        self.assertEqual(restored, [])
        self.assertNotIn(("wg", "set", "wg0", "fwmark", "51820"), calls)
        self.assertFalse(any(call[:3] == ("ip", "rule", "add") for call in calls))

    def test_non_authorized_fwmark_collision_fails_before_global_rule_mutation(self) -> None:
        calls: list[tuple] = []
        rule_state = {
            "rules": "",
            "fwmarks": "wg0\toff\nwgcorp\t0xca6c\nnordlynx\t0xe1f1\n",
        }

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            response = routing_rule_response(command, rule_state)
            if response is not None:
                return response
            return CompletedProcess(command, 0, stdout="", stderr="")

        restored = _restore_wireguard_routing(runner, ["wg0"], fwmark=51820)

        self.assertEqual(restored, [])
        self.assertFalse(any(call[:3] == ("ip", "rule", "add") for call in calls))
        self.assertNotIn(("wg", "set", "wg0", "fwmark", "51820"), calls)

    def test_new_rule_is_rolled_back_when_all_target_mutations_fail(self) -> None:
        calls: list[tuple] = []
        rule_state = {"rules": "", "fwmarks": "wg0\toff\n"}

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            response = routing_rule_response(command, rule_state)
            if response is not None:
                return response
            if "wg" in command and "set" in command:
                return CompletedProcess(command, 1, stdout="", stderr="denied")
            return CompletedProcess(command, 0, stdout="", stderr="")

        restored = _restore_wireguard_routing(runner, ["wg0"], fwmark=51820)

        self.assertEqual(restored, [])
        self.assertEqual(rule_state["rules"], "")
        self.assertIn(DELETE_RULE_COMMAND, calls)

    def test_racing_fwmark_collision_rolls_back_new_rule(self) -> None:
        calls: list[tuple] = []
        rule_state = {"rules": "", "fwmarks": "wg0\toff\n"}
        inventory_reads = 0

        def runner(command, capture_output, text, check):
            nonlocal inventory_reads
            calls.append(tuple(command))
            if tuple(command) == ("wg", "show", "all", "fwmark"):
                inventory_reads += 1
                stdout = "wg0\toff\n" if inventory_reads == 1 else "wg0\toff\nwgcorp\t0xca6c\n"
                return CompletedProcess(command, 0, stdout=stdout, stderr="")
            response = routing_rule_response(command, rule_state)
            if response is not None:
                return response
            return CompletedProcess(command, 0, stdout="", stderr="")

        restored = _restore_wireguard_routing(runner, ["wg0"], fwmark=51820)

        self.assertEqual(restored, [])
        self.assertEqual(rule_state["rules"], "")
        self.assertNotIn(("wg", "set", "wg0", "fwmark", "51820"), calls)

    def test_unverified_rule_add_fails_before_wireguard_mutation(self) -> None:
        calls: list[tuple] = []

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            if tuple(command) == ("wg", "show", "all", "fwmark"):
                return CompletedProcess(command, 0, stdout="wg0\toff\n", stderr="")
            return CompletedProcess(command, 0, stdout="", stderr="")

        restored = _restore_wireguard_routing(runner, ["wg0"], fwmark=51820)

        self.assertEqual(restored, [])
        self.assertNotIn(("wg", "set", "wg0", "fwmark", "51820"), calls)

    def test_retries_fwmark_with_sudo_on_permission_failure(self) -> None:
        calls: list[tuple] = []
        rule_state = {"rules": ""}
        responses = {
            ("wg", "set", "wg0", "fwmark", "51820"): CompletedProcess(
                [], 1, stdout="", stderr="Operation not permitted"
            ),
            ("sudo", "-n", "wg", "set", "wg0", "fwmark", "51820"): CompletedProcess(
                [], 0, stdout="", stderr=""
            ),
        }

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            routing_response = routing_rule_response(command, rule_state)
            if routing_response is not None:
                return routing_response
            return responses.get(tuple(command), CompletedProcess(command, 0, stdout="", stderr=""))

        restored = _restore_wireguard_routing(runner, ["wg0"], fwmark=51820)

        self.assertEqual(restored, ["wg0"])
        self.assertIn(("sudo", "-n", "wg", "set", "wg0", "fwmark", "51820"), calls)

    def test_retries_ip_rule_add_with_sudo_on_permission_failure(self) -> None:
        calls: list[tuple] = []
        rule_state = {"rules": ""}
        add_command = ADD_RULE_COMMAND

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            key = tuple(command)
            if key == ("wg", "show", "all", "fwmark"):
                return CompletedProcess(command, 0, stdout="wg0\toff\n", stderr="")
            if key == ("ip", "rule", "show"):
                return CompletedProcess(command, 0, stdout=rule_state["rules"], stderr="")
            if key == add_command:
                return CompletedProcess(command, 1, stdout="", stderr="Operation not permitted")
            if key == ("sudo", "-n") + add_command:
                rule_state["rules"] = OWNED_RULE
                return CompletedProcess(command, 0, stdout="", stderr="")
            return CompletedProcess(command, 0, stdout="", stderr="")

        restored = _restore_wireguard_routing(runner, ["wg0"], fwmark=51820)

        self.assertEqual(restored, ["wg0"])
        self.assertIn(
            (
                "sudo",
                "-n",
                "ip",
                "rule",
                "add",
                "fwmark",
                "51820",
                "lookup",
                "main",
                "priority",
                "100",
                "protocol",
                "196",
            ),
            calls,
        )

    def test_returns_empty_when_fwmark_set_fails(self) -> None:
        def runner(command, capture_output, text, check):
            if tuple(command) == ("wg", "show", "all", "fwmark"):
                return CompletedProcess(command, 0, stdout="wg0\toff\n", stderr="")
            if tuple(command) == ("ip", "rule", "show"):
                return CompletedProcess(command, 0, stdout=OWNED_RULE, stderr="")
            if "fwmark" in command and "wg" in command:
                return CompletedProcess(command, 1, stdout="", stderr="error")
            return CompletedProcess(command, 0, stdout="", stderr="")

        restored = _restore_wireguard_routing(runner, ["wg0"], fwmark=51820)

        self.assertEqual(restored, [])

    def test_returns_empty_when_exact_ip_rule_cannot_be_added(self) -> None:
        add_command = ADD_RULE_COMMAND

        def runner(command, capture_output, text, check):
            key = tuple(command)
            if key == ("wg", "show", "all", "fwmark"):
                return CompletedProcess(command, 0, stdout="wg0\toff\n", stderr="")
            if key == ("ip", "rule", "show"):
                return CompletedProcess(command, 0, stdout="", stderr="")
            if key in {add_command, ("sudo", "-n") + add_command}:
                return CompletedProcess(command, 1, stdout="", stderr="permission denied")
            return CompletedProcess(command, 0, stdout="", stderr="")

        restored = _restore_wireguard_routing(runner, ["wg0"], fwmark=51820)

        self.assertEqual(restored, [])

    def test_change_cli_restores_routing_with_restore_wireguard(self) -> None:
        calls: list[tuple] = []
        rule_state = {"rules": ""}
        wg_responses = {
            ("wg", "show", "interfaces"): CompletedProcess([], 0, stdout="wg0\n", stderr=""),
            ("wg", "show", "wg0", "endpoints"): CompletedProcess(
                [], 0, stdout="PUBKEY\t10.0.0.1:51820\n", stderr=""
            ),
            ("ip", "rule", "show"): CompletedProcess([], 0, stdout="", stderr=""),
        }

        def fake_runner(command, capture_output, text, check):
            calls.append(tuple(command))
            routing_response = routing_rule_response(command, rule_state)
            if routing_response is not None:
                return routing_response
            return wg_responses.get(
                tuple(command), CompletedProcess(command, 0, stdout="ok", stderr="")
            )

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
        rule_state = {"rules": ""}
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
            routing_response = routing_rule_response(command, rule_state)
            if routing_response is not None:
                return routing_response
            return wg_responses.get(
                tuple(command), CompletedProcess(command, 0, stdout="ok", stderr="")
            )

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
            return wg_responses.get(
                tuple(command), CompletedProcess(command, 0, stdout="ok", stderr="")
            )

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

        self.assertIn("WireGuard refreshed on wg0", result.message)
        self.assertIn(("wg", "set", "wg0", "peer", "PUBKEY", "endpoint", "10.0.0.1:51820"), calls)
        self.assertNotIn("routing restored", result.message)
        self.assertNotIn(("ip", "rule", "show"), calls)


class WireGuardWatchTests(unittest.TestCase):
    def test_nordvpn_signature_ignores_dynamic_status_lines(self) -> None:
        status_outputs = iter(
            [
                "Status: Connected\nHostname: us1.nordvpn.com\nUptime: 1 second\nTransfer: 1 KiB\n",
                "Status: Connected\nHostname: us1.nordvpn.com\nUptime: 2 seconds\nTransfer: 2 KiB\n",
            ]
        )

        def runner(command, capture_output, text, check):
            key = tuple(command)
            if key == ("nordvpn", "status"):
                return CompletedProcess(command, 0, stdout=next(status_outputs), stderr="")
            if key == ("wg", "show", "nordlynx", "endpoints"):
                return CompletedProcess(command, 0, stdout="NORD\t198.51.100.1:51820\n", stderr="")
            if key == ("wg", "show", "nordlynx", "fwmark"):
                return CompletedProcess(command, 0, stdout="0xe1f1\n", stderr="")
            return CompletedProcess(command, 0, stdout="", stderr="")

        self.assertEqual(
            _nordvpn_connection_signature(runner),
            _nordvpn_connection_signature(runner),
        )

    def test_restore_filters_refresh_and_routing_to_user_managed_interfaces(self) -> None:
        calls: list[tuple] = []
        rule_state = {"rules": ""}

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            key = tuple(command)
            if key == ("wg", "show", "interfaces"):
                return CompletedProcess(command, 0, stdout="wg0 wgcorp nordlynx\n", stderr="")
            if key == ("wg", "show", "wg0", "endpoints"):
                return CompletedProcess(command, 0, stdout="WG0\t10.99.0.2:51820\n", stderr="")
            if key == ("wg", "show", "wgcorp", "endpoints"):
                return CompletedProcess(command, 0, stdout="CORP\t10.88.0.2:51820\n", stderr="")
            if key == ("wg", "show", "nordlynx", "endpoints"):
                return CompletedProcess(command, 0, stdout="NORD\t198.51.100.1:51820\n", stderr="")
            routing_response = routing_rule_response(command, rule_state)
            if routing_response is not None:
                return routing_response
            return CompletedProcess(command, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp)
            (config_dir / "wg0.conf").write_text("[Interface]\n", encoding="utf-8")
            (config_dir / "wgcorp.conf").write_text("[Interface]\n", encoding="utf-8")
            # A confusing local filename must never make Nord's daemon-owned
            # interface eligible for endpoint or fwmark mutation.
            (config_dir / "nordlynx.conf").write_text("[Interface]\n", encoding="utf-8")

            summary = restore_wireguard_after_nordvpn(
                runner,
                backend="cli",
                wireguard_config_dir=config_dir,
            )

        self.assertEqual(summary.refreshed, ("wg0",))
        self.assertEqual(summary.routing_candidates, ("wg0",))
        self.assertEqual(summary.routing_restored, ("wg0",))
        self.assertNotIn(("wg", "show", "nordlynx", "endpoints"), calls)
        self.assertNotIn(("wg", "show", "wgcorp", "endpoints"), calls)
        self.assertFalse(any(call[:4] == ("wg", "set", "nordlynx", "peer") for call in calls))
        self.assertIn(("wg", "set", "wg0", "fwmark", "51820"), calls)
        self.assertNotIn(("wg", "set", "nordlynx", "fwmark", "51820"), calls)
        self.assertNotIn(("wg", "set", "wgcorp", "fwmark", "51820"), calls)

    def test_watch_starts_configured_wireguard_interface_when_down(self) -> None:
        calls: list[tuple] = []
        active_interfaces = ""
        rule_state = {"rules": ""}

        def runner(command, capture_output, text, check):
            nonlocal active_interfaces
            calls.append(tuple(command))
            key = tuple(command)
            if key == ("wg", "show", "interfaces"):
                return CompletedProcess(command, 0, stdout=active_interfaces, stderr="")
            if key == ("systemctl", "start", "wg-quick@wg0.service"):
                active_interfaces = "wg0\n"
                return CompletedProcess(command, 0, stdout="", stderr="")
            if key == ("wg", "show", "wg0", "endpoints"):
                return CompletedProcess(command, 0, stdout="WG0\t10.99.0.2:51820\n", stderr="")
            routing_response = routing_rule_response(command, rule_state)
            if routing_response is not None:
                return routing_response
            return CompletedProcess(command, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp)
            (config_dir / "wg0.conf").write_text("[Interface]\n", encoding="utf-8")

            events = watch_nordvpn_wireguard(
                runner=runner,
                sleeper=lambda _: None,
                wireguard_config_dir=config_dir,
                once=True,
            )

        self.assertEqual(events[0].started, ("wg0",))
        self.assertIn(("systemctl", "start", "wg-quick@wg0.service"), calls)
        self.assertIn(("wg", "set", "wg0", "fwmark", "51820"), calls)

    def test_watch_never_starts_provider_managed_nordlynx(self) -> None:
        calls: list[tuple] = []

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            if tuple(command) == ("wg", "show", "interfaces"):
                return CompletedProcess(command, 0, stdout="", stderr="")
            return CompletedProcess(command, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp)
            (config_dir / "nordlynx.conf").write_text("[Interface]\n", encoding="utf-8")

            summary = restore_wireguard_after_nordvpn(
                runner,
                backend="cli",
                wireguard_config_dir=config_dir,
                ensure_interfaces=("nordlynx",),
            )

        self.assertEqual(summary.started, ())
        self.assertFalse(any("wg-quick@nordlynx" in part for call in calls for part in call))
        self.assertNotIn(("wg-quick", "up", "nordlynx"), calls)

    def test_watch_rejects_provider_managed_interface_before_polling(self) -> None:
        runner = mock.Mock()

        with self.assertRaisesRegex(ConfigurationError, "provider-managed"):
            watch_nordvpn_wireguard(
                runner=runner,
                sleeper=lambda _: None,
                ensure_interfaces=("nordlynx",),
                max_iterations=1,
            )

        runner.assert_not_called()

    def test_watch_retries_start_when_configured_interface_stays_down(self) -> None:
        calls: list[tuple] = []

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            key = tuple(command)
            if key == ("nordvpn", "status"):
                return CompletedProcess(command, 0, stdout="Status: Disconnected\n", stderr="")
            if key == ("wg", "show", "interfaces"):
                return CompletedProcess(command, 0, stdout="", stderr="")
            if key == ("wg", "show", "nordlynx", "endpoints"):
                return CompletedProcess(command, 0, stdout="", stderr="")
            if key == ("wg", "show", "nordlynx", "fwmark"):
                return CompletedProcess(command, 0, stdout="", stderr="")
            if key == ("systemctl", "start", "wg-quick@wg0.service"):
                return CompletedProcess(command, 1, stdout="", stderr="failed")
            if key == ("sudo", "-n", "systemctl", "start", "wg-quick@wg0.service"):
                return CompletedProcess(command, 1, stdout="", stderr="failed")
            if key == ("wg-quick", "up", "wg0"):
                return CompletedProcess(command, 1, stdout="", stderr="failed")
            if key == ("sudo", "-n", "wg-quick", "up", "wg0"):
                return CompletedProcess(command, 1, stdout="", stderr="failed")
            return CompletedProcess(command, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp)
            (config_dir / "wg0.conf").write_text("[Interface]\n", encoding="utf-8")

            events = watch_nordvpn_wireguard(
                runner=runner,
                sleeper=lambda _: None,
                interval_seconds=1,
                stabilize_seconds=0,
                wireguard_config_dir=config_dir,
                max_iterations=1,
            )

        self.assertEqual(len(events), 2)
        self.assertEqual(calls.count(("systemctl", "start", "wg-quick@wg0.service")), 2)
        self.assertNotIn(("wg-quick", "up", "wg0"), calls)
        self.assertNotIn(("sudo", "-n", "wg-quick", "up", "wg0"), calls)

    def test_watch_reapplies_when_nordvpn_signature_changes(self) -> None:
        calls: list[tuple] = []
        rule_state = {"rules": ""}
        status_outputs = iter(
            [
                "Status: Connected\nHostname: old.nordvpn.com\n",
                "Status: Connected\nHostname: new.nordvpn.com\n",
                "Status: Connected\nHostname: new.nordvpn.com\n",
            ]
        )

        def runner(command, capture_output, text, check):
            calls.append(tuple(command))
            key = tuple(command)
            if key == ("nordvpn", "status"):
                return CompletedProcess(command, 0, stdout=next(status_outputs), stderr="")
            if key == ("wg", "show", "interfaces"):
                return CompletedProcess(command, 0, stdout="wg0\n", stderr="")
            if key == ("wg", "show", "wg0", "endpoints"):
                return CompletedProcess(command, 0, stdout="WG0\t10.99.0.2:51820\n", stderr="")
            if key == ("wg", "show", "nordlynx", "endpoints"):
                return CompletedProcess(command, 0, stdout="NORD\t198.51.100.1:51820\n", stderr="")
            if key == ("wg", "show", "nordlynx", "fwmark"):
                return CompletedProcess(command, 0, stdout="0xe1f1\n", stderr="")
            routing_response = routing_rule_response(command, rule_state)
            if routing_response is not None:
                return routing_response
            return CompletedProcess(command, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp)
            (config_dir / "wg0.conf").write_text("[Interface]\n", encoding="utf-8")

            events = watch_nordvpn_wireguard(
                runner=runner,
                sleeper=lambda _: None,
                interval_seconds=1,
                stabilize_seconds=0,
                wireguard_config_dir=config_dir,
                max_iterations=1,
            )

        self.assertEqual(len(events), 2)
        self.assertEqual(calls.count(("wg", "set", "wg0", "fwmark", "51820")), 2)


if __name__ == "__main__":
    unittest.main()
