import http.client
import json
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock
from unittest.mock import patch

from nordility.client import CommandResult, ConfigurationError, WireGuardRestoreSummary
from nordility.web import (
    ActionOutcome,
    NordilityWebController,
    ThreadingHTTPServer,
    _validate_trusted_origin,
    make_handler,
)


class NordilityWebControllerTests(unittest.TestCase):
    def test_status_reports_groups_and_command_output(self) -> None:
        def runner(command, capture_output, text, check):
            if tuple(command) == ("nordvpn", "status"):
                return CompletedProcess(
                    command,
                    0,
                    stdout="Status: Connected\nHostname: us1.nordvpn.com\nCountry: United States\n",
                    stderr="",
                )
            return CompletedProcess(command, 0, stdout="", stderr="")

        controller = NordilityWebController(executable="nordvpn", backend="cli", runner=runner)

        status = controller.status()

        self.assertIn("United_States", status["groups"]["fast"])
        self.assertIn("Status: Connected", status["nordvpn_status"])

    def test_rejects_unknown_group(self) -> None:
        controller = NordilityWebController(executable="nordvpn", backend="cli")

        with self.assertRaises(ConfigurationError):
            controller.perform_action({"action": "connect", "group": "bad;group"})

    def test_connect_uses_auto_login_defaults(self) -> None:
        captured: dict[str, object] = {}

        def runner(command, capture_output, text, check):
            return CompletedProcess(command, 0, stdout="", stderr="")

        controller = NordilityWebController(
            executable="nordvpn",
            backend="cli",
            runner=runner,
            auto_login=True,
            keepass_entry="vpn/token",
            keepass_profile="mock-profile",
        )

        def connect(**kwargs):
            captured.update(kwargs)
            return CommandResult(command=("nordvpn", "connect"), message="VPN Connected")

        controller.client.connect = connect  # type: ignore[method-assign]

        controller.perform_action({"action": "connect"})

        self.assertTrue(captured["auto_login"])
        self.assertEqual(captured["keepass_entry"], "vpn/token")
        self.assertEqual(captured["keepass_profile"], "mock-profile")

    def test_disconnect_starts_wireguard_and_repairs_routing(self) -> None:
        calls: list[tuple] = []
        active_interfaces = ""
        routing_rule = ""

        def runner(command, capture_output, text, check):
            nonlocal active_interfaces, routing_rule
            calls.append(tuple(command))
            key = tuple(command)
            if key == ("nordvpn", "disconnect"):
                return CompletedProcess(command, 0, stdout="Disconnected", stderr="")
            if key == ("wg", "show", "interfaces"):
                return CompletedProcess(command, 0, stdout=active_interfaces, stderr="")
            if key == ("systemctl", "start", "wg-quick@wg0.service"):
                active_interfaces = "wg0\n"
                return CompletedProcess(command, 0, stdout="", stderr="")
            if key == ("wg", "show", "wg0", "endpoints"):
                return CompletedProcess(command, 0, stdout="WG0\t10.99.0.2:51820\n", stderr="")
            if key == ("wg", "show", "all", "fwmark"):
                return CompletedProcess(command, 0, stdout="wg0\toff\n", stderr="")
            if key == ("ip", "rule", "show"):
                return CompletedProcess(command, 0, stdout=routing_rule, stderr="")
            if key == (
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
            ):
                routing_rule = "100: from all fwmark 0xca6c lookup main proto 196\n"
                return CompletedProcess(command, 0, stdout="", stderr="")
            return CompletedProcess(command, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            config_dir = Path(tmp)
            (config_dir / "wg0.conf").write_text("[Interface]\n", encoding="utf-8")
            controller = NordilityWebController(
                executable="nordvpn",
                backend="cli",
                runner=runner,
                wireguard_config_dir=config_dir,
            )

            outcome = controller.perform_action({"action": "disconnect"})

        self.assertEqual(outcome.result.message, "VPN Disconnected")
        self.assertEqual(outcome.repair.started, ("wg0",))
        self.assertIn(("systemctl", "start", "wg-quick@wg0.service"), calls)
        self.assertIn(("wg", "set", "wg0", "fwmark", "51820"), calls)

    def test_status_payload_is_json_serializable(self) -> None:
        controller = NordilityWebController(
            executable="nordvpn",
            backend="cli",
            runner=lambda command, capture_output, text, check: CompletedProcess(
                command, 0, stdout="", stderr=""
            ),
        )

        json.dumps(controller.status())

    def _make_disconnected_controller(self):
        def runner(command, capture_output, text, check):
            if tuple(command) == ("nordvpn", "status"):
                return CompletedProcess(command, 0, stdout="Status: Disconnected", stderr="")
            return CompletedProcess(command, 0, stdout="", stderr="")

        return NordilityWebController(executable="nordvpn", backend="cli", runner=runner)

    def test_disconnected_status_includes_public_ip(self) -> None:
        controller = self._make_disconnected_controller()
        payload = json.dumps({"ip": "1.2.3.4", "country": "US"}).encode()

        with patch("urllib.request.urlopen") as mock_open:
            mock_open.return_value.__enter__ = lambda s: s
            mock_open.return_value.__exit__ = lambda s, *a: False
            mock_open.return_value.read = lambda: payload

            status = controller.status()

        self.assertEqual(status["public_ip"], "1.2.3.4")
        self.assertEqual(status["public_country"], "US")

    def test_disconnected_status_omits_public_fields_on_lookup_failure(self) -> None:
        controller = self._make_disconnected_controller()

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
            status = controller.status()

        self.assertNotIn("public_ip", status)
        self.assertNotIn("public_country", status)

    def test_connected_status_does_not_call_public_ip_lookup(self) -> None:
        def runner(command, capture_output, text, check):
            if tuple(command) == ("nordvpn", "status"):
                return CompletedProcess(
                    command,
                    0,
                    stdout="Status: Connected\nIP: 5.6.7.8\nCountry: United States\n",
                    stderr="",
                )
            return CompletedProcess(command, 0, stdout="", stderr="")

        controller = NordilityWebController(executable="nordvpn", backend="cli", runner=runner)

        with patch("urllib.request.urlopen") as mock_open:
            status = controller.status()
            mock_open.assert_not_called()

        self.assertNotIn("public_ip", status)

    def test_public_info_is_cached_within_ttl(self) -> None:
        controller = self._make_disconnected_controller()
        payload = json.dumps({"ip": "1.2.3.4", "country": "US"}).encode()
        call_count = 0

        def fake_urlopen(req, timeout):
            nonlocal call_count
            call_count += 1

            class FakeResp:
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

                def read(self):
                    return payload

            return FakeResp()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            controller.status()
            controller.status()

        self.assertEqual(call_count, 1)


class NordilityWebTransportTests(unittest.TestCase):
    def request(
        self,
        handler,
        *,
        headers: dict[str, str],
    ) -> tuple[int, bytes]:
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            connection.request(
                "POST",
                "/api/action",
                body=b'{"action":"disconnect"}',
                headers=headers,
            )
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_tcp_handler_never_allows_mutations(self) -> None:
        controller = mock.Mock()
        handler = make_handler(controller)

        status, body = self.request(
            handler,
            headers={
                "Content-Type": "application/json",
                "Origin": "https://nordility.clockwork.internal",
                "Host": "nordility.clockwork.internal",
            },
        )

        self.assertEqual(status, 403)
        self.assertIn(b"protected Unix-socket transport", body)
        controller.perform_action.assert_not_called()

    def test_protected_handler_requires_exact_origin_host_and_json(self) -> None:
        origin = "https://nordility.clockwork.internal"
        controller = mock.Mock()
        controller.perform_action.return_value = ActionOutcome(
            result=CommandResult(command=("nordvpn", "disconnect"), message="VPN Disconnected"),
            repair=WireGuardRestoreSummary(),
        )
        controller.status.return_value = {"groups": {"fast": [], "full": []}}
        handler = make_handler(controller, actions_enabled=True, trusted_origin=origin)

        wrong_status, _ = self.request(
            handler,
            headers={
                "Content-Type": "application/json",
                "Origin": "https://attacker.invalid",
                "Host": "nordility.clockwork.internal",
            },
        )
        self.assertEqual(wrong_status, 403)

        ok_status, _ = self.request(
            handler,
            headers={
                "Content-Type": "application/json",
                "Origin": origin,
                "Host": "nordility.clockwork.internal",
            },
        )
        self.assertEqual(ok_status, 200)
        controller.perform_action.assert_called_once_with({"action": "disconnect"})

    def test_trusted_origin_must_be_one_https_origin(self) -> None:
        self.assertEqual(
            _validate_trusted_origin("https://nordility.clockwork.internal/"),
            "https://nordility.clockwork.internal",
        )
        for invalid in (
            "http://nordility.clockwork.internal",
            "https://nordility.clockwork.internal/path",
            "https://user@nordility.clockwork.internal",
        ):
            with self.subTest(origin=invalid), self.assertRaises(ConfigurationError):
                _validate_trusted_origin(invalid)


if __name__ == "__main__":
    unittest.main()
