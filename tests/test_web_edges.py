"""Controller actions, HTTP handler routing/headers, and server start-up checks.

Real loopback HTTP is used for the handler; the NordVPN client, WireGuard
repair and public-IP lookup are stubbed. Unix sockets live in a private temp
directory.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import shutil
import socket
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

from nordility import web
from nordility.client import CommandResult, ConfigurationError, WireGuardRestoreSummary

ORIGIN = "https://nordility.clockwork.internal"
HOST = "nordility.clockwork.internal"


def _outcome(message: str = "done") -> web.ActionOutcome:
    return web.ActionOutcome(
        result=CommandResult(command=("nordvpn", "x"), message=message),
        repair=WireGuardRestoreSummary(),
    )


class ControllerActionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = web.NordilityWebController(
            executable="nordvpn",
            backend="cli",
            runner=lambda command, **_kw: CompletedProcess(command, 0, stdout="", stderr=""),
            auto_login=True,
            keepass_entry="entry/x",
            keepass_profile="profile-x",
            wireguard_interfaces=("wg-a",),
            wireguard_fwmark=7,
            ip_rule_priority=99,
        )
        self.repair = mock.patch.object(
            web, "restore_wireguard_after_nordvpn", return_value=WireGuardRestoreSummary()
        ).start()
        self.addCleanup(mock.patch.stopall)

    def test_rotate_passes_speed_group_and_login_settings(self) -> None:
        change = mock.Mock(return_value=CommandResult(command=("n",), message="rotated"))
        self.controller.client.change = change  # type: ignore[method-assign]
        outcome = self.controller.perform_action(
            {"action": " rotate ", "speed": " FAST ", "group": " United_States "}
        )
        self.assertEqual(outcome.result.message, "rotated")
        change.assert_called_once_with(
            speed="fast",
            group="United_States",
            auto_login=True,
            keepass_entry="entry/x",
            keepass_profile="profile-x",
        )

    def test_rotate_defaults_to_fast_and_rejects_unknown_speed(self) -> None:
        change = mock.Mock(return_value=CommandResult(command=("n",), message="ok"))
        self.controller.client.change = change  # type: ignore[method-assign]
        self.controller.perform_action({"action": "rotate"})
        self.assertEqual(change.call_args.kwargs["speed"], "fast")
        self.assertIsNone(change.call_args.kwargs["group"])

        change.reset_mock()
        with self.assertRaisesRegex(ConfigurationError, "Unsupported speed: warp"):
            self.controller.perform_action({"action": "rotate", "speed": "warp"})
        change.assert_not_called()

    def test_unknown_or_missing_action_is_rejected_before_any_side_effect(self) -> None:
        for payload in ({}, {"action": ""}, {"action": "format"}, {"action": None}):
            with self.subTest(payload=payload):
                with self.assertRaises(ConfigurationError):
                    self.controller.perform_action(payload)
        self.repair.assert_not_called()

    def test_rejected_group_never_reaches_the_client(self) -> None:
        connect = mock.Mock()
        self.controller.client.connect = connect  # type: ignore[method-assign]
        with self.assertRaisesRegex(ConfigurationError, "Unsupported group"):
            self.controller.perform_action({"action": "connect", "group": "Nope; rm"})
        connect.assert_not_called()

    def test_blank_or_missing_group_means_no_group(self) -> None:
        for raw in (None, "", "   "):
            with self.subTest(raw=raw):
                self.assertIsNone(self.controller._optional_group(raw))
        self.assertEqual(self.controller._optional_group(" Germany "), "Germany")

    def test_every_action_is_followed_by_the_wireguard_repair_with_settings(self) -> None:
        self.controller.client.disconnect = mock.Mock(  # type: ignore[method-assign]
            return_value=CommandResult(command=("n",), message="bye")
        )
        outcome = self.controller.perform_action({"action": "disconnect"})
        self.assertIs(outcome.repair, self.repair.return_value)
        kwargs = self.repair.call_args.kwargs
        self.assertEqual(kwargs["fwmark"], 7)
        self.assertEqual(kwargs["ip_rule_priority"], 99)
        self.assertEqual(kwargs["ensure_interfaces"], ("wg-a",))
        self.assertEqual(kwargs["backend"], self.controller.client.backend)

    def test_failed_action_skips_the_repair(self) -> None:
        self.controller.client.disconnect = mock.Mock(  # type: ignore[method-assign]
            side_effect=ConfigurationError("boom")
        )
        with self.assertRaises(ConfigurationError):
            self.controller.perform_action({"action": "disconnect"})
        self.repair.assert_not_called()

    def test_run_text_prefers_stdout_then_stderr_and_strips(self) -> None:
        def make(stdout, stderr):
            return web.NordilityWebController(
                executable="nordvpn",
                backend="cli",
                runner=lambda command, **_kw: CompletedProcess(
                    command, 0, stdout=stdout, stderr=stderr
                ),
            )

        self.assertEqual(make(" out \n", "err")._run_text(["x"]), "out")
        self.assertEqual(make("", " err \n")._run_text(["x"]), "err")
        self.assertEqual(make(None, None)._run_text(["x"]), "")

    def test_run_text_reports_a_missing_tool_instead_of_raising(self) -> None:
        def runner(command, **_kw):
            raise FileNotFoundError("no such file")

        controller = web.NordilityWebController(executable="nordvpn", backend="cli", runner=runner)
        self.assertIn("wg unavailable", controller._run_text(["wg", "show"]))
        status = controller.status()
        self.assertIn("(no output)", status["details"].replace("unavailable", "(no output)"))
        self.assertIn("unavailable", status["nordvpn_status"])

    def test_run_text_reports_any_os_error_instead_of_raising(self) -> None:
        def runner(command, **_kw):
            raise PermissionError("denied")

        controller = web.NordilityWebController(executable="nordvpn", backend="cli", runner=runner)
        self.assertEqual(controller._run_text(["ip", "rule"]), "ip unavailable: denied")

    def test_status_details_label_each_section(self) -> None:
        controller = web.NordilityWebController(
            executable="nordvpn",
            backend="cli",
            runner=lambda command, **_kw: CompletedProcess(command, 0, stdout="", stderr=""),
        )
        details = controller.status()["details"]
        for heading in (
            "NordVPN:\n(no output)",
            "WireGuard fwmarks:\n(no output)",
            "IP rules:\n(no output)",
        ):
            self.assertIn(heading, details)
        self.assertEqual(details.count("\n\n"), 2)

    def test_public_lookup_error_is_cached_so_a_dead_network_is_not_hammered(self) -> None:
        controller = web.NordilityWebController(
            executable="nordvpn",
            backend="cli",
            runner=lambda command, **_kw: CompletedProcess(
                command, 0, stdout="Status: Disconnected", stderr=""
            ),
        )
        with mock.patch("urllib.request.urlopen", side_effect=OSError("down")) as urlopen:
            first = controller.status()
            second = controller.status()
        self.assertNotIn("public_ip", first)
        self.assertNotIn("public_ip", second)
        self.assertEqual(urlopen.call_count, 1)


class HandlerTests(unittest.TestCase):
    controller: mock.Mock

    def setUp(self) -> None:
        self.controller = mock.Mock()
        self.controller.status.side_effect = lambda: {
            "groups": {"fast": ["A"]},
            "nordvpn_status": "x",
        }
        self.controller.perform_action.return_value = web.ActionOutcome(
            result=CommandResult(command=("nordvpn", "x"), message="all good"),
            repair=WireGuardRestoreSummary(interfaces=("wg0",), started=("wg0",)),
        )

    def call(self, method, path, *, body=None, headers=None, actions=False, origin=None):
        handler = web.make_handler(self.controller, actions_enabled=actions, trusted_origin=origin)
        server = web.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        thread.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response, response.read()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def post(self, body=b'{"action":"disconnect"}', headers=None):
        merged = {"Content-Type": "application/json", "Origin": ORIGIN}
        merged.update(headers or {})
        merged.setdefault("Content-Length", str(len(body)))
        return self.call(
            "POST", "/api/action", body=body, headers=merged, actions=True, origin=ORIGIN
        )

    def test_index_is_served_on_both_paths_with_hardening_headers(self) -> None:
        for path in ("/", "/index.html"):
            with self.subTest(path=path):
                response, body = self.call("GET", path)
                self.assertEqual(response.status, 200)
                self.assertEqual(body, web.INDEX_HTML.encode())
                self.assertEqual(response.getheader("Content-Type"), "text/html; charset=utf-8")
                self.assertEqual(response.getheader("Content-Length"), str(len(body)))
                self.assertEqual(response.getheader("Cache-Control"), "no-store")
                self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")
                self.assertEqual(response.getheader("X-Frame-Options"), "DENY")

    def test_csp_allows_only_self_or_the_trusted_origin_asset_path(self) -> None:
        response, _ = self.call("GET", "/")
        csp = response.getheader("Content-Security-Policy")
        self.assertIn("default-src 'none'", csp)
        self.assertIn("style-src 'unsafe-inline' 'self'", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("base-uri 'none'", csp)

        response, _ = self.call("GET", "/", actions=True, origin=ORIGIN)
        csp = response.getheader("Content-Security-Policy")
        self.assertIn(f"script-src 'unsafe-inline' {ORIGIN}{web.PORTFOLIO_PREFIX};", csp)
        self.assertNotIn("'self'; connect", csp.replace("connect-src 'self'", ""))

    def test_portfolio_assets_are_served_with_their_types(self) -> None:
        for path, (text, ctype) in web.PORTFOLIO_ASSETS.items():
            with self.subTest(path=path):
                response, body = self.call("GET", path)
                self.assertEqual(response.status, 200)
                self.assertEqual(body, text.encode())
                self.assertEqual(response.getheader("Content-Type"), ctype)

    def test_head_matches_get_headers_without_a_body(self) -> None:
        for path in ("/", "/index.html", "/api/status", *web.PORTFOLIO_ASSETS):
            with self.subTest(path=path):
                got, body = self.call("GET", path)
                head, head_body = self.call("HEAD", path)
                self.assertEqual(head.status, 200)
                self.assertEqual(head_body, b"")
                self.assertEqual(head.getheader("Content-Length"), str(len(body)))
                self.assertEqual(head.getheader("Content-Type"), got.getheader("Content-Type"))

    def test_status_endpoint_reports_the_transport_capability(self) -> None:
        response, body = self.call("GET", "/api/status")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Type"), "application/json; charset=utf-8")
        self.assertIs(json.loads(body)["actions_enabled"], False)
        self.assertEqual(json.loads(body)["groups"], {"fast": ["A"]})

        response, body = self.call("GET", "/api/status", actions=True, origin=ORIGIN)
        self.assertIs(json.loads(body)["actions_enabled"], True)
        response, body = self.call("HEAD", "/api/status", actions=True, origin=ORIGIN)
        self.assertEqual(response.status, 200)

    def test_unknown_paths_are_404_for_every_method(self) -> None:
        for method in ("GET", "HEAD"):
            response, _ = self.call(method, "/nope")
            self.assertEqual(response.status, 404)
        response, _ = self.call("GET", "/portfolio/other.js")
        self.assertEqual(response.status, 404)
        response, _ = self.call("POST", "/api/status", body=b"{}")
        self.assertEqual(response.status, 404)
        self.controller.perform_action.assert_not_called()

    def test_actions_need_both_the_flag_and_a_trusted_origin(self) -> None:
        body = b'{"action":"disconnect"}'
        headers = {"Content-Type": "application/json", "Origin": ORIGIN, "Host": HOST}
        for actions, origin in ((True, None), (False, ORIGIN), (False, None)):
            with self.subTest(actions=actions, origin=origin):
                response, data = self.call(
                    "POST",
                    "/api/action",
                    body=body,
                    headers=headers,
                    actions=actions,
                    origin=origin,
                )
                self.assertEqual(response.status, 403)
                self.assertIn(b"Unix-socket transport", data)
        self.controller.perform_action.assert_not_called()

    def test_body_of_exactly_the_size_limit_is_accepted(self) -> None:
        prefix = b'{"action":"disconnect"}'
        body = prefix + b" " * (web.MAX_REQUEST_BODY_BYTES - len(prefix))
        self.assertEqual(len(body), web.MAX_REQUEST_BODY_BYTES)
        response, _ = self.post(body=body, headers={"Host": HOST})
        self.assertEqual(response.status, 200)
        self.controller.perform_action.assert_called_once_with({"action": "disconnect"})

    def test_post_requires_the_exact_host_header(self) -> None:
        response, body = self.post(headers={"Host": "attacker.invalid"})
        self.assertEqual(response.status, 403)
        self.assertIn(b"untrusted request host", body)
        self.controller.perform_action.assert_not_called()

    def test_post_with_missing_origin_is_refused(self) -> None:
        response, body = self.call(
            "POST",
            "/api/action",
            body=b"{}",
            headers={"Content-Type": "application/json", "Host": HOST},
            actions=True,
            origin=ORIGIN,
        )
        self.assertEqual(response.status, 403)
        self.assertIn(b"untrusted request origin", body)

    def test_post_requires_json_content_type_but_allows_parameters_and_case(self) -> None:
        response, body = self.post(headers={"Content-Type": "text/plain", "Host": HOST})
        self.assertEqual(response.status, 415)
        self.assertIn(b"application/json", body)
        self.controller.perform_action.assert_not_called()

        response, _ = self.post(
            headers={"Content-Type": "Application/JSON; charset=utf-8", "Host": HOST}
        )
        self.assertEqual(response.status, 200)

    def test_post_success_returns_message_repair_and_fresh_status(self) -> None:
        response, body = self.post(headers={"Host": HOST})
        self.assertEqual(response.status, 200)
        data = json.loads(body)
        self.assertEqual(data["message"], "all good; WireGuard started on wg0")
        self.assertEqual(data["repair"], "interfaces: wg0; started: wg0")
        self.assertEqual(data["status"], self.controller.status())

    def test_empty_body_is_an_empty_payload(self) -> None:
        response, _ = self.post(body=b"", headers={"Host": HOST})
        self.assertEqual(response.status, 200)
        self.controller.perform_action.assert_called_once_with({})

    def test_non_object_body_is_a_client_error(self) -> None:
        for body in (b"[1]", b'"x"', b"7", b"null"):
            with self.subTest(body=body):
                response, data = self.post(body=body, headers={"Host": HOST})
                self.assertEqual(response.status, 400)
                self.assertIn(b"JSON object", data)
        self.controller.perform_action.assert_not_called()

    def test_malformed_body_is_a_client_error_not_a_server_error(self) -> None:
        cases = {
            "invalid json": (b"{not json", {}),
            "bad utf-8": (b"\xff\xfe", {}),
            "bad length": (b"{}", {"Content-Length": "abc"}),
            "oversize": (b"{}", {"Content-Length": str(web.MAX_REQUEST_BODY_BYTES + 1)}),
        }
        for name, (body, extra) in cases.items():
            with self.subTest(name):
                headers = {"Host": HOST, **extra}
                response, data = self.post(body=body, headers=headers)
                self.assertEqual(response.status, 400)
                self.assertNotIn(b"Traceback", data)
        self.controller.perform_action.assert_not_called()

    def test_validation_errors_from_the_controller_are_400_with_the_message(self) -> None:
        self.controller.perform_action.side_effect = ConfigurationError("Unsupported action: x")
        response, body = self.post(headers={"Host": HOST})
        self.assertEqual(response.status, 400)
        self.assertEqual(json.loads(body), {"error": "Unsupported action: x"})

    def test_unexpected_errors_are_500(self) -> None:
        self.controller.perform_action.side_effect = RuntimeError("kaboom")
        with self.assertLogs("nordility.web", level="ERROR"):
            response, body = self.post(headers={"Host": HOST})
        self.assertEqual(response.status, 500)
        self.assertEqual(json.loads(body), {"error": "kaboom"})

    def test_peer_address_is_anonymised_only_on_the_trusted_transport(self) -> None:
        trusted = web.make_handler(self.controller, actions_enabled=True, trusted_origin=ORIGIN)
        plain = web.make_handler(self.controller)
        instance = trusted.__new__(trusted)
        self.assertEqual(instance.address_string(), "trusted-unix-peer")
        plain_instance = plain.__new__(plain)
        plain_instance.client_address = ("10.1.2.3", 5555)
        self.assertEqual(plain_instance.address_string(), "10.1.2.3")

    def test_log_message_goes_to_the_module_logger(self) -> None:
        trusted = web.make_handler(self.controller, actions_enabled=True, trusted_origin=ORIGIN)
        instance = trusted.__new__(trusted)
        with self.assertLogs("nordility.web", level="INFO") as logs:
            instance.log_message("%s %d", "GET", 200)
        self.assertEqual(logs.records[0].getMessage(), "trusted-unix-peer - GET 200")


class SocketParentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="nd"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.root.chmod(0o700)

    def test_accepts_a_private_parent(self) -> None:
        web._validate_socket_parent(self.root / "s.sock")

    def test_rejects_each_unsafe_shape(self) -> None:
        existing = self.root / "taken"
        existing.write_text("x")
        link = self.root / "dangling"
        link.symlink_to(self.root / "nowhere")
        real = self.root / "real"
        real.mkdir(mode=0o700)
        parent_link = self.root / "parent-link"
        parent_link.symlink_to(real)
        loose = self.root / "loose"
        loose.mkdir()
        loose.chmod(0o770)
        group_only = self.root / "grp"
        group_only.mkdir()
        group_only.chmod(0o720)
        world_only = self.root / "wrld"
        world_only.mkdir()
        world_only.chmod(0o702)
        cases = {
            "relative": (Path("rel.sock"), "absolute"),
            "existing file": (existing, "existing"),
            "dangling symlink": (link, "existing"),
            "missing parent": (self.root / "gone" / "s.sock", "non-symlink directory"),
            "symlink parent": (parent_link / "s.sock", "non-symlink directory"),
            "file parent": (existing / "s.sock", "non-symlink directory"),
            "group writable": (loose / "s.sock", "group/world writable"),
            "group write bit": (group_only / "s.sock", "group/world writable"),
            "world write bit": (world_only / "s.sock", "group/world writable"),
        }
        for name, (path, fragment) in cases.items():
            with self.subTest(name), self.assertRaisesRegex(ConfigurationError, fragment):
                web._validate_socket_parent(path)

    def test_trusted_origin_rejections(self) -> None:
        for bad in (
            "",
            "ftp://h",
            "https://",
            "https://u:p@h",
            "https://:p@h",
            "https://h/x",
            "https://h?q=1",
            "https://h#f",
            "https://h/../",
        ):
            with self.subTest(bad), self.assertRaises(ConfigurationError):
                web._validate_trusted_origin(bad)
        self.assertEqual(web._validate_trusted_origin("https://h:8443"), "https://h:8443")
        self.assertEqual(web._validate_trusted_origin("https://h"), "https://h")


def _args(**overrides) -> argparse.Namespace:
    values = {
        "executable": "nordvpn",
        "backend": "cli",
        "wireguard_interfaces": None,
        "wireguard_fwmark": 1,
        "ip_rule_priority": 2,
        "auto_login": False,
        "keepass_entry": None,
        "keepass_profile": None,
        "unix_socket": None,
        "trusted_origin": None,
        "host": None,
        "port": 0,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class RunWebServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="nd"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.root.chmod(0o700)

    def test_tcp_mode_binds_the_requested_host_and_serves_without_actions(self) -> None:
        server = mock.Mock()
        with (
            mock.patch.object(web, "ThreadingHTTPServer", return_value=server) as cls,
            self.assertLogs("nordility.web", level="WARNING") as logs,
        ):
            web.run_web_server(_args(host="10.0.0.5", port=5301))
        self.assertEqual(cls.call_args.args[0], ("10.0.0.5", 5301))
        server.serve_forever.assert_called_once_with()
        server.server_close.assert_called_once_with()
        self.assertTrue(any("actions are disabled" in line for line in logs.output))

    def test_tcp_mode_defaults_to_loopback(self) -> None:
        server = mock.Mock()
        with mock.patch.object(web, "ThreadingHTTPServer", return_value=server) as cls:
            web.run_web_server(_args(port=5301))
        self.assertEqual(cls.call_args.args[0], ("127.0.0.1", 5301))

    def test_server_is_closed_even_when_serving_fails(self) -> None:
        server = mock.Mock()
        server.serve_forever.side_effect = KeyboardInterrupt
        with (
            mock.patch.object(web, "ThreadingHTTPServer", return_value=server),
            self.assertRaises(KeyboardInterrupt),
        ):
            web.run_web_server(_args())
        server.server_close.assert_called_once_with()

    def test_unix_socket_without_platform_support_exits_with_guidance(self) -> None:
        with (
            mock.patch.object(web, "UNIX_SOCKETS_SUPPORTED", False),
            self.assertRaises(SystemExit) as ctx,
        ):
            web.run_web_server(_args(unix_socket=str(self.root / "s.sock")))
        self.assertIn("--unix-socket", str(ctx.exception))

    def test_unix_socket_requires_a_valid_trusted_origin_before_binding(self) -> None:
        path = self.root / "s.sock"
        for origin in (None, "http://h"):
            with self.subTest(origin=origin), self.assertRaises(ConfigurationError):
                web.run_web_server(_args(unix_socket=str(path), trusted_origin=origin))
        self.assertFalse(path.exists())

    def test_unix_socket_refuses_an_unsafe_parent_before_binding(self) -> None:
        loose = self.root / "loose"
        loose.mkdir()
        loose.chmod(0o777)
        with self.assertRaises(ConfigurationError):
            web.run_web_server(_args(unix_socket=str(loose / "s.sock"), trusted_origin=ORIGIN))
        self.assertEqual(list(loose.iterdir()), [])

    def _serve(self, during):
        seen: dict[str, object] = {}
        path = self.root / "s.sock"

        def serve(_self):
            seen["mode"] = stat.S_IMODE(path.lstat().st_mode)
            seen["is_socket"] = stat.S_ISSOCK(path.lstat().st_mode)
            during(path)

        with mock.patch.object(web.ThreadingUnixHTTPServer, "serve_forever", serve):
            web.run_web_server(_args(unix_socket=str(path), trusted_origin=ORIGIN + "/"))
        return path, seen

    def test_unix_socket_is_group_accessible_only_and_removed_on_exit(self) -> None:
        path, seen = self._serve(lambda _p: None)
        self.assertTrue(seen["is_socket"])
        self.assertEqual(seen["mode"], web.DEFAULT_WEB_SOCKET_MODE)
        self.assertFalse(path.exists())

    def test_replaced_socket_path_is_not_deleted_on_exit(self) -> None:
        def swap(path: Path) -> None:
            path.unlink()
            path.write_text("someone else's file")

        path, _ = self._serve(swap)
        self.assertEqual(path.read_text(), "someone else's file")

    def test_replacement_socket_with_a_different_inode_is_left_alone(self) -> None:
        keep: list[socket.socket] = []

        def swap(path: Path) -> None:
            # Bind the replacement first so it cannot reuse the original inode.
            staged = path.with_name("staged.sock")
            other = socket.socket(socket.AF_UNIX)
            other.bind(str(staged))
            keep.append(other)
            os.replace(staged, path)

        path, _ = self._serve(swap)
        try:
            self.assertTrue(path.exists())
        finally:
            for sock in keep:
                sock.close()

    def test_unlink_errors_other_than_a_missing_socket_are_not_hidden(self) -> None:
        with mock.patch.object(Path, "unlink", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                self._serve(lambda _p: None)
        # Real cleanup, since the patched unlink did nothing.
        (self.root / "s.sock").unlink()

    def test_unix_server_gets_the_canonical_origin_and_actions_enabled(self) -> None:
        with mock.patch.object(web, "make_handler", wraps=web.make_handler) as maker:
            self._serve(lambda _p: None)
        self.assertTrue(maker.call_args.kwargs["actions_enabled"])
        self.assertEqual(maker.call_args.kwargs["trusted_origin"], ORIGIN)

    def test_already_removed_socket_is_tolerated(self) -> None:
        path, _ = self._serve(lambda p: p.unlink())
        self.assertFalse(path.exists())

    def test_passes_controller_settings_through(self) -> None:
        server = mock.Mock()
        with (
            mock.patch.object(web, "ThreadingHTTPServer", return_value=server),
            mock.patch.object(web, "NordilityWebController") as controller,
        ):
            web.run_web_server(
                _args(
                    wireguard_interfaces=["wg-x"],
                    wireguard_fwmark=5,
                    ip_rule_priority=6,
                    auto_login=True,
                    keepass_entry="e",
                    keepass_profile="p",
                )
            )
        kwargs = controller.call_args.kwargs
        self.assertEqual(kwargs["wireguard_interfaces"], ("wg-x",))
        self.assertEqual(kwargs["wireguard_fwmark"], 5)
        self.assertEqual(kwargs["ip_rule_priority"], 6)
        self.assertTrue(kwargs["auto_login"])
        self.assertEqual((kwargs["keepass_entry"], kwargs["keepass_profile"]), ("e", "p"))


class FileModeSanityTests(unittest.TestCase):
    def test_socket_mode_constant_is_not_world_accessible(self) -> None:
        self.assertEqual(web.DEFAULT_WEB_SOCKET_MODE & 0o007, 0)
        self.assertTrue(os.name == "posix")


if __name__ == "__main__":
    unittest.main()
