from __future__ import annotations

import unittest
from unittest import mock

from nordility import token_login


class TokenLoginHelperTests(unittest.TestCase):
    def test_main_disables_dumpability_before_pty_login(self) -> None:
        calls: list[str] = []

        def disable() -> None:
            calls.append("disable")

        def verify(executable: str) -> None:
            calls.append("consent")
            self.assertEqual(executable, "/usr/bin/nordvpn")

        def run(executable_fd: int) -> int:
            calls.append("pty")
            self.assertEqual(executable_fd, 17)
            return 0

        with (
            mock.patch.object(token_login, "_open_validated_executable", return_value=17),
            mock.patch.object(token_login, "_disable_dumpability", side_effect=disable),
            mock.patch.object(token_login, "_verify_consent_disabled", side_effect=verify),
            mock.patch.object(token_login, "_run_pty_login", side_effect=run),
            mock.patch.object(token_login.os, "close") as close,
        ):
            self.assertEqual(token_login.main(["/usr/bin/nordvpn"]), 0)

        self.assertEqual(calls, ["disable", "consent", "pty"])
        close.assert_called_once_with(17)

    def test_handoff_waits_for_hidden_prompt_before_reading_token(self) -> None:
        calls: list[str] = []
        token = bytearray(b"secure-token-abc123456789")

        def prompt(pid: int, master_fd: int) -> None:
            calls.append("prompt")
            self.assertEqual((pid, master_fd), (123, 19))

        def read_token() -> bytearray:
            calls.append("read")
            return token

        def write(descriptor: int, payload) -> None:
            calls.append("newline" if bytes(payload) == b"\n" else "token")
            self.assertEqual(descriptor, 19)

        with (
            mock.patch.object(token_login, "_spawn_cli", return_value=(123, 19)),
            mock.patch.object(token_login, "_wait_for_hidden_prompt", side_effect=prompt),
            mock.patch.object(token_login, "_read_token", side_effect=read_token),
            mock.patch.object(token_login, "_write_all", side_effect=write),
            mock.patch.object(token_login, "_wait_for_login", return_value=0),
            mock.patch.object(token_login.os, "close"),
            mock.patch.object(token_login, "_terminate_child"),
        ):
            self.assertEqual(token_login._run_pty_login(17), 0)

        self.assertEqual(calls, ["prompt", "read", "token", "newline"])
        self.assertEqual(token, bytearray(len(token)))

    def test_child_exec_has_no_secret_bearing_argument(self) -> None:
        class ChildExec(Exception):
            pass

        with (
            mock.patch.object(token_login.pty, "fork", return_value=(0, -1)),
            mock.patch.object(token_login.os, "execve", side_effect=ChildExec) as execve,
            self.assertRaises(ChildExec),
        ):
            token_login._spawn_cli(17)

        executable_fd, argv, environment = execve.call_args.args
        self.assertEqual(executable_fd, 17)
        self.assertEqual(argv, ["nordvpn", "login", "--token"])
        self.assertIsInstance(environment, dict)
        self.assertNotIn("NORDVPN_TOKEN", environment)

    def test_consent_is_verified_from_exact_settings_line(self) -> None:
        results = [
            mock.Mock(returncode=1, stdout="", stderr="already set"),
            mock.Mock(returncode=0, stdout="Technology: NORDLYNX\nUser Consent: disabled\n"),
        ]
        with mock.patch.object(token_login.subprocess, "run", side_effect=results) as run:
            token_login._verify_consent_disabled("/usr/bin/nordvpn")

        self.assertEqual(run.call_args_list[0].args[0], ["/usr/bin/nordvpn", "set", "analytics", "off"])
        self.assertEqual(run.call_args_list[1].args[0], ["/usr/bin/nordvpn", "settings"])
        self.assertTrue(all(call.kwargs["stdin"] is token_login.subprocess.DEVNULL for call in run.call_args_list))

    def test_child_cleanup_kills_session_and_reaps(self) -> None:
        with (
            mock.patch.object(token_login.os, "killpg") as killpg,
            mock.patch.object(token_login.os, "kill") as kill,
            mock.patch.object(token_login.os, "waitpid") as waitpid,
        ):
            token_login._terminate_child(123)

        killpg.assert_called_once_with(123, token_login.signal.SIGKILL)
        kill.assert_called_once_with(123, token_login.signal.SIGKILL)
        waitpid.assert_called_once_with(123, 0)

    def test_rejects_relative_executable_before_open(self) -> None:
        with (
            mock.patch.object(token_login.os, "open") as open_mock,
            self.assertRaises(SystemExit),
        ):
            token_login._open_validated_executable("nordvpn")

        open_mock.assert_not_called()

    def test_token_policy_matches_the_pinned_cli_handoff_boundary(self) -> None:
        self.assertEqual(token_login.TOKEN_MINIMUM, 1)
        self.assertEqual(token_login.TOKEN_MAXIMUM, 1024)


if __name__ == "__main__":
    unittest.main()
