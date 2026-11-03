"""Edge and failure paths of the token handoff broker.

Everything here is stubbed: no NordVPN binary, no pseudoterminal child, no real
token. Canary token bytes are fake and only used to prove they never surface.
"""

from __future__ import annotations

import contextlib
import io
import os
import stat
import subprocess
import tempfile
import termios
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from nordility import token_login

CANARY = b"CANARYtokenValue0123456789"


class FakeClock:
    """Monotonic clock that only moves when the code under test sleeps/reads."""

    def __init__(self, step: float = 0.0) -> None:
        self.now = 1000.0
        self.step = step

    def __call__(self) -> float:
        value = self.now
        self.now += self.step
        return value


def _stdin(data: bytes):
    return SimpleNamespace(buffer=io.BytesIO(data))


def _fail_message(callable_, *args) -> str:
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr), unittest.TestCase().assertRaises(SystemExit) as ctx:
        callable_(*args)
    assert ctx.exception.code == 1
    return stderr.getvalue()


class FailTests(unittest.TestCase):
    def test_fail_prefixes_message_on_stderr_and_exits_one(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as ctx:
            token_login._fail("boom")
        self.assertEqual(ctx.exception.code, 1)
        self.assertEqual(stderr.getvalue(), "nordility-token-login: boom\n")


class DumpabilityTests(unittest.TestCase):
    def test_refuses_non_linux_before_touching_limits(self) -> None:
        with (
            mock.patch.object(token_login.sys, "platform", "darwin"),
            mock.patch.object(token_login.resource, "setrlimit") as setrlimit,
        ):
            message = _fail_message(token_login._disable_dumpability)
        self.assertIn("only on Linux", message)
        setrlimit.assert_not_called()

    def test_core_dump_limit_failure_is_fatal(self) -> None:
        for error in (OSError("nope"), ValueError("nope")):
            with (
                mock.patch.object(token_login.sys, "platform", "linux"),
                mock.patch.object(token_login.resource, "setrlimit", side_effect=error),
                mock.patch.object(token_login.ctypes, "CDLL") as cdll,
            ):
                message = _fail_message(token_login._disable_dumpability)
            self.assertIn("core dumps", message)
            cdll.assert_not_called()

    def test_prctl_failure_is_fatal(self) -> None:
        libc = mock.Mock()
        libc.prctl.return_value = -1
        with (
            mock.patch.object(token_login.sys, "platform", "linux"),
            mock.patch.object(token_login.resource, "setrlimit"),
            mock.patch.object(token_login.ctypes, "CDLL", return_value=libc),
        ):
            message = _fail_message(token_login._disable_dumpability)
        self.assertIn("dumpability", message)

    def test_success_zeroes_core_limit_and_clears_dumpable_flag(self) -> None:
        libc = mock.Mock()
        libc.prctl.return_value = 0
        with (
            mock.patch.object(token_login.sys, "platform", "linux"),
            mock.patch.object(token_login.resource, "setrlimit") as setrlimit,
            mock.patch.object(token_login.ctypes, "CDLL", return_value=libc),
        ):
            token_login._disable_dumpability()
        setrlimit.assert_called_once_with(token_login.resource.RLIMIT_CORE, (0, 0))
        libc.prctl.assert_called_once_with(token_login.PR_SET_DUMPABLE, 0, 0, 0, 0)
        self.assertEqual(token_login.PR_SET_DUMPABLE, 4)


class OpenExecutableTests(unittest.TestCase):
    def _open_with(self, metadata) -> tuple[str, mock.Mock]:
        with (
            mock.patch.object(token_login.os, "open", return_value=99),
            mock.patch.object(token_login.os, "fstat", return_value=metadata),
            mock.patch.object(token_login.os, "close") as close,
        ):
            try:
                result = token_login._open_validated_executable("/usr/bin/nordvpn")
            except SystemExit:
                return "failed", close
        self.assertEqual(result, 99)
        return "ok", close

    @staticmethod
    def _meta(mode: int, uid: int = 0):
        return SimpleNamespace(st_mode=mode, st_uid=uid)

    def test_accepts_root_owned_executable_and_keeps_descriptor_open(self) -> None:
        outcome, close = self._open_with(self._meta(stat.S_IFREG | 0o755))
        self.assertEqual(outcome, "ok")
        close.assert_not_called()

    def test_rejections_close_the_descriptor(self) -> None:
        cases = {
            "directory": self._meta(stat.S_IFDIR | 0o755),
            "not root": self._meta(stat.S_IFREG | 0o755, uid=1000),
            "group writable": self._meta(stat.S_IFREG | 0o775),
            "world writable": self._meta(stat.S_IFREG | 0o757),
            "not executable": self._meta(stat.S_IFREG | 0o644),
        }
        for name, metadata in cases.items():
            with self.subTest(name):
                outcome, close = self._open_with(metadata)
                self.assertEqual(outcome, "failed")
                close.assert_called_once_with(99)

    def test_each_rejection_names_its_reason(self) -> None:
        expected = {
            "regular file": self._meta(stat.S_IFDIR | 0o755),
            "root-owned": self._meta(stat.S_IFREG | 0o755, uid=7),
            "is not executable": self._meta(stat.S_IFREG | 0o644),
        }
        for fragment, metadata in expected.items():
            with (
                self.subTest(fragment),
                mock.patch.object(token_login.os, "open", return_value=99),
                mock.patch.object(token_login.os, "fstat", return_value=metadata),
                mock.patch.object(token_login.os, "close"),
            ):
                self.assertIn(fragment, _fail_message(token_login._open_validated_executable, "/x"))

    def test_open_failure_is_fatal(self) -> None:
        with mock.patch.object(token_login.os, "open", side_effect=OSError("denied")):
            message = _fail_message(token_login._open_validated_executable, "/usr/bin/nordvpn")
        self.assertIn("without following symlinks", message)

    def test_fstat_failure_closes_descriptor_and_is_fatal(self) -> None:
        with (
            mock.patch.object(token_login.os, "open", return_value=99),
            mock.patch.object(token_login.os, "fstat", side_effect=OSError("gone")),
            mock.patch.object(token_login.os, "close") as close,
        ):
            message = _fail_message(token_login._open_validated_executable, "/usr/bin/nordvpn")
        self.assertIn("could not inspect", message)
        close.assert_called_once_with(99)

    def test_symlink_is_refused_for_real(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            target = Path(raw) / "real"
            target.write_text("#!/bin/sh\n")
            link = Path(raw) / "link"
            link.symlink_to(target)
            message = _fail_message(token_login._open_validated_executable, str(link))
        self.assertIn("without following symlinks", message)

    def test_open_uses_nofollow_and_read_only(self) -> None:
        with (
            mock.patch.object(token_login.os, "open", side_effect=OSError) as open_mock,
            self.assertRaises(SystemExit),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            token_login._open_validated_executable("/usr/bin/nordvpn")
        flags = open_mock.call_args.args[1]
        self.assertTrue(flags & os.O_NOFOLLOW)
        self.assertFalse(flags & (os.O_WRONLY | os.O_RDWR))


class ReadTokenTests(unittest.TestCase):
    def _read(self, data: bytes) -> bytearray:
        with mock.patch.object(token_login.sys, "stdin", _stdin(data)):
            return token_login._read_token()

    def _reject(self, data: bytes) -> tuple[str, list[bytes]]:
        wiped: list[bytes] = []
        real_wipe = token_login._wipe

        def spy(buffer: bytearray) -> None:
            wiped.append(bytes(buffer))
            real_wipe(buffer)

        with (
            mock.patch.object(token_login.sys, "stdin", _stdin(data)),
            mock.patch.object(token_login, "_wipe", side_effect=spy),
        ):
            message = _fail_message(token_login._read_token)
        return message, wiped

    def test_strips_trailing_cr_and_lf_only(self) -> None:
        self.assertEqual(self._read(CANARY + b"\r\n"), bytearray(CANARY))
        self.assertEqual(self._read(CANARY + b"\n\n\r"), bytearray(CANARY))
        self.assertEqual(self._read(CANARY), bytearray(CANARY))

    def test_size_boundaries(self) -> None:
        maximum = b"A" * token_login.TOKEN_MAXIMUM
        self.assertEqual(self._read(maximum), bytearray(maximum))
        self.assertEqual(self._read(maximum + b"\r\n"), bytearray(maximum))
        self.assertEqual(self._read(b"A"), bytearray(b"A"))

        message, _ = self._reject(maximum + b"A")
        self.assertIn("invalid size", message)
        message, _ = self._reject(maximum + b"\r\n\n")
        self.assertIn("too large", message)

    def test_empty_and_newline_only_are_rejected(self) -> None:
        for data in (b"", b"\n", b"\r\n\r\n"):
            with self.subTest(data=data):
                message, wiped = self._reject(data)
                self.assertIn("invalid size", message)
                self.assertEqual(len(wiped), 1)

    def test_whitespace_controls_and_non_ascii_are_rejected(self) -> None:
        for data in (b"abc def", b"abc\tdef", b"abc\x00def", b"abc\x7fdef", "abcé".encode()):
            with self.subTest(data=data):
                message, wiped = self._reject(data)
                self.assertIn("whitespace, controls, or non-ASCII", message)
                self.assertEqual(len(wiped), 1)

    def test_printable_boundary_bytes_are_accepted(self) -> None:
        self.assertEqual(self._read(b"!~"), bytearray(b"!~"))

    def test_rejected_input_is_wiped_and_never_echoed_in_the_error(self) -> None:
        message, wiped = self._reject(CANARY + b" tail")
        self.assertNotIn(CANARY.decode(), message)
        self.assertEqual(len(wiped), 1)
        self.assertIn(CANARY, wiped[0])

        oversize = CANARY + b"A" * token_login.TOKEN_MAXIMUM
        message, wiped = self._reject(oversize)
        self.assertNotIn(CANARY.decode(), message)
        self.assertEqual(len(wiped), 1)

    def test_reads_at_most_one_more_than_the_largest_acceptable_input(self) -> None:
        stdin = SimpleNamespace(buffer=mock.Mock())
        stdin.buffer.read.return_value = b"A"
        with mock.patch.object(token_login.sys, "stdin", stdin):
            token_login._read_token()
        stdin.buffer.read.assert_called_once_with(token_login.TOKEN_MAXIMUM + 3)

    def test_wipe_zeroes_in_place_without_resizing(self) -> None:
        buffer = bytearray(CANARY)
        token_login._wipe(buffer)
        self.assertEqual(buffer, bytearray(len(CANARY)))
        token_login._wipe(bytearray())


class ChildPollingTests(unittest.TestCase):
    def test_child_exited_reflects_waitid_without_reaping(self) -> None:
        with mock.patch.object(token_login.os, "waitid", return_value=None) as waitid:
            self.assertFalse(token_login._child_exited(5))
        flags = waitid.call_args.args[2]
        self.assertTrue(flags & token_login.os.WNOHANG)
        self.assertTrue(flags & token_login.os.WNOWAIT)
        with mock.patch.object(token_login.os, "waitid", return_value=SimpleNamespace()):
            self.assertTrue(token_login._child_exited(5))

    def test_read_available_returns_nothing_when_not_readable(self) -> None:
        with (
            mock.patch.object(token_login.select, "select", return_value=([], [], [])),
            mock.patch.object(token_login.os, "read") as read,
        ):
            self.assertEqual(token_login._read_available(7, 0.5), b"")
        read.assert_not_called()

    def test_read_available_reads_a_bounded_chunk(self) -> None:
        with (
            mock.patch.object(token_login.select, "select", return_value=([7], [], [])),
            mock.patch.object(token_login.os, "read", return_value=b"hi") as read,
        ):
            self.assertEqual(token_login._read_available(7, 0.5), b"hi")
        read.assert_called_once_with(7, 4096)

    def test_read_available_swallows_a_closed_terminal(self) -> None:
        with (
            mock.patch.object(token_login.select, "select", return_value=([7], [], [])),
            mock.patch.object(token_login.os, "read", side_effect=OSError("EIO")),
        ):
            self.assertEqual(token_login._read_available(7, 0.5), b"")

    def test_negative_timeout_is_clamped_to_zero(self) -> None:
        with mock.patch.object(token_login.select, "select", return_value=([], [], [])) as sel:
            token_login._read_available(7, -3.0)
        self.assertEqual(sel.call_args.args[3], 0.0)

    def test_real_pipe_roundtrip(self) -> None:
        read_fd, write_fd = os.pipe()
        try:
            self.assertEqual(token_login._read_available(read_fd, 0.0), b"")
            os.write(write_fd, b"abc")
            self.assertEqual(token_login._read_available(read_fd, 1.0), b"abc")
        finally:
            os.close(read_fd)
            os.close(write_fd)


class HiddenPromptTests(unittest.TestCase):
    def _run(self, chunks, exited, attribute_flags, step=0.0):
        """Drive _wait_for_hidden_prompt with scripted PTY output and state."""
        chunk_iter = iter(chunks)
        exit_iter = iter(exited)
        flag_iter = iter(attribute_flags)
        clock = FakeClock(step)

        def read_available(_fd, _timeout):
            return next(chunk_iter, b"")

        def child_exited(_pid):
            return next(exit_iter, False)

        def tcgetattr(_fd):
            return [0, 0, 0, next(flag_iter), 0, 0, []]

        patches = (
            mock.patch.object(token_login.time, "monotonic", side_effect=clock),
            mock.patch.object(token_login, "_read_available", side_effect=read_available),
            mock.patch.object(token_login, "_child_exited", side_effect=child_exited),
            mock.patch.object(token_login.termios, "tcgetattr", side_effect=tcgetattr),
        )
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            return token_login._wait_for_hidden_prompt(11, 12)

    def test_returns_once_prompt_seen_and_echo_is_off(self) -> None:
        self.assertIsNone(self._run([token_login.PROMPT], [False], [0]))

    def test_prompt_split_across_reads_is_recognised(self) -> None:
        half = len(token_login.PROMPT) // 2
        self.assertIsNone(
            self._run([token_login.PROMPT[:half], token_login.PROMPT[half:]], [False] * 3, [0])
        )

    def test_waits_while_echo_is_still_enabled(self) -> None:
        flags = [termios.ECHO, termios.ECHO | termios.ECHONL, termios.ECHONL, 0]
        remaining = iter(flags)
        seen = []

        def tcgetattr(_fd):
            value = next(remaining)
            seen.append(value)
            return [0, 0, 0, value, 0, 0, []]

        with (
            mock.patch.object(token_login.time, "monotonic", side_effect=FakeClock()),
            mock.patch.object(
                token_login, "_read_available", side_effect=[token_login.PROMPT] + [b""] * 10
            ),
            mock.patch.object(token_login, "_child_exited", return_value=False),
            mock.patch.object(token_login.termios, "tcgetattr", side_effect=tcgetattr),
        ):
            token_login._wait_for_hidden_prompt(11, 12)
        # ECHONL alone also counts as "echo on": only a clean state returns.
        self.assertEqual(seen, flags)

    def test_prompt_with_echo_never_disabled_times_out(self) -> None:
        with (
            mock.patch.object(token_login.time, "monotonic", side_effect=FakeClock(step=10.0)),
            mock.patch.object(token_login, "_read_available", return_value=token_login.PROMPT),
            mock.patch.object(token_login, "_child_exited", return_value=False),
            mock.patch.object(
                token_login.termios, "tcgetattr", return_value=[0, 0, 0, termios.ECHO, 0, 0, []]
            ),
        ):
            message = _fail_message(token_login._wait_for_hidden_prompt, 11, 12)
        self.assertIn("did not present a no-echo token prompt", message)

    def test_child_exit_before_prompt_is_fatal(self) -> None:
        with (
            mock.patch.object(token_login.time, "monotonic", side_effect=FakeClock()),
            mock.patch.object(token_login, "_read_available", return_value=b"error text"),
            mock.patch.object(token_login, "_child_exited", return_value=True),
        ):
            message = _fail_message(token_login._wait_for_hidden_prompt, 11, 12)
        self.assertIn("exited before its secure token prompt", message)

    def test_child_exit_while_waiting_for_echo_off_is_fatal(self) -> None:
        exits = iter([False, True])
        with (
            mock.patch.object(token_login.time, "monotonic", side_effect=FakeClock()),
            mock.patch.object(token_login, "_read_available", return_value=token_login.PROMPT),
            mock.patch.object(token_login, "_child_exited", side_effect=lambda _p: next(exits)),
            mock.patch.object(
                token_login.termios, "tcgetattr", return_value=[0, 0, 0, termios.ECHO, 0, 0, []]
            ),
        ):
            message = _fail_message(token_login._wait_for_hidden_prompt, 11, 12)
        self.assertIn("exited before disabling terminal echo", message)

    def test_silence_times_out(self) -> None:
        with (
            mock.patch.object(token_login.time, "monotonic", side_effect=FakeClock(step=10.0)),
            mock.patch.object(token_login, "_read_available", return_value=b""),
            mock.patch.object(token_login, "_child_exited", return_value=False),
        ):
            message = _fail_message(token_login._wait_for_hidden_prompt, 11, 12)
        self.assertIn("did not present a no-echo token prompt", message)

    def test_other_output_without_the_prompt_never_releases_the_token(self) -> None:
        with (
            mock.patch.object(token_login.time, "monotonic", side_effect=FakeClock(step=5.0)),
            mock.patch.object(token_login, "_read_available", return_value=b"Enter token: "),
            mock.patch.object(token_login, "_child_exited", return_value=False),
            mock.patch.object(token_login.termios, "tcgetattr") as tcgetattr,
        ):
            _fail_message(token_login._wait_for_hidden_prompt, 11, 12)
        tcgetattr.assert_not_called()


class WriteAllTests(unittest.TestCase):
    def test_retries_partial_writes_until_everything_is_sent(self) -> None:
        sent = bytearray()

        def write(_fd, view):
            chunk = bytes(view[:3])
            sent.extend(chunk)
            return len(chunk)

        with mock.patch.object(token_login.os, "write", side_effect=write):
            token_login._write_all(9, bytearray(CANARY))
        self.assertEqual(bytes(sent), CANARY)

    def test_zero_length_write_is_fatal_and_does_not_loop(self) -> None:
        with mock.patch.object(token_login.os, "write", return_value=0) as write:
            message = _fail_message(token_login._write_all, 9, b"abc")
        self.assertIn("could not write the token", message)
        self.assertNotIn("abc", message)
        write.assert_called_once()

    def test_empty_payload_writes_nothing(self) -> None:
        with mock.patch.object(token_login.os, "write") as write:
            token_login._write_all(9, b"")
        write.assert_not_called()


class WaitForLoginTests(unittest.TestCase):
    def test_returns_decoded_exit_code_and_reaps(self) -> None:
        with (
            mock.patch.object(token_login.time, "monotonic", side_effect=FakeClock()),
            mock.patch.object(token_login, "_read_available", return_value=b"secret-ish output"),
            mock.patch.object(token_login, "_child_exited", side_effect=[False, True]),
            mock.patch.object(token_login.os, "waitpid", return_value=(5, 3 << 8)) as waitpid,
        ):
            self.assertEqual(token_login._wait_for_login(5, 6), 3)
        waitpid.assert_called_once_with(5, 0)

    def test_signal_death_is_a_negative_code(self) -> None:
        with (
            mock.patch.object(token_login.time, "monotonic", side_effect=FakeClock()),
            mock.patch.object(token_login, "_read_available", return_value=b""),
            mock.patch.object(token_login, "_child_exited", return_value=True),
            mock.patch.object(token_login.os, "waitpid", return_value=(5, 9)),
        ):
            self.assertEqual(token_login._wait_for_login(5, 6), -9)

    def test_output_is_drained_and_discarded(self) -> None:
        with (
            mock.patch.object(token_login.time, "monotonic", side_effect=FakeClock()),
            mock.patch.object(token_login, "_read_available", return_value=CANARY) as read,
            mock.patch.object(token_login, "_child_exited", side_effect=[False, False, True]),
            mock.patch.object(token_login.os, "waitpid", return_value=(5, 0)),
            contextlib.redirect_stdout(io.StringIO()) as out,
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            token_login._wait_for_login(5, 6)
        self.assertGreaterEqual(read.call_count, 3)
        self.assertEqual(out.getvalue() + err.getvalue(), "")

    def test_timeout_is_fatal(self) -> None:
        with (
            mock.patch.object(token_login.time, "monotonic", side_effect=FakeClock(step=30.0)),
            mock.patch.object(token_login, "_read_available", return_value=b""),
            mock.patch.object(token_login, "_child_exited", return_value=False),
        ):
            message = _fail_message(token_login._wait_for_login, 5, 6)
        self.assertIn("timed out", message)


class TerminateChildTests(unittest.TestCase):
    def test_already_gone_child_is_tolerated_at_every_step(self) -> None:
        with (
            mock.patch.object(token_login.os, "killpg", side_effect=ProcessLookupError),
            mock.patch.object(token_login.os, "kill", side_effect=ProcessLookupError) as kill,
            mock.patch.object(token_login.os, "waitpid", side_effect=ChildProcessError) as waitpid,
        ):
            token_login._terminate_child(77)
        kill.assert_called_once()
        waitpid.assert_called_once_with(77, 0)

    def test_unexpected_errors_are_not_hidden(self) -> None:
        with (
            mock.patch.object(token_login.os, "killpg", side_effect=PermissionError),
            self.assertRaises(PermissionError),
        ):
            token_login._terminate_child(77)


class ConsentTests(unittest.TestCase):
    def _verify(self, results):
        with mock.patch.object(token_login.subprocess, "run", side_effect=results) as run:
            try:
                token_login._verify_consent_disabled("/usr/bin/nordvpn")
            except SystemExit:
                return "failed", run
        return "ok", run

    @staticmethod
    def _done(returncode=0, stdout=""):
        return mock.Mock(returncode=returncode, stdout=stdout, stderr="")

    def test_accepts_exact_line_among_others(self) -> None:
        outcome, run = self._verify(
            [self._done(), self._done(stdout="A: b\nUser Consent: disabled\nC: d\n")]
        )
        self.assertEqual(outcome, "ok")
        self.assertEqual(run.call_count, 2)

    def test_rejects_enabled_consent(self) -> None:
        outcome, _ = self._verify([self._done(), self._done(stdout="User Consent: enabled\n")])
        self.assertEqual(outcome, "failed")

    def test_rejects_substring_match_that_is_not_the_whole_line(self) -> None:
        for line in (
            "Not User Consent: disabled",
            "User Consent: disabled-ish",
            "  User Consent: disabled",
        ):
            with self.subTest(line):
                outcome, _ = self._verify([self._done(), self._done(stdout=line + "\n")])
                self.assertEqual(outcome, "failed")

    def test_rejects_failing_settings_command_even_with_matching_text(self) -> None:
        outcome, _ = self._verify(
            [self._done(), self._done(returncode=1, stdout="User Consent: disabled\n")]
        )
        self.assertEqual(outcome, "failed")

    def test_set_command_failure_alone_is_not_fatal(self) -> None:
        outcome, _ = self._verify(
            [self._done(returncode=1), self._done(stdout="User Consent: disabled\n")]
        )
        self.assertEqual(outcome, "ok")

    def test_spawn_errors_and_timeouts_are_fatal_with_one_message(self) -> None:
        errors = (OSError("missing"), subprocess.TimeoutExpired(cmd="nordvpn", timeout=10))
        for error in errors:
            with self.subTest(type(error).__name__):
                with mock.patch.object(token_login.subprocess, "run", side_effect=error):
                    message = _fail_message(
                        token_login._verify_consent_disabled, "/usr/bin/nordvpn"
                    )
                self.assertIn("non-interactive NordVPN consent setting", message)

    def test_second_command_failure_is_fatal_too(self) -> None:
        outcome, _ = self._verify([self._done(), OSError("gone")])
        self.assertEqual(outcome, "failed")

    def test_commands_are_isolated_from_the_caller_environment(self) -> None:
        with mock.patch.dict(os.environ, {"NORDVPN_TOKEN": CANARY.decode(), "HOME": "/home/x"}):
            _, run = self._verify([self._done(), self._done(stdout="User Consent: disabled\n")])
        for call in run.call_args_list:
            env = call.kwargs["env"]
            self.assertEqual(env["PATH"], "/usr/sbin:/usr/bin:/sbin:/bin")
            self.assertEqual(env["HOME"], "/home/x")
            self.assertEqual(env["TERM"], "dumb")
            self.assertNotIn("NORDVPN_TOKEN", env)
            self.assertEqual(call.kwargs["timeout"], token_login.CONSENT_TIMEOUT_SECONDS)
            self.assertFalse(call.kwargs["check"])
            self.assertTrue(call.kwargs["capture_output"])


class SpawnEnvironmentTests(unittest.TestCase):
    def test_parent_returns_pid_and_master_without_exec(self) -> None:
        with (
            mock.patch.object(token_login.pty, "fork", return_value=(4321, 8)),
            mock.patch.object(token_login.os, "execve") as execve,
        ):
            self.assertEqual(token_login._spawn_cli(17), (4321, 8))
        execve.assert_not_called()

    def test_child_environment_is_minimal_and_never_carries_the_token(self) -> None:
        class Stop(Exception):
            pass

        with (
            mock.patch.dict(os.environ, {"NORDVPN_TOKEN": CANARY.decode(), "HOME": "/home/y"}),
            mock.patch.object(token_login.pty, "fork", return_value=(0, -1)),
            mock.patch.object(token_login.os, "execve", side_effect=Stop) as execve,
            self.assertRaises(Stop),
        ):
            token_login._spawn_cli(17)
        environment = execve.call_args.args[2]
        self.assertEqual(set(environment), {"HOME", "PATH", "LANG", "TERM", "NO_COLOR"})
        self.assertEqual(environment["HOME"], "/home/y")

    def test_exec_failure_in_child_exits_127(self) -> None:
        class Exited(Exception):
            pass

        with (
            mock.patch.object(token_login.pty, "fork", return_value=(0, -1)),
            mock.patch.object(token_login.os, "execve", side_effect=OSError),
            mock.patch.object(token_login.os, "_exit", side_effect=Exited) as exit_,
            self.assertRaises(Exited),
        ):
            token_login._spawn_cli(17)
        exit_.assert_called_once_with(127)


class RunPtyLoginTests(unittest.TestCase):
    def _run(self, *, prompt=None, write=None, login=0):
        token = bytearray(CANARY)
        patches = {
            "_spawn_cli": mock.patch.object(token_login, "_spawn_cli", return_value=(123, 19)),
            "_wait_for_hidden_prompt": mock.patch.object(
                token_login, "_wait_for_hidden_prompt", side_effect=prompt
            ),
            "_read_token": mock.patch.object(token_login, "_read_token", return_value=token),
            "_write_all": mock.patch.object(token_login, "_write_all", side_effect=write),
            "_wait_for_login": mock.patch.object(
                token_login, "_wait_for_login", return_value=login
            ),
            "close": mock.patch.object(token_login.os, "close"),
            "_terminate_child": mock.patch.object(token_login, "_terminate_child"),
        }
        with contextlib.ExitStack() as stack, contextlib.redirect_stderr(io.StringIO()) as err:
            started = {name: stack.enter_context(patch) for name, patch in patches.items()}
            try:
                code = token_login._run_pty_login(17)
            except SystemExit as exc:
                code = exc.code
        return code, token, started, err.getvalue()

    def test_failed_login_reports_exit_code_wipes_token_and_closes_terminal(self) -> None:
        code, token, started, stderr = self._run(login=4)
        self.assertEqual(code, 1)
        self.assertIn("exit code 4", stderr)
        self.assertNotIn(CANARY.decode(), stderr)
        self.assertEqual(token, bytearray(len(CANARY)))
        started["close"].assert_called_once_with(19)
        # The child was reaped by _wait_for_login, so it must not be killed.
        started["_terminate_child"].assert_not_called()

    def test_success_closes_terminal_without_killing_the_child(self) -> None:
        code, _, started, _ = self._run(login=0)
        self.assertEqual(code, 0)
        started["close"].assert_called_once_with(19)
        started["_terminate_child"].assert_not_called()

    def test_prompt_failure_terminates_child_and_never_reads_the_token(self) -> None:
        def boom(*_args):
            raise SystemExit(1)

        code, _, started, _ = self._run(prompt=boom)
        self.assertEqual(code, 1)
        started["_read_token"].assert_not_called()
        started["_write_all"].assert_not_called()
        started["_terminate_child"].assert_called_once_with(123)
        started["close"].assert_called_once_with(19)

    def test_write_failure_wipes_token_and_terminates_child(self) -> None:
        def boom(*_args):
            raise SystemExit(1)

        code, token, started, _ = self._run(write=boom)
        self.assertEqual(code, 1)
        self.assertEqual(token, bytearray(len(CANARY)))
        started["_wait_for_login"].assert_not_called()
        started["_terminate_child"].assert_called_once_with(123)

    def test_login_timeout_terminates_the_unreaped_child(self) -> None:
        with (
            mock.patch.object(token_login, "_spawn_cli", return_value=(123, 19)),
            mock.patch.object(token_login, "_wait_for_hidden_prompt"),
            mock.patch.object(token_login, "_read_token", return_value=bytearray(b"x")),
            mock.patch.object(token_login, "_write_all"),
            mock.patch.object(token_login, "_wait_for_login", side_effect=SystemExit(1)),
            mock.patch.object(token_login.os, "close"),
            mock.patch.object(token_login, "_terminate_child") as terminate,
            self.assertRaises(SystemExit),
        ):
            token_login._run_pty_login(17)
        terminate.assert_called_once_with(123)


class MainTests(unittest.TestCase):
    def test_descriptor_is_closed_when_dumpability_cannot_be_disabled(self) -> None:
        with (
            mock.patch.object(token_login, "_open_validated_executable", return_value=17),
            mock.patch.object(token_login, "_disable_dumpability", side_effect=SystemExit(1)),
            mock.patch.object(token_login, "_verify_consent_disabled") as consent,
            mock.patch.object(token_login, "_run_pty_login") as run,
            mock.patch.object(token_login.os, "close") as close,
            self.assertRaises(SystemExit),
        ):
            token_login.main(["/usr/bin/nordvpn"])
        consent.assert_not_called()
        run.assert_not_called()
        close.assert_called_once_with(17)

    def test_consent_failure_stops_before_any_token_is_read(self) -> None:
        with (
            mock.patch.object(token_login, "_open_validated_executable", return_value=17),
            mock.patch.object(token_login, "_disable_dumpability"),
            mock.patch.object(token_login, "_verify_consent_disabled", side_effect=SystemExit(1)),
            mock.patch.object(token_login, "_run_pty_login") as run,
            mock.patch.object(token_login.os, "close") as close,
            self.assertRaises(SystemExit),
        ):
            token_login.main(["/usr/bin/nordvpn"])
        run.assert_not_called()
        close.assert_called_once_with(17)

    def test_invalid_executable_never_reaches_later_stages(self) -> None:
        with (
            mock.patch.object(token_login, "_open_validated_executable", side_effect=SystemExit(1)),
            mock.patch.object(token_login, "_disable_dumpability") as disable,
            mock.patch.object(token_login.os, "close") as close,
            self.assertRaises(SystemExit),
        ):
            token_login.main(["/usr/bin/nordvpn"])
        disable.assert_not_called()
        close.assert_not_called()

    def test_requires_exactly_one_executable_argument(self) -> None:
        for argv in ([], ["a", "b"]):
            with (
                self.subTest(argv=argv),
                mock.patch.object(token_login, "_open_validated_executable") as opened,
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                token_login.main(argv)
            opened.assert_not_called()

    def test_executable_path_is_passed_through_to_consent_check(self) -> None:
        with (
            mock.patch.object(token_login, "_open_validated_executable", return_value=17) as opened,
            mock.patch.object(token_login, "_disable_dumpability"),
            mock.patch.object(token_login, "_verify_consent_disabled") as consent,
            mock.patch.object(token_login, "_run_pty_login", return_value=0),
            mock.patch.object(token_login.os, "close"),
        ):
            token_login.main(["/opt/nordvpn"])
        opened.assert_called_once_with("/opt/nordvpn")
        consent.assert_called_once_with("/opt/nordvpn")


if __name__ == "__main__":
    unittest.main()
