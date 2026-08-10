"""Linux-only NordVPN token handoff through its no-echo terminal prompt.

The parent passes the token over a private stdin pipe. This broker becomes
non-dumpable, starts ``nordvpn login --token`` without a positional token in a
pseudoterminal, waits for NordVPN 5.2's exact prompt and no-echo terminal state,
and only then forwards the token. The credential never enters process argv,
the environment, logs, or captured child output.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import os
import pty
import resource
import select
import signal
import stat
import subprocess
import sys
import termios
import time
from typing import NoReturn

PR_SET_DUMPABLE = 4
TOKEN_MINIMUM = 1
TOKEN_MAXIMUM = 1024
PROMPT = b"Enter access token: "
PROMPT_TIMEOUT_SECONDS = 30.0
LOGIN_TIMEOUT_SECONDS = 90.0
CONSENT_TIMEOUT_SECONDS = 10.0


def _fail(message: str) -> NoReturn:
    print(f"nordility-token-login: {message}", file=sys.stderr)
    raise SystemExit(1)


def _disable_dumpability() -> None:
    if not sys.platform.startswith("linux"):
        _fail("secure token handoff is supported only on Linux")
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (OSError, ValueError):
        _fail("could not disable core dumps")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        _fail("could not disable process dumpability")


def _open_validated_executable(raw_path: str) -> int:
    if not os.path.isabs(raw_path):
        _fail("NordVPN executable must be an absolute path")
    try:
        descriptor = os.open(raw_path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        _fail("could not open the NordVPN executable without following symlinks")
    try:
        metadata = os.fstat(descriptor)
    except OSError:
        os.close(descriptor)
        _fail("could not inspect the NordVPN executable")
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        _fail("NordVPN executable must be a regular file")
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        os.close(descriptor)
        _fail("NordVPN executable must be root-owned and not group/world writable")
    if not metadata.st_mode & 0o111:
        os.close(descriptor)
        _fail("NordVPN executable is not executable")
    return descriptor


def _read_token() -> bytearray:
    raw = bytearray(sys.stdin.buffer.read(TOKEN_MAXIMUM + 3))
    if len(raw) > TOKEN_MAXIMUM + 2:
        _wipe(raw)
        _fail("token is too large")
    while raw and raw[-1] in b"\r\n":
        raw.pop()
    if not TOKEN_MINIMUM <= len(raw) <= TOKEN_MAXIMUM:
        _wipe(raw)
        _fail("token has an invalid size")
    if any(byte < 0x21 or byte > 0x7E for byte in raw):
        _wipe(raw)
        _fail("token contains whitespace, controls, or non-ASCII bytes")
    return raw


def _wipe(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


def _spawn_cli(executable_fd: int) -> tuple[int, int]:
    pid, master_fd = pty.fork()
    if pid == 0:  # pragma: no cover - replaces the child process
        try:
            os.execve(
                executable_fd,
                ["nordvpn", "login", "--token"],
                {
                    "HOME": os.environ.get("HOME", "/root"),
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C.UTF-8",
                    "TERM": "dumb",
                    "NO_COLOR": "1",
                },
            )
        except OSError:
            os._exit(127)
    return pid, master_fd


def _child_exited(pid: int) -> bool:
    result = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    return result is not None


def _read_available(master_fd: int, timeout: float) -> bytes:
    readable, _, _ = select.select([master_fd], [], [], max(0.0, timeout))
    if not readable:
        return b""
    try:
        return os.read(master_fd, 4096)
    except OSError:
        return b""


def _wait_for_hidden_prompt(pid: int, master_fd: int) -> None:
    deadline = time.monotonic() + PROMPT_TIMEOUT_SECONDS
    observed = bytearray()
    while time.monotonic() < deadline:
        chunk = _read_available(master_fd, min(0.1, deadline - time.monotonic()))
        if chunk:
            observed.extend(chunk)
            del observed[:-4096]
        if _child_exited(pid):
            _fail("NordVPN exited before its secure token prompt")
        if PROMPT not in observed:
            continue

        # The prompt is printed just before x/term disables echo. Poll the PTY
        # state rather than writing immediately and racing that transition.
        while time.monotonic() < deadline:
            attributes = termios.tcgetattr(master_fd)
            if not attributes[3] & (termios.ECHO | termios.ECHONL):
                return
            _read_available(master_fd, 0.01)
            if _child_exited(pid):
                _fail("NordVPN exited before disabling terminal echo")
        break
    _fail("NordVPN did not present a no-echo token prompt in time")


def _write_all(descriptor: int, payload: bytes | bytearray) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            _fail("could not write the token to NordVPN's secure prompt")
        view = view[written:]


def _wait_for_login(pid: int, master_fd: int) -> int:
    deadline = time.monotonic() + LOGIN_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        # Child output is intentionally drained and discarded after handoff.
        _read_available(master_fd, min(0.1, deadline - time.monotonic()))
        if _child_exited(pid):
            _, status = os.waitpid(pid, 0)
            return os.waitstatus_to_exitcode(status)
    _fail("NordVPN token login timed out")


def _terminate_child(pid: int) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pid, signal.SIGKILL)
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGKILL)
    with contextlib.suppress(ChildProcessError):
        os.waitpid(pid, 0)


def _verify_consent_disabled(executable: str) -> None:
    environment = {
        "HOME": os.environ.get("HOME", "/root"),
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "TERM": "dumb",
        "NO_COLOR": "1",
    }
    try:
        subprocess.run(
            [executable, "set", "analytics", "off"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=CONSENT_TIMEOUT_SECONDS,
            env=environment,
        )
        settings = subprocess.run(
            [executable, "settings"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=CONSENT_TIMEOUT_SECONDS,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail("could not establish the non-interactive NordVPN consent setting")
    if settings.returncode != 0 or "User Consent: disabled" not in settings.stdout.splitlines():
        _fail("NordVPN user consent is not disabled")


def _run_pty_login(executable_fd: int) -> int:
    pid, master_fd = _spawn_cli(executable_fd)
    child_reaped = False
    try:
        _wait_for_hidden_prompt(pid, master_fd)
        token = _read_token()
        try:
            _write_all(master_fd, token)
            _write_all(master_fd, b"\n")
        finally:
            _wipe(token)
        exit_code = _wait_for_login(pid, master_fd)
        child_reaped = True
        if exit_code != 0:
            _fail(f"NordVPN token login failed with exit code {exit_code}")
        return 0
    finally:
        os.close(master_fd)
        if not child_reaped:
            _terminate_child(pid)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("executable")
    args = parser.parse_args(argv)

    executable_fd = _open_validated_executable(args.executable)
    try:
        _disable_dumpability()
        _verify_consent_disabled(args.executable)
        return _run_pty_login(executable_fd)
    finally:
        os.close(executable_fd)


if __name__ == "__main__":
    raise SystemExit(main())
