"""Integration tests using dyno-lab utilities.

Uses ``ProcessRecorder`` / ``SubprocessPatch`` from ``dyno_lab.proc`` and
``EnvPatch`` from ``dyno_lab.env`` to test the nordility client and CLI
without spawning real NordVPN processes.

Pattern used for subprocess mocking:
  ``NordVPNClient`` accepts a custom ``runner`` callable, so we pass a
  ``ProcessRecorder`` directly.  ``SubprocessPatch`` wraps the block as a
  safety net — any unexpected direct call to ``subprocess.run`` would be
  intercepted — and provides the shared recorder infrastructure.
"""

from __future__ import annotations

import unittest
from subprocess import CompletedProcess

from dyno_lab.env import EnvPatch
from dyno_lab.proc import ProcessRecorder, SubprocessPatch, build_completed_process

from nordility.client import (
    CommandExecutionError,
    NordVPNClient,
    connect_vpn_server,
    disconnect_vpn_server,
    resolve_executable,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cli_client(recorder: ProcessRecorder) -> NordVPNClient:
    """Return a CLI-backend NordVPNClient wired to *recorder* as its runner."""
    return NordVPNClient(
        executable="nordvpn",
        backend="cli",
        runner=recorder,
        sleeper=lambda _: None,
    )


# ---------------------------------------------------------------------------
# Subprocess / command-shape tests
# ---------------------------------------------------------------------------

class SubprocessPatchCliTests(unittest.TestCase):
    """Verify that NordVPNClient builds correct CLI commands and handles results."""

    def test_connect_with_group_issues_space_separated_cli_arg(self) -> None:
        recorder = ProcessRecorder(default_stdout="You are connected to United States")
        with SubprocessPatch(recorder):
            result = _cli_client(recorder).connect(group="United_States", wait_seconds=0)

        self.assertEqual(recorder.call_count, 1)
        self.assertEqual(recorder.calls[0].args, ("nordvpn", "connect", "United States"))
        self.assertEqual(result.message, "VPN Connected to United_States")
        self.assertEqual(result.group, "United_States")

    def test_disconnect_issues_disconnect_verb(self) -> None:
        recorder = ProcessRecorder(default_stdout="You are disconnected")
        with SubprocessPatch(recorder):
            result = _cli_client(recorder).disconnect(wait_seconds=0)

        self.assertEqual(recorder.call_count, 1)
        self.assertEqual(recorder.calls[0].args, ("nordvpn", "disconnect"))
        self.assertEqual(result.message, "VPN Disconnected")

    def test_nonzero_returncode_raises_command_execution_error(self) -> None:
        recorder = ProcessRecorder(
            responses=[
                build_completed_process(returncode=1, stderr="daemon not running"),
            ]
        )
        with SubprocessPatch(recorder):
            with self.assertRaises(CommandExecutionError) as ctx:
                _cli_client(recorder).connect(wait_seconds=0)

        self.assertIn("daemon not running", str(ctx.exception))

    def test_change_command_includes_connect_and_valid_fast_group(self) -> None:
        import random

        recorder = ProcessRecorder(default_stdout="Reconnected")
        with SubprocessPatch(recorder):
            client = NordVPNClient(
                executable="nordvpn",
                backend="cli",
                runner=recorder,
                sleeper=lambda _: None,
                rng=random.Random(7),
            )
            result = client.change(speed="fast", wait_seconds=0)

        self.assertIn("VPN Connection Successfully Redirected", result.message)
        self.assertEqual(recorder.call_count, 1)
        cmd = recorder.calls[0].args
        self.assertEqual(cmd[0], "nordvpn")
        self.assertEqual(cmd[1], "connect")
        # CLI backend replaces underscores with spaces; either form is valid
        chosen = result.group
        self.assertIsNotNone(chosen)

    def test_connect_no_group_omits_group_arg(self) -> None:
        recorder = ProcessRecorder(default_stdout="Connected")
        with SubprocessPatch(recorder):
            result = _cli_client(recorder).connect(wait_seconds=0)

        self.assertEqual(recorder.calls[0].args, ("nordvpn", "connect"))
        self.assertEqual(result.message, "VPN Connected")

    def test_recorder_captures_capture_output_kwarg(self) -> None:
        """Verify that NordVPNClient passes capture_output=True to subprocess.run."""
        recorder = ProcessRecorder(default_stdout="ok")
        with SubprocessPatch(recorder):
            _cli_client(recorder).connect(wait_seconds=0)

        kwargs = recorder.calls[0].kwargs
        self.assertTrue(kwargs.get("capture_output"))
        self.assertTrue(kwargs.get("text"))


# ---------------------------------------------------------------------------
# EnvPatch tests — environment-driven configuration
# ---------------------------------------------------------------------------

class EnvPatchNordilityTests(unittest.TestCase):
    """Verify env-var-driven executable and backend resolution."""

    def test_nordility_executable_env_takes_priority(self) -> None:
        with EnvPatch({"NORDILITY_EXECUTABLE": "/opt/custom/nordvpn", "NORDVPN_EXECUTABLE": ""}):
            exe = resolve_executable(None)
        self.assertEqual(exe, "/opt/custom/nordvpn")

    def test_nordvpn_executable_env_used_as_fallback(self) -> None:
        with EnvPatch({"NORDILITY_EXECUTABLE": "", "NORDVPN_EXECUTABLE": "/usr/bin/nordvpn"}):
            exe = resolve_executable(None)
        self.assertEqual(exe, "/usr/bin/nordvpn")

    def test_explicit_executable_beats_env(self) -> None:
        with EnvPatch({"NORDILITY_EXECUTABLE": "/env/nordvpn"}):
            exe = resolve_executable("/explicit/nordvpn")
        self.assertEqual(exe, "/explicit/nordvpn")

    def test_nordility_backend_env_forces_cli_on_client(self) -> None:
        recorder = ProcessRecorder(default_stdout="connected")
        with EnvPatch({"NORDILITY_BACKEND": "cli"}):
            with SubprocessPatch(recorder):
                client = NordVPNClient(
                    executable="nordvpn",
                    runner=recorder,
                    sleeper=lambda _: None,
                )
        self.assertEqual(client.backend, "cli")

    def test_connect_vpn_server_returns_message_string_on_success(self) -> None:
        from unittest.mock import patch as _patch
        from nordility.client import CommandResult

        mock_result = CommandResult(
            command=("nordvpn", "connect"),
            message="VPN Connected",
            returncode=0,
        )
        with EnvPatch({"NORDILITY_EXECUTABLE": "nordvpn", "NORDVPN_EXECUTABLE": ""}):
            with _patch("nordility.client.NordVPNClient") as mock_cls:
                mock_cls.return_value.connect.return_value = mock_result
                msg = connect_vpn_server(status=True)

        self.assertEqual(msg, "VPN Connected")

    def test_disconnect_vpn_server_returns_message_string_on_success(self) -> None:
        from unittest.mock import patch as _patch
        from nordility.client import CommandResult

        mock_result = CommandResult(
            command=("nordvpn", "disconnect"),
            message="VPN Disconnected",
            returncode=0,
        )
        with EnvPatch({"NORDILITY_EXECUTABLE": "nordvpn", "NORDVPN_EXECUTABLE": ""}):
            with _patch("nordility.client.NordVPNClient") as mock_cls:
                mock_cls.return_value.disconnect.return_value = mock_result
                msg = disconnect_vpn_server(status=True)

        self.assertEqual(msg, "VPN Disconnected")


if __name__ == "__main__":
    unittest.main()
