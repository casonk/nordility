import io
import sys
from unittest import mock
from unittest import TestCase

from nordility.cli import main
from nordility.client import CommandResult, NordilityError


class CLITests(TestCase):
    @mock.patch("nordility.cli.NordVPNClient")
    def test_connect_prints_success(self, mock_client_cls) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.connect.return_value = CommandResult(
            command=("nordvpn", "connect"),
            message="VPN Connected",
            returncode=0,
        )

        stdout = io.StringIO()
        with mock.patch("sys.stdout", new=stdout):
            exit_code = main(["connect"])

        self.assertEqual(exit_code, 0)
        self.assertIn("VPN Connected", stdout.getvalue())
        mock_client.connect.assert_called_once_with(
            group=None, wait_seconds=0, auto_login=False, keepass_entry="Nord_VPN"
        )

    @mock.patch("nordility.cli.NordVPNClient")
    def test_list_groups_prints_pool(self, mock_client_cls) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.list_groups.return_value = ("United_States", "Japan")

        stdout = io.StringIO()
        with mock.patch("sys.stdout", new=stdout):
            exit_code = main(["list-groups"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout.getvalue().splitlines(), ["United_States", "Japan"])
        mock_client.list_groups.assert_called_once_with(speed="fast")

    @mock.patch("nordility.cli.NordVPNClient")
    def test_prints_error_and_exits_nonzero(self, mock_client_cls) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.connect.side_effect = NordilityError("boom")

        stderr = io.StringIO()
        with mock.patch("sys.stderr", new=stderr):
            exit_code = main(["connect"])

        self.assertEqual(exit_code, 1)
        self.assertIn("boom", stderr.getvalue())

    @mock.patch("nordility.cli.NordVPNClient")
    def test_login_subcommand_calls_login(self, mock_client_cls) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.login.return_value = CommandResult(
            command=("nordvpn", "login", "--token", "tok"),
            message="NordVPN Logged In",
            returncode=0,
        )

        stdout = io.StringIO()
        with mock.patch("sys.stdout", new=stdout):
            exit_code = main(["login", "--token", "tok"])

        self.assertEqual(exit_code, 0)
        self.assertIn("NordVPN Logged In", stdout.getvalue())
        mock_client.login.assert_called_once_with(token="tok", keepass_entry=None)

    @mock.patch("nordility.cli.NordVPNClient")
    def test_login_subcommand_defaults_to_keepass_entry(self, mock_client_cls) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.login.return_value = CommandResult(
            command=("nordvpn", "login", "--token", "tok"),
            message="NordVPN Logged In",
            returncode=0,
        )

        main(["login"])

        mock_client.login.assert_called_once_with(token=None, keepass_entry="Nord_VPN")

    @mock.patch("nordility.cli.NordVPNClient")
    def test_connect_passes_auto_login_flag(self, mock_client_cls) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.connect.return_value = CommandResult(
            command=("nordvpn", "connect"),
            message="VPN Connected",
            returncode=0,
        )

        main(["connect", "--auto-login"])

        mock_client.connect.assert_called_once_with(
            group=None, wait_seconds=0, auto_login=True, keepass_entry="Nord_VPN"
        )
