from unittest import TestCase, mock

from nordility import change_vpn_server, connect_vpn_server, disconnect_vpn_server
from nordility.client import CommandResult, NordilityError


class HelperTests(TestCase):
    @mock.patch("nordility.client.NordVPNClient")
    def test_connect_vpn_server_returns_string_and_result(self, mock_client_cls) -> None:
        mock_client = mock_client_cls.return_value
        result = CommandResult(command=("cmd",), message="VPN Connected", returncode=0)
        mock_client.connect.return_value = result

        self.assertEqual(connect_vpn_server(), "VPN Connected")
        self.assertIs(connect_vpn_server(status=False), result)
        mock_client.connect.assert_called()

    @mock.patch("nordility.client.NordVPNClient")
    def test_connect_vpn_server_handles_failure(self, mock_client_cls) -> None:
        mock_client_cls.return_value.connect.side_effect = NordilityError("boom")

        self.assertEqual(connect_vpn_server(), "VPN Failed to Connect")
        with self.assertRaises(NordilityError):
            connect_vpn_server(status=False)

    @mock.patch("nordility.client.NordVPNClient")
    def test_change_vpn_server_returns_message(self, mock_client_cls) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.change.return_value = CommandResult(
            command=("cmd",),
            message="VPN Connection Successfully Redirected to United_States",
            returncode=0,
        )

        self.assertIn("VPN Connection Successfully Redirected", change_vpn_server())

    @mock.patch("nordility.client.NordVPNClient")
    def test_disconnect_vpn_server_returns_string(self, mock_client_cls) -> None:
        mock_client = mock_client_cls.return_value
        mock_client.disconnect.return_value = CommandResult(
            command=("cmd",), message="VPN Disconnected", returncode=0
        )

        self.assertEqual(disconnect_vpn_server(), "VPN Disconnected")
        self.assertIs(disconnect_vpn_server(status=False), mock_client.disconnect.return_value)
