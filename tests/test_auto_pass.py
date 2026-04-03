from __future__ import annotations

import sys
import unittest
from pathlib import Path

DYNO_LAB_SRC = Path(__file__).resolve().parents[2] / "dyno-lab" / "src"
if str(DYNO_LAB_SRC) not in sys.path:
    sys.path.insert(0, str(DYNO_LAB_SRC))

from dyno_lab.auto_pass import AutoPassPatch, AutoPassRecorder
from nordility.client import _resolve_keepass_token


class NordilityAutoPassTests(unittest.TestCase):
    def test_resolve_keepass_token_loads_profile_and_falls_back_to_prefixed_entry(self) -> None:
        recorder = AutoPassRecorder()
        recorder.add_response(
            "provider#access-token",
            recorder.keepass_error("Entry provider#access-token was not found."),
        )
        recorder.add_response(
            "nordvpn/provider#access-token",
            {"token": "vpn-token-123"},
        )

        with AutoPassPatch(recorder):
            token = _resolve_keepass_token("provider#access-token", "work")

        self.assertEqual(token, "vpn-token-123")
        self.assertEqual(recorder.load_calls[0].profile, "work")
        self.assertTrue(str(recorder.load_calls[0].path).endswith("auto-pass/config/auto-pass.env.local"))
        self.assertEqual(
            [call.entry for call in recorder.resolve_calls],
            ["provider#access-token", "nordvpn/provider#access-token"],
        )
        self.assertEqual(recorder.resolve_calls[0].attrs_map, {"token": "password"})


if __name__ == "__main__":
    unittest.main()
