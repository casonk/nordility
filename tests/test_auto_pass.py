from __future__ import annotations

import importlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

DYNO_LAB_SRC = Path(__file__).resolve().parents[2] / "dyno-lab" / "src"
if str(DYNO_LAB_SRC) not in sys.path:
    sys.path.insert(0, str(DYNO_LAB_SRC))
for module_name in [
    name for name in sys.modules if name == "dyno_lab" or name.startswith("dyno_lab.")
]:
    del sys.modules[module_name]

auto_pass = importlib.import_module("dyno_lab.auto_pass")

from nordility.client import _resolve_keepass_token  # noqa: E402

AutoPassPatch = auto_pass.AutoPassPatch
AutoPassRecorder = auto_pass.AutoPassRecorder


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

        with tempfile.TemporaryDirectory() as temp_dir:
            auto_pass_root = Path(temp_dir)
            env_path = auto_pass_root / "config" / "auto-pass.env.local"
            env_path.parent.mkdir(parents=True, exist_ok=True)
            env_path.write_text("# test env\n", encoding="utf-8")

            with (
                AutoPassPatch(recorder),
                mock.patch("nordility.client._AUTO_PASS_ROOT", auto_pass_root),
            ):
                token = _resolve_keepass_token("provider#access-token", "work")

        self.assertEqual(token, "vpn-token-123")
        self.assertEqual(recorder.load_calls[0].profile, "work")
        self.assertEqual(Path(recorder.load_calls[0].path), env_path)
        self.assertEqual(
            [call.entry for call in recorder.resolve_calls],
            ["provider#access-token", "nordvpn/provider#access-token"],
        )
        self.assertEqual(recorder.resolve_calls[0].attrs_map, {"token": "password"})


if __name__ == "__main__":
    unittest.main()
