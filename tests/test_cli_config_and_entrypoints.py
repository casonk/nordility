"""Repo-local auto-pass config loading, the module entry point and the vendoring script."""

from __future__ import annotations

import importlib.util
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from nordility import cli
from nordility.client import DEFAULT_KEEPASS_ENTRY, DEFAULT_KEEPASS_PROFILE, NordilityError

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "vendor_portfolio_assets.py"


class AutoPassConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "auto-pass.ini"
        patcher = mock.patch.object(cli, "_AUTO_PASS_CONFIG_PATH", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_missing_file_means_built_in_defaults(self) -> None:
        self.assertEqual(cli._load_repo_auto_pass_config(), {})
        self.assertEqual(
            cli._resolve_keepass_defaults(), (DEFAULT_KEEPASS_PROFILE, DEFAULT_KEEPASS_ENTRY)
        )

    def test_profile_and_entry_are_read_and_trimmed(self) -> None:
        self.path.write_text(
            "[auto_pass]\nprofile =  my-profile \n[nordility]\nkeepass_entry = vpn/x#tok \n"
        )
        self.assertEqual(
            cli._load_repo_auto_pass_config(),
            {"profile": "my-profile", "keepass_entry": "vpn/x#tok"},
        )
        self.assertEqual(cli._resolve_keepass_defaults(), ("my-profile", "vpn/x#tok"))

    def test_blank_values_and_missing_sections_fall_back_per_field(self) -> None:
        self.path.write_text("[auto_pass]\nprofile =   \n")
        self.assertEqual(cli._load_repo_auto_pass_config(), {})
        self.path.write_text("[nordility]\nkeepass_entry = only/entry\n")
        self.assertEqual(cli._resolve_keepass_defaults(), (DEFAULT_KEEPASS_PROFILE, "only/entry"))
        self.path.write_text("[auto_pass]\nprofile = p\n")
        self.assertEqual(cli._resolve_keepass_defaults(), ("p", DEFAULT_KEEPASS_ENTRY))

    def test_percent_signs_are_literal_not_interpolated(self) -> None:
        self.path.write_text("[nordility]\nkeepass_entry = vpn/100%done\n")
        self.assertEqual(cli._load_repo_auto_pass_config()["keepass_entry"], "vpn/100%done")

    def test_keys_keep_their_case(self) -> None:
        self.path.write_text("[nordility]\nKeepass_Entry = x\n")
        self.assertEqual(cli._load_repo_auto_pass_config(), {})

    def test_malformed_or_unreadable_config_is_a_clean_error(self) -> None:
        self.path.write_text("no section header\n")
        with self.assertRaisesRegex(NordilityError, "invalid config/auto-pass.ini"):
            cli._load_repo_auto_pass_config()
        self.path.write_bytes(b"\xff\xfe[bad]\n")
        with self.assertRaisesRegex(NordilityError, "invalid config/auto-pass.ini"):
            cli._load_repo_auto_pass_config()

    def test_unreadable_config_path_is_a_clean_error(self) -> None:
        self.path.mkdir()
        with self.assertRaisesRegex(NordilityError, "invalid config/auto-pass.ini"):
            cli._load_repo_auto_pass_config()

    def test_parser_defaults_come_from_the_config(self) -> None:
        self.path.write_text("[auto_pass]\nprofile = p1\n[nordility]\nkeepass_entry = e1\n")
        args = cli.build_parser().parse_args(["login"])
        self.assertEqual((args.keepass_profile, args.keepass_entry), ("p1", "e1"))
        args = cli.build_parser().parse_args(["login", "--keepass-entry", "cli"])
        self.assertEqual(args.keepass_entry, "cli")


class EntryPointTests(unittest.TestCase):
    def test_module_execution_exits_with_the_cli_status(self) -> None:
        for code in (0, 1):
            with (
                self.subTest(code=code),
                mock.patch.object(cli, "main", return_value=code),
                mock.patch.object(sys, "argv", ["nordility"]),
                self.assertRaises(SystemExit) as ctx,
            ):
                runpy.run_module("nordility", run_name="__main__")
            self.assertEqual(ctx.exception.code, code)

    def test_importing_the_module_does_not_run_the_cli(self) -> None:
        with mock.patch.object(cli, "main") as main:
            runpy.run_module("nordility.__main__", run_name="not_main")
        main.assert_not_called()


class VendorScriptTests(unittest.TestCase):
    def load(self):
        spec = importlib.util.spec_from_file_location("vendor_portfolio_assets_under_test", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def make_source(self, root: Path) -> dict[str, str]:
        contents = {
            "portfolio-theme.css": "body { color: var(--text); }\n'quoted' \"double\"\n",
            "portfolio-theme.js": "console.log('théme');\n",
            "portfolio-chrome.js": "var x = 1;\\n\n",
        }
        for name, text in contents.items():
            (root / name).write_text(text, encoding="utf-8")
        return contents

    def test_generates_an_importable_module_with_the_exact_contents(self) -> None:
        module = self.load()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "themes"
            source.mkdir()
            contents = self.make_source(source)
            (root / "src" / "nordility").mkdir(parents=True)
            module.REPO = root
            with mock.patch.object(sys, "argv", ["vendor", str(source)]):
                self.assertEqual(module.main(), 0)
            generated = root / "src" / "nordility" / "portfolio_assets.py"
            text = generated.read_text(encoding="utf-8")
            namespace: dict[str, str] = {}
            exec(compile(text, str(generated), "exec"), namespace)  # noqa: S102
        self.assertEqual(namespace["THEME_CSS"], contents["portfolio-theme.css"])
        self.assertEqual(namespace["THEME_JS"], contents["portfolio-theme.js"])
        self.assertEqual(namespace["CHROME_JS"], contents["portfolio-chrome.js"])
        self.assertIn("do not edit", text)
        self.assertIn("vendor_portfolio_assets.py", text)

    def test_default_source_is_the_sibling_traction_control_themes(self) -> None:
        module = self.load()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "nordility"
            themes = Path(raw) / "traction-control" / "themes"
            themes.mkdir(parents=True)
            self.make_source(themes)
            (root / "src" / "nordility").mkdir(parents=True)
            module.REPO = root
            with mock.patch.object(sys, "argv", ["vendor"]):
                self.assertEqual(module.main(), 0)
            self.assertTrue((root / "src" / "nordility" / "portfolio_assets.py").exists())

    def test_missing_source_file_fails_without_writing_a_partial_module(self) -> None:
        module = self.load()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "themes"
            source.mkdir()
            (source / "portfolio-theme.css").write_text("x")
            (root / "src" / "nordility").mkdir(parents=True)
            module.REPO = root
            with mock.patch.object(sys, "argv", ["vendor", str(source)]):
                with self.assertRaises(FileNotFoundError):
                    module.main()
            self.assertFalse((root / "src" / "nordility" / "portfolio_assets.py").exists())

    def test_vendored_module_in_the_repo_matches_the_generator_format(self) -> None:
        from nordility import portfolio_assets

        for name in ("THEME_CSS", "THEME_JS", "CHROME_JS"):
            self.assertIsInstance(getattr(portfolio_assets, name), str)
            self.assertTrue(getattr(portfolio_assets, name))


if __name__ == "__main__":
    unittest.main()
