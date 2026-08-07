from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = (
    "install_wireguard_watch_service.sh",
    "install_autoconnect_service.sh",
    "install_web_service.sh",
)


class ServiceInstallerRenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bash = shutil.which("bash")
        if cls.bash is None:
            raise unittest.SkipTest("bash is required for service installer tests")

    def render(self, script_name: str, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                self.bash,
                str(REPO_ROOT / "scripts" / script_name),
                "--render-only",
                "--python-bin",
                "/usr/bin/python3",
                *args,
            ],
            cwd=REPO_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_every_unit_uses_only_the_protected_runtime(self) -> None:
        for script_name in SCRIPTS:
            with self.subTest(script=script_name):
                result = self.render(script_name)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
                self.assertIn("WorkingDirectory=/opt/nordility\n", result.stdout)
                self.assertIn("Environment=PYTHONPATH=/opt/nordility/src\n", result.stdout)
                self.assertIn("Environment=PYTHONDONTWRITEBYTECODE=1\n", result.stdout)
                self.assertIn("ExecStart=/usr/bin/python3 -m nordility ", result.stdout)
                self.assertNotIn(str(REPO_ROOT), result.stdout)
                self.assertNotIn("Documentation=file://", result.stdout)

    def test_watch_render_preserves_service_arguments(self) -> None:
        result = self.render(
            "install_wireguard_watch_service.sh",
            "--interval",
            "11",
            "--stabilize-wait",
            "3",
            "--wireguard-interface",
            "wg-mesh",
            "--wireguard-fwmark",
            "52000",
            "--ip-rule-priority",
            "101",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "watch-wireguard --interval 11 --stabilize-wait 3 "
            "--wireguard-interface wg-mesh --wireguard-fwmark 52000 "
            "--ip-rule-priority 101",
            result.stdout,
        )

    def test_autoconnect_render_preserves_service_arguments(self) -> None:
        result = self.render(
            "install_autoconnect_service.sh",
            "--group",
            "Japan",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("connect --group Japan", result.stdout)
        self.assertNotIn("--auto-login", result.stdout)
        self.assertNotIn("keepass", result.stdout.lower())

    def test_web_render_preserves_service_arguments(self) -> None:
        result = self.render(
            "install_web_service.sh",
            "--trusted-origin",
            "https://nordility.mesh.example",
            "--wireguard-interface",
            "wg-mesh",
            "--wireguard-fwmark",
            "52000",
            "--ip-rule-priority",
            "101",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "web --unix-socket /run/nordility/web.sock "
            "--trusted-origin https://nordility.mesh.example "
            "--wireguard-interface wg-mesh "
            "--wireguard-fwmark 52000 --ip-rule-priority 101",
            result.stdout,
        )
        self.assertIn("Group=caddy", result.stdout)
        self.assertIn("RuntimeDirectory=nordility", result.stdout)
        self.assertIn("RuntimeDirectoryMode=0750", result.stdout)
        self.assertIn("UMask=0007", result.stdout)
        self.assertNotIn("--host", result.stdout)
        self.assertNotIn("--auto-login", result.stdout)

    def test_root_service_installers_reject_auto_login_options(self) -> None:
        for script_name in (
            "install_autoconnect_service.sh",
            "install_web_service.sh",
        ):
            with self.subTest(script=script_name):
                result = self.render(script_name, "--auto-login")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unknown argument: --auto-login", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_render_rejects_multiline_unit_values(self) -> None:
        result = self.render(
            "install_web_service.sh",
            "--trusted-origin",
            "https://nordility.example\nEnvironment=INJECTED=1",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("trusted web origin must be a single line", result.stderr)
        self.assertEqual(result.stdout, "")


class ServiceRuntimeAllowlistTests(unittest.TestCase):
    def test_runtime_allowlist_tracks_every_package_module(self) -> None:
        helper = (REPO_ROOT / "scripts" / "lib" / "install_runtime.sh").read_text()
        package_modules = sorted(
            path.name for path in (REPO_ROOT / "src" / "nordility").glob("*.py")
        )

        for module_name in package_modules:
            with self.subTest(module=module_name):
                self.assertIn(f'  "{module_name}"', helper)

    def test_every_real_installer_stages_and_pins_its_runtime(self) -> None:
        for script_name in SCRIPTS:
            with self.subTest(script=script_name):
                script = (REPO_ROOT / "scripts" / script_name).read_text()
                self.assertIn('PYTHON_BIN="$(nordility_secure_python', script)
                self.assertIn('nordility_stage_runtime "${REPO_ROOT}"', script)


if __name__ == "__main__":
    unittest.main()
