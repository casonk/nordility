"""The declared Python floor: source must not use names that arrived after it.

CI tests the oldest supported Python, but a developer's machine runs a newer one, so
`from datetime import UTC` (3.11+) or a bare `import tomllib` passes locally and fails
only in CI's oldest job. This reads the floor from pyproject.toml and rejects, on any
Python, what that floor does not have. It is a static check, so it is no substitute for
CI's oldest-Python job; it catches the common slips before a push.

The same file is used in every portfolio repository that declares a floor below 3.11
(template: traction-control/docs/templates/test_python_floor.py). It needs only the standard
library and reads the floor from pyproject.toml, so it is copied unchanged.
"""

from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (module, name) -> first Python version that has it.
NEW_IMPORTS = {
    ("datetime", "UTC"): (3, 11),
    ("enum", "StrEnum"): (3, 11),
    ("typing", "Self"): (3, 11),
    ("typing", "Never"): (3, 11),
    ("typing", "LiteralString"): (3, 11),
    ("typing", "assert_never"): (3, 11),
    ("typing", "assert_type"): (3, 11),
    ("typing", "reveal_type"): (3, 11),
    ("typing", "Required"): (3, 11),
    ("typing", "NotRequired"): (3, 11),
    ("typing", "Unpack"): (3, 11),
    ("typing", "TypeVarTuple"): (3, 11),
    ("asyncio", "TaskGroup"): (3, 11),
    ("asyncio", "timeout"): (3, 11),
    ("itertools", "batched"): (3, 12),
}
NEW_MODULES = {"tomllib": (3, 11)}  # fine only inside a try that falls back on ImportError
NEW_BUILTINS = {"ExceptionGroup": (3, 11), "BaseExceptionGroup": (3, 11)}
IMPORT_ERRORS = {"ImportError", "ModuleNotFoundError"}
SKIPPED_DIRS = {"node_modules", "venv", "build", "dist", "site-packages", "__pycache__"}


def python_files(root: Path) -> list[Path]:
    """Every .py file in the repository, leaving out hidden folders, environments and build output."""
    found = []
    for path in root.rglob("*.py"):
        parts = path.relative_to(root).parts[:-1]
        if any(p.startswith(".") or p in SKIPPED_DIRS or p.endswith(".egg-info") for p in parts):
            continue
        found.append(path)
    return sorted(found)


def declared_floor(pyproject: str) -> tuple[int, int] | None:
    match = re.search(r'^requires-python\s*=\s*"[^"]*?>=\s*(\d+)\.(\d+)', pyproject, re.M)
    return (int(match.group(1)), int(match.group(2))) if match else None


def _checks_python_version(test: ast.AST) -> bool:
    """True for a condition on ``sys.version_info`` (``sys.version_info >= (3, 11)`` and the like)."""
    return any(isinstance(n, ast.Attribute) and n.attr == "version_info" for n in ast.walk(test))


def _guarded(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """True if *node* is in a try that catches ImportError, or in a branch on sys.version_info."""
    child, parent = node, parents.get(node)
    while parent is not None:
        if (
            isinstance(parent, ast.If)
            and _checks_python_version(parent.test)
            and (child in parent.body or child in parent.orelse)
        ):
            return True
        if isinstance(parent, ast.Try) and child in parent.body:
            for handler in parent.handlers:
                caught = handler.type
                names = (
                    {n.id for n in ast.walk(caught) if isinstance(n, ast.Name)} if caught else set()
                )
                if caught is None or names & IMPORT_ERRORS:
                    return True
        child, parent = parent, parents.get(parent)
    return False


def violations(source: str, floor: tuple[int, int], name: str = "<source>") -> list[str]:
    """Everything in *source* that the *floor* Python does not have."""
    try:
        tree = ast.parse(source, name, feature_version=floor)
    except SyntaxError as exc:
        return [f"{name}:{exc.lineno}: syntax newer than Python {floor[0]}.{floor[1]}: {exc.msg}"]
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    found = []

    def add(node: ast.AST, what: str, since: tuple[int, int]) -> None:
        found.append(f"{name}:{node.lineno}: {what} needs Python {since[0]}.{since[1]}")

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                since = NEW_IMPORTS.get((node.module, alias.name))
                if since and since > floor:
                    add(node, f"`from {node.module} import {alias.name}`", since)
            since = NEW_MODULES.get(node.module.split(".")[0])
            if since and since > floor and not _guarded(node, parents):
                add(node, f"`from {node.module} import ...` without an ImportError fallback", since)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                since = NEW_MODULES.get(alias.name.split(".")[0])
                if since and since > floor and not _guarded(node, parents):
                    add(node, f"`import {alias.name}` without an ImportError fallback", since)
        elif (
            isinstance(node, ast.Attribute)
            and node.attr == "UTC"
            and isinstance(node.value, ast.Name)
            and node.value.id == "datetime"
            and floor < (3, 11)
        ):
            add(node, "`datetime.UTC`", (3, 11))
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            since = NEW_BUILTINS.get(node.id)
            if since and since > floor:
                add(node, f"`{node.id}`", since)
    return found


class CheckerTests(unittest.TestCase):
    """The checker has to flag the slips it exists for, and leave valid code alone."""

    floor = (3, 10)

    def test_datetime_utc_is_flagged_as_an_import_and_as_an_attribute(self):
        self.assertTrue(violations("from datetime import UTC, datetime\n", self.floor))
        self.assertTrue(violations("import datetime\nx = datetime.UTC\n", self.floor))

    def test_timezone_utc_is_fine(self):
        self.assertEqual(
            violations("from datetime import timezone\nx = timezone.utc\n", self.floor), []
        )

    def test_a_bare_tomllib_import_is_flagged_but_a_guarded_one_is_not(self):
        self.assertTrue(violations("import tomllib\n", self.floor))
        self.assertTrue(violations("from tomllib import loads\n", self.floor))
        guarded = (
            "try:\n    import tomllib\nexcept ModuleNotFoundError:\n    import tomli as tomllib\n"
        )
        self.assertEqual(violations(guarded, self.floor), [])
        tupled = "try:\n    import tomllib\nexcept (ImportError, OSError):\n    tomllib = None\n"
        self.assertEqual(violations(tupled, self.floor), [])

    def test_a_branch_on_sys_version_info_is_a_guard(self):
        branch = (
            "import sys\nif sys.version_info >= (3, 11):\n    import tomllib\nelse:\n"
            "    import tomli as tomllib\n"
        )
        self.assertEqual(violations(branch, self.floor), [])
        inverted = (
            "import sys\nif sys.version_info < (3, 11):\n    import tomli as tomllib\nelse:\n"
            "    import tomllib\n"
        )
        self.assertEqual(violations(inverted, self.floor), [])

    def test_an_if_on_something_else_is_not_a_guard(self):
        self.assertTrue(violations("if DEBUG:\n    import tomllib\n", self.floor))

    def test_a_try_that_does_not_catch_import_errors_is_not_a_guard(self):
        source = "try:\n    import tomllib\nexcept ValueError:\n    pass\n"
        self.assertTrue(violations(source, self.floor))

    def test_an_import_in_the_except_branch_is_not_covered_by_the_guard(self):
        source = "try:\n    pass\nexcept ImportError:\n    import tomllib\n"
        self.assertTrue(violations(source, self.floor))

    def test_other_names_that_arrived_after_the_floor_are_flagged(self):
        for source in (
            "from enum import StrEnum\n",
            "from typing import Self\n",
            "from itertools import batched\n",
            "raise ExceptionGroup('x', [])\n",
        ):
            with self.subTest(source=source):
                self.assertTrue(violations(source, self.floor))

    def test_syntax_newer_than_the_floor_is_flagged(self):
        self.assertTrue(violations("try:\n    pass\nexcept* ValueError:\n    pass\n", self.floor))

    def test_a_higher_floor_allows_what_it_has(self):
        self.assertEqual(violations("from datetime import UTC\nimport tomllib\n", (3, 11)), [])
        self.assertTrue(violations("from itertools import batched\n", (3, 11)))

    def test_the_declared_floor_is_read_from_pyproject(self):
        self.assertEqual(declared_floor('[project]\nrequires-python = ">=3.10"\n'), (3, 10))
        self.assertEqual(declared_floor('requires-python = ">= 3.9, <4"\n'), (3, 9))
        self.assertIsNone(declared_floor("[project]\nname = 'x'\n"))


class WalkerTests(unittest.TestCase):
    def test_environments_build_output_and_hidden_folders_are_left_out(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in (
                "pkg/a.py",
                "tests/test_a.py",
                "scripts/run.py",
                ".venv/lib/x.py",
                "venv/lib/y.py",
                "build/lib/z.py",
                ".git/hooks/h.py",
                "pkg.egg-info/w.py",
                "node_modules/n/v.py",
            ):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text("x = 1\n")
            names = [p.relative_to(root).as_posix() for p in python_files(root)]
        self.assertEqual(names, ["pkg/a.py", "scripts/run.py", "tests/test_a.py"])


class SourceTreeTests(unittest.TestCase):
    def test_nothing_in_the_repository_needs_a_newer_python_than_it_declares(self):
        floor = declared_floor((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        if floor is None:
            self.skipTest("pyproject.toml declares no requires-python")
        files = python_files(ROOT)
        self.assertTrue(files)
        problems = []
        for path in files:
            problems += violations(
                path.read_text(encoding="utf-8"), floor, str(path.relative_to(ROOT))
            )
        self.assertEqual(problems, [], f"newer than the declared Python {floor[0]}.{floor[1]}")


if __name__ == "__main__":
    unittest.main()
