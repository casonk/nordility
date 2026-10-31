#!/usr/bin/env python3
"""Regenerate src/nordility/portfolio_assets.py from traction-control's rendered theme files.

    scripts/vendor_portfolio_assets.py [DIR]    DIR defaults to ../traction-control/themes

The web service serves these as root-owned code instead of loading the user-writable shared
directory the other portfolio sites use, because this page controls a root service.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
NAMES = {
    "THEME_CSS": "portfolio-theme.css",
    "THEME_JS": "portfolio-theme.js",
    "CHROME_JS": "portfolio-chrome.js",
}


def main() -> int:
    source = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO.parent / "traction-control" / "themes"
    lines = [
        '"""Portfolio theme and top bar assets, vendored from traction-control (do not edit).',
        "",
        "Regenerate with scripts/vendor_portfolio_assets.py. Served by nordility.web from this",
        "root-owned module, so no user-writable file is ever executed on the control page.",
        '"""',
        "",
        "# ruff: noqa",
        "# fmt: off",
        "",
    ]
    for const, name in NAMES.items():
        lines.append(f"{const} = {(source / name).read_text(encoding='utf-8')!r}")
        lines.append("")
    (REPO / "src" / "nordility" / "portfolio_assets.py").write_text(
        "\n".join(lines), encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
