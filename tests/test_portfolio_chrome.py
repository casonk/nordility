"""Every page loads the portfolio top bar, which the shared Caddy serves at /_portfolio/."""

from pathlib import Path

TAG = '<script src="/_portfolio/chrome.js" defer></script>'
ROOT = Path(__file__).resolve().parents[1]
FILES = ["src/nordility/web.py"]


def test_every_page_loads_the_portfolio_top_bar():
    pages = [p for pattern in FILES for p in sorted(ROOT.glob(pattern))]
    assert pages
    for path in pages:
        text = path.read_text(encoding="utf-8")
        assert text.count("</head>") >= 1, path
        assert text.count(TAG) == text.count("</head>"), f"{path} has a page without the top bar"


def test_page_takes_its_colours_from_the_shared_theme():
    import re

    from nordility.web import INDEX_HTML

    assert '<link rel="stylesheet" href="/_portfolio/theme.css">' in INDEX_HTML
    assert '<script src="/_portfolio/theme.js"></script>' in INDEX_HTML
    style = INDEX_HTML.split("<style>")[1].split("</style>")[0]
    style = re.sub(r"var\([^)]*\)", "", style)
    lines = [ln for ln in style.splitlines() if "shadow" not in ln]
    assert re.findall(r"#[0-9a-fA-F]{3,8}\b|rgba?\(", "\n".join(lines)) == []
