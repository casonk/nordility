"""Every page loads the portfolio top bar, which the shared Caddy serves at /_portfolio/."""

from pathlib import Path

TAG = '<script src="/portfolio/chrome.js" defer></script>'
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

    assert '<link rel="stylesheet" href="/portfolio/theme.css">' in INDEX_HTML
    assert '<script src="/portfolio/theme.js"></script>' in INDEX_HTML
    style = INDEX_HTML.split("<style>")[1].split("</style>")[0]
    style = re.sub(r"var\([^)]*\)", "", style)
    lines = [ln for ln in style.splitlines() if "shadow" not in ln]
    assert re.findall(r"#[0-9a-fA-F]{3,8}\b|rgba?\(", "\n".join(lines)) == []


def test_assets_are_served_from_root_owned_code_and_the_csp_is_pinned_to_them():
    import http.client
    import threading
    from http.server import ThreadingHTTPServer
    from unittest import mock

    from nordility.web import PORTFOLIO_ASSETS, make_handler

    controller = mock.Mock()
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        make_handler(controller, trusted_origin="https://nordility.example"),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port)
        for path, (body, ctype) in PORTFOLIO_ASSETS.items():
            conn.request("GET", path)
            response = conn.getresponse()
            assert response.status == 200, path
            assert response.getheader("Content-Type") == ctype
            assert response.read().decode() == body
            policy = response.getheader("Content-Security-Policy")
            assert "script-src 'unsafe-inline' https://nordility.example/portfolio/;" in policy
            assert "style-src 'unsafe-inline' https://nordility.example/portfolio/;" in policy
            assert "_portfolio" not in policy
            assert "default-src 'none'" in policy
        conn.request("GET", "/portfolio/other.js")
        assert conn.getresponse().status == 404
    finally:
        server.shutdown()
        server.server_close()


def test_vendored_assets_match_traction_control_when_it_is_next_door():
    from nordility import portfolio_assets

    source = ROOT.parent / "traction-control" / "themes"
    if not source.is_dir():
        return
    for const, name in (
        ("THEME_CSS", "portfolio-theme.css"),
        ("THEME_JS", "portfolio-theme.js"),
        ("CHROME_JS", "portfolio-chrome.js"),
    ):
        assert getattr(portfolio_assets, const) == (source / name).read_text(encoding="utf-8"), name


def test_runtime_staging_includes_the_assets_module():
    script = (ROOT / "scripts" / "lib" / "install_runtime.sh").read_text(encoding="utf-8")
    assert '"portfolio_assets.py"' in script
