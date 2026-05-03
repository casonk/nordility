from __future__ import annotations

import argparse
import json
import logging
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .client import (
    DEFAULT_KEEPASS_ENTRY,
    DEFAULT_KEEPASS_PROFILE,
    DEFAULT_WIREGUARD_FWMARK,
    DEFAULT_WIREGUARD_INTERFACES,
    DEFAULT_WIREGUARD_IP_RULE_PRIORITY,
    FULL_GROUPS,
    GROUPS_BY_SPEED,
    CommandResult,
    ConfigurationError,
    NordilityError,
    NordVPNClient,
    WireGuardRestoreSummary,
    restore_wireguard_after_nordvpn,
)

LOGGER = logging.getLogger("nordility.web")

DEFAULT_WEB_HOST = "127.0.0.1"
DEFAULT_WEB_PORT = 5300
_PUBLIC_INFO_TTL = 60.0
_PUBLIC_INFO_URL = "https://ipinfo.io/json"


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Nordility</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #f5f7f8;
      --panel: #ffffff;
      --text: #162027;
      --muted: #5b6871;
      --line: #d7dde1;
      --primary: #145a78;
      --primary-text: #ffffff;
      --danger: #a03030;
      --ok: #2d6a4f;
      --shadow: 0 1px 2px rgba(22, 32, 39, 0.08);
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #101519;
        --panel: #172027;
        --text: #edf2f4;
        --muted: #a7b3bc;
        --line: #2d3a43;
        --primary: #4ca3c7;
        --primary-text: #071116;
        --danger: #d56b6b;
        --ok: #74c69d;
        --shadow: none;
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
    }
    main {
      width: min(760px, 100%);
      margin: 0 auto;
      padding: 16px;
    }
    header {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
      padding: 8px 0 14px;
    }
    h1 {
      margin: 0;
      font-size: 1.45rem;
      letter-spacing: 0;
    }
    .timestamp {
      color: var(--muted);
      font-size: .86rem;
      white-space: nowrap;
    }
    section {
      background: var(--panel);
      border: 1px solid var(--line);
      box-shadow: var(--shadow);
      border-radius: 8px;
      padding: 14px;
      margin: 12px 0;
    }
    h2 {
      margin: 0 0 10px;
      font-size: 1rem;
      letter-spacing: 0;
    }
    .status-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }
    .metric {
      min-height: 64px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px;
      overflow: hidden;
    }
    .metric label {
      display: block;
      color: var(--muted);
      font-size: .75rem;
      text-transform: uppercase;
      margin-bottom: 5px;
    }
    .metric div {
      font-size: .98rem;
      overflow-wrap: anywhere;
    }
    .state-connected { color: var(--ok); font-weight: 650; }
    .state-disconnected { color: var(--danger); font-weight: 650; }
    .controls {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }
    .full { grid-column: 1 / -1; }
    button, select {
      width: 100%;
      min-height: 44px;
      border-radius: 6px;
      border: 1px solid var(--line);
      background: var(--panel);
      color: var(--text);
      font: inherit;
    }
    button {
      font-weight: 650;
      cursor: pointer;
    }
    button.primary {
      background: var(--primary);
      border-color: var(--primary);
      color: var(--primary-text);
    }
    button.danger {
      color: var(--danger);
    }
    button:disabled {
      opacity: .55;
      cursor: wait;
    }
    .row {
      display: flex;
      gap: 10px;
    }
    .row > * { flex: 1; }
    pre {
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      margin: 0;
      color: var(--muted);
      font-size: .86rem;
      line-height: 1.35;
    }
    .message {
      min-height: 24px;
      color: var(--muted);
      overflow-wrap: anywhere;
    }
    @media (max-width: 520px) {
      main { padding: 12px; }
      .status-grid, .controls { grid-template-columns: 1fr; }
      .row { flex-direction: column; }
    }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Nordility</h1>
      <div class="timestamp" id="updated">--</div>
    </header>

    <section>
      <h2>Status</h2>
      <div class="status-grid">
        <div class="metric"><label>Connection</label><div id="state">Loading</div></div>
        <div class="metric"><label>Server</label><div id="server">--</div></div>
        <div class="metric"><label>Country</label><div id="country">--</div></div>
        <div class="metric"><label>IP</label><div id="ip">--</div></div>
      </div>
    </section>

    <section>
      <h2>Controls</h2>
      <div class="controls">
        <button class="primary" id="connect" type="button">Power On</button>
        <button class="danger" id="disconnect" type="button">Power Off</button>
        <button id="rotate-fast" type="button">Rotate Fast</button>
        <button id="rotate-full" type="button">Rotate Full</button>
        <div class="full row">
          <select id="group"></select>
          <button id="connect-group" type="button">Connect</button>
        </div>
      </div>
      <p class="message" id="message"></p>
    </section>

    <section>
      <h2>Details</h2>
      <pre id="details">--</pre>
    </section>
  </main>

  <script>
    const $ = (id) => document.getElementById(id);
    let busy = false;

    function setBusy(value) {
      busy = value;
      for (const button of document.querySelectorAll("button")) button.disabled = value;
      $("message").textContent = value ? "Working..." : $("message").textContent;
    }

    function statusValue(lines, key) {
      const prefix = key.toLowerCase() + ":";
      for (const line of lines) {
        if (line.toLowerCase().startsWith(prefix)) return line.slice(line.indexOf(":") + 1).trim();
      }
      return "";
    }

    function renderStatus(data) {
      const lines = (data.nordvpn_status || "").split("\\n").map((line) => line.trim()).filter(Boolean);
      const state = statusValue(lines, "Status") || "Unknown";
      $("state").textContent = state;
      $("state").className = state.toLowerCase().includes("connected") ? "state-connected" : "state-disconnected";
      $("server").textContent = statusValue(lines, "Hostname") || statusValue(lines, "Server") || "--";
      $("country").textContent = statusValue(lines, "Country") || data.public_country || "--";
      $("ip").textContent = statusValue(lines, "IP") || data.public_ip || "--";
      $("details").textContent = data.details || data.nordvpn_status || "--";
      $("updated").textContent = new Date().toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});

      const select = $("group");
      if (!select.dataset.loaded) {
        for (const group of data.groups.full || []) {
          const option = document.createElement("option");
          option.value = group;
          option.textContent = group.replaceAll("_", " ");
          select.appendChild(option);
        }
        select.dataset.loaded = "1";
      }
    }

    async function refresh() {
      const response = await fetch("/api/status", {cache: "no-store"});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "status failed");
      renderStatus(data);
    }

    async function action(payload) {
      if (busy) return;
      setBusy(true);
      try {
        const response = await fetch("/api/action", {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          body: JSON.stringify(payload)
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "action failed");
        $("message").textContent = data.message || "Done";
        renderStatus(data.status);
      } catch (error) {
        $("message").textContent = error.message;
      } finally {
        setBusy(false);
      }
    }

    $("connect").addEventListener("click", () => action({action: "connect"}));
    $("disconnect").addEventListener("click", () => action({action: "disconnect"}));
    $("rotate-fast").addEventListener("click", () => action({action: "rotate", speed: "fast"}));
    $("rotate-full").addEventListener("click", () => action({action: "rotate", speed: "full"}));
    $("connect-group").addEventListener("click", () => action({action: "connect", group: $("group").value}));

    refresh().catch((error) => $("message").textContent = error.message);
    setInterval(() => { if (!busy) refresh().catch(() => {}); }, 8000);
  </script>
</body>
</html>
"""


@dataclass(frozen=True)
class ActionOutcome:
    result: CommandResult
    repair: WireGuardRestoreSummary


class NordilityWebController:
    def __init__(
        self,
        *,
        executable: str | None = None,
        backend: str = "auto",
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        wireguard_interfaces: tuple[str, ...] = DEFAULT_WIREGUARD_INTERFACES,
        wireguard_config_dir: Path | None = None,
        wireguard_fwmark: int = DEFAULT_WIREGUARD_FWMARK,
        ip_rule_priority: int = DEFAULT_WIREGUARD_IP_RULE_PRIORITY,
        auto_login: bool = False,
        keepass_entry: str | None = DEFAULT_KEEPASS_ENTRY,
        keepass_profile: str | None = DEFAULT_KEEPASS_PROFILE,
    ) -> None:
        self.client = NordVPNClient(executable=executable, backend=backend, runner=runner)
        self._runner = runner
        self._wireguard_interfaces = wireguard_interfaces
        self._wireguard_config_dir = wireguard_config_dir
        self._wireguard_fwmark = wireguard_fwmark
        self._ip_rule_priority = ip_rule_priority
        self._auto_login = auto_login
        self._keepass_entry = keepass_entry
        self._keepass_profile = keepass_profile
        self._lock = threading.Lock()
        self._public_info_lock = threading.Lock()
        self._public_info_cache: dict[str, str] = {}
        self._public_info_fetched_at: float = 0.0

    def _fetch_public_info(self) -> dict[str, str]:
        with self._public_info_lock:
            now = time.monotonic()
            if self._public_info_cache and (now - self._public_info_fetched_at) < _PUBLIC_INFO_TTL:
                return self._public_info_cache
            try:
                req = urllib.request.Request(
                    _PUBLIC_INFO_URL, headers={"Accept": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                result: dict[str, str] = {
                    "ip": data.get("ip", ""),
                    "country": data.get("country", ""),
                }
            except (urllib.error.URLError, OSError, ValueError):
                LOGGER.debug("Public IP lookup failed", exc_info=True)
                result = {}
            self._public_info_cache = result
            self._public_info_fetched_at = now
            return result

    def status(self) -> dict[str, Any]:
        nordvpn_status = self._run_text([self.client.executable, "status"])
        wg_fwmarks = self._run_text(["wg", "show", "all", "fwmark"])
        ip_rules = self._run_text(["ip", "rule", "show"])
        details = "\n\n".join(
            part
            for part in (
                "NordVPN:\n" + (nordvpn_status or "(no output)"),
                "WireGuard fwmarks:\n" + (wg_fwmarks or "(no output)"),
                "IP rules:\n" + (ip_rules or "(no output)"),
            )
            if part
        )
        out: dict[str, Any] = {
            "nordvpn_status": nordvpn_status,
            "details": details,
            "groups": {speed: list(groups) for speed, groups in GROUPS_BY_SPEED.items()},
        }
        if "disconnected" in nordvpn_status.lower():
            public = self._fetch_public_info()
            if public:
                out["public_ip"] = public.get("ip", "")
                out["public_country"] = public.get("country", "")
        return out

    def perform_action(self, payload: dict[str, Any]) -> ActionOutcome:
        action = str(payload.get("action", "")).strip()
        with self._lock:
            if action == "connect":
                result = self.client.connect(
                    group=self._optional_group(payload.get("group")),
                    auto_login=self._auto_login,
                    keepass_entry=self._keepass_entry,
                    keepass_profile=self._keepass_profile,
                )
            elif action == "disconnect":
                result = self.client.disconnect()
            elif action == "rotate":
                speed = str(payload.get("speed", "fast")).strip().lower()
                if speed not in GROUPS_BY_SPEED:
                    raise ConfigurationError(f"Unsupported speed: {speed}")
                result = self.client.change(
                    speed=speed,
                    group=self._optional_group(payload.get("group")),
                    auto_login=self._auto_login,
                    keepass_entry=self._keepass_entry,
                    keepass_profile=self._keepass_profile,
                )
            else:
                raise ConfigurationError(f"Unsupported action: {action}")

            repair = restore_wireguard_after_nordvpn(
                self._runner,
                backend=self.client.backend,
                fwmark=self._wireguard_fwmark,
                ip_rule_priority=self._ip_rule_priority,
                wireguard_config_dir=self._wireguard_config_dir,
                ensure_interfaces=self._wireguard_interfaces,
            )
            return ActionOutcome(result=result, repair=repair)

    def _optional_group(self, raw_group: object) -> str | None:
        if raw_group is None:
            return None
        group = str(raw_group).strip()
        if not group:
            return None
        if group not in FULL_GROUPS:
            raise ConfigurationError(f"Unsupported group: {group}")
        return group

    def _run_text(self, command: list[str]) -> str:
        try:
            result = self._runner(command, capture_output=True, text=True, check=False)
        except (OSError, FileNotFoundError) as exc:
            return f"{command[0]} unavailable: {exc}"
        return (result.stdout or result.stderr).strip()


def _json_bytes(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True).encode("utf-8")


def make_handler(controller: NordilityWebController) -> type[BaseHTTPRequestHandler]:
    class NordilityWebHandler(BaseHTTPRequestHandler):
        server_version = "NordilityWeb/1.0"

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/" or self.path == "/index.html":
                self._send_bytes(
                    HTTPStatus.OK, INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8"
                )
                return
            if self.path == "/api/status":
                self._send_json(HTTPStatus.OK, controller.status())
                return
            self.send_error(HTTPStatus.NOT_FOUND, "not found")

        def do_HEAD(self) -> None:  # noqa: N802
            if self.path == "/" or self.path == "/index.html":
                self._send_headers(
                    HTTPStatus.OK,
                    len(INDEX_HTML.encode("utf-8")),
                    "text/html; charset=utf-8",
                )
                return
            if self.path == "/api/status":
                body = _json_bytes(controller.status())
                self._send_headers(HTTPStatus.OK, len(body), "application/json; charset=utf-8")
                return
            self.send_error(HTTPStatus.NOT_FOUND, "not found")

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/api/action":
                self.send_error(HTTPStatus.NOT_FOUND, "not found")
                return
            try:
                payload = self._read_json()
                outcome = controller.perform_action(payload)
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "message": outcome.result.message + outcome.repair.message_suffix(),
                        "repair": outcome.repair.describe(),
                        "status": controller.status(),
                    },
                )
            except NordilityError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except Exception as exc:  # pragma: no cover - runtime guard
                LOGGER.exception("web action failed")
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

        def log_message(self, fmt: str, *args: object) -> None:
            LOGGER.info("%s - %s", self.address_string(), fmt % args)

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                return {}
            raw = self.rfile.read(length)
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise ConfigurationError("request body must be a JSON object")
            return data

        def _send_json(self, status: HTTPStatus, data: dict[str, Any]) -> None:
            self._send_bytes(status, _json_bytes(data), "application/json; charset=utf-8")

        def _send_bytes(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
            self._send_headers(status, len(body), content_type)
            self.wfile.write(body)

        def _send_headers(self, status: HTTPStatus, content_length: int, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(content_length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()

    return NordilityWebHandler


def run_web_server(args: argparse.Namespace) -> None:
    controller = NordilityWebController(
        executable=args.executable,
        backend=args.backend,
        wireguard_interfaces=tuple(args.wireguard_interfaces or DEFAULT_WIREGUARD_INTERFACES),
        wireguard_fwmark=args.wireguard_fwmark,
        ip_rule_priority=args.ip_rule_priority,
        auto_login=args.auto_login,
        keepass_entry=args.keepass_entry,
        keepass_profile=args.keepass_profile,
    )
    server = ThreadingHTTPServer((args.host, args.port), make_handler(controller))
    LOGGER.info("Serving nordility web UI on http://%s:%d", args.host, args.port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
