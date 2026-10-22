"""Isolated HTML -> PNG renderer for the mail preview.

Suspicious sanitises a reported mail's HTML (nh3 allow-list, no resource
references) and sends it here; this service rasterises it with headless Chromium
and returns a PNG. It runs in its own container on a network with no route out,
so a rendering bug in the browser can neither reach another service nor the
internet. Defence in depth inside the page as well: JavaScript is off, every
request the page tries to make is aborted, DNS resolves nothing, and the
screenshot is clipped to the content, never more than MAX_HEIGHT_PX tall.

One worker thread owns the browser (Playwright's sync API is not thread safe);
HTTP threads queue jobs for it and a full queue answers 503, so a burst of mail
cannot pile up memory. A job stuck past WATCHDOG_SECONDS takes the process down
and the container restart policy brings back a clean one.

POST /render   body: UTF-8 HTML        -> 200 image/png
GET  /health                           -> 200 {"status": "ok", ...}
"""
from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
from concurrent.futures import Future, TimeoutError as FutureTimeout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

WIDTH_PX = int(os.environ.get("RENDER_WIDTH_PX", "900"))
MAX_HEIGHT_PX = int(os.environ.get("RENDER_MAX_HEIGHT_PX", "4000"))
BOTTOM_MARGIN_PX = int(os.environ.get("RENDER_BOTTOM_MARGIN_PX", "24"))
MAX_HTML_BYTES = int(os.environ.get("RENDER_MAX_HTML_BYTES", str(2 * 1024 * 1024)))
PAGE_TIMEOUT_MS = int(os.environ.get("RENDER_PAGE_TIMEOUT_MS", "10000"))
REQUEST_TIMEOUT_S = int(os.environ.get("RENDER_REQUEST_TIMEOUT_S", "30"))
WATCHDOG_SECONDS = int(os.environ.get("RENDER_WATCHDOG_S", "45"))
QUEUE_MAX = int(os.environ.get("RENDER_QUEUE_MAX", "4"))
RECYCLE_AFTER = int(os.environ.get("RENDER_RECYCLE_AFTER", "200"))
PORT = int(os.environ.get("PORT", "8080"))

CHROMIUM_ARGS = [
    # No name resolves, whatever the page asks for.
    "--host-resolver-rules=MAP * ~NOTFOUND",
    "--disable-gpu",
    "--disable-extensions",
    "--disable-background-networking",
    "--mute-audio",
]

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format='{"levelname": "%(levelname)s", "name": "%(name)s", "message": "%(message)s"}')
log = logging.getLogger("mail-renderer")

_jobs: "queue.Queue[tuple[str, Future]]" = queue.Queue(maxsize=QUEUE_MAX)
_state = {"ready": False, "renders": 0, "busy_since": 0.0}


def _launch(pw):
    return pw.chromium.launch(args=CHROMIUM_ARGS)


def _render_one(browser, html: str) -> bytes:
    context = browser.new_context(
        viewport={"width": WIDTH_PX, "height": MAX_HEIGHT_PX},
        java_script_enabled=False,
        offline=True,
        accept_downloads=False,
        service_workers="block",
    )
    try:
        context.route("**/*", lambda route: route.abort())
        context.set_default_timeout(PAGE_TIMEOUT_MS)
        page = context.new_page()
        page.set_content(html, wait_until="load")
        # <html> (and <body> in quirks mode) stretch to the viewport, so measure
        # where the last element in the body ends, and keep a bottom margin; no
        # box means nothing to draw.
        children = page.locator("body > *")
        box = children.last.bounding_box() if children.count() else page.locator("body").bounding_box()
        content_bottom = box["y"] + box["height"] if box else 0
        height = max(1, min(int(content_bottom) + BOTTOM_MARGIN_PX, MAX_HEIGHT_PX))
        return page.screenshot(
            type="png",
            clip={"x": 0, "y": 0, "width": WIDTH_PX, "height": height},
            animations="disabled",
            caret="hide",
        )
    finally:
        context.close()


def _worker() -> None:
    with sync_playwright() as pw:
        browser = _launch(pw)
        _state["ready"] = True
        log.info("chromium %s ready", browser.version)
        while True:
            html, fut = _jobs.get()
            if not fut.set_running_or_notify_cancel():
                continue
            _state["busy_since"] = time.monotonic()
            try:
                if not browser.is_connected() or _state["renders"] and _state["renders"] % RECYCLE_AFTER == 0:
                    try:
                        browser.close()
                    except PlaywrightError:
                        pass
                    browser = _launch(pw)
                fut.set_result(_render_one(browser, html))
                _state["renders"] += 1
            except Exception as exc:  # noqa: BLE001 - reported to the caller, not swallowed
                log.warning("render failed: %s", str(exc).splitlines()[0][:200] if str(exc) else type(exc).__name__)
                fut.set_exception(exc)
            finally:
                _state["busy_since"] = 0.0


def _watchdog() -> None:
    while True:
        time.sleep(5)
        started = _state["busy_since"]
        if started and time.monotonic() - started > WATCHDOG_SECONDS:
            log.error("render stuck for over %ss, exiting so the container restarts", WATCHDOG_SECONDS)
            os._exit(3)


class Handler(BaseHTTPRequestHandler):
    server_version = "mail-renderer"
    sys_version = ""

    def log_message(self, fmt, *args):  # request lines are not useful here
        pass

    def _reply(self, code: int, body: bytes = b"", ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, payload: dict) -> None:
        self._reply(code, json.dumps(payload).encode())

    def do_GET(self):
        if self.path != "/health":
            return self._json(404, {"detail": "not found"})
        if not _state["ready"]:
            return self._json(503, {"status": "starting"})
        self._json(200, {"status": "ok", "renders": _state["renders"]})

    def do_POST(self):
        if self.path != "/render":
            return self._json(404, {"detail": "not found"})
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0:
            return self._json(411, {"detail": "Content-Length required"})
        if length > MAX_HTML_BYTES:
            # The body is not read; close so the unread bytes cannot be taken
            # for the next request on this connection.
            self.close_connection = True
            return self._json(413, {"detail": f"HTML over {MAX_HTML_BYTES} bytes"})
        if not _state["ready"]:
            return self._json(503, {"detail": "browser starting"})
        try:
            html = self.rfile.read(length).decode("utf-8")
        except UnicodeDecodeError:
            return self._json(400, {"detail": "body is not UTF-8"})

        fut: Future = Future()
        try:
            _jobs.put_nowait((html, fut))
        except queue.Full:
            return self._json(503, {"detail": "renderer busy"})
        try:
            png = fut.result(timeout=REQUEST_TIMEOUT_S)
        except FutureTimeout:
            fut.cancel()
            return self._json(504, {"detail": "render timed out"})
        except Exception:  # noqa: BLE001 - detail already logged by the worker
            return self._json(500, {"detail": "render failed"})
        self._reply(200, png, "image/png")


def main() -> None:
    threading.Thread(target=_worker, name="browser", daemon=True).start()
    threading.Thread(target=_watchdog, name="watchdog", daemon=True).start()
    log.info("listening on :%s", PORT)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
