"""Live tests for the renderer: they drive the real Chromium, so run them inside
the image:

    docker run --rm --security-opt seccomp=seccomp_profile.json \
        --shm-size=1g -e HOME=/tmp mail-renderer:local python -m unittest -v test_server
"""
import http.server
import struct
import threading
import time
import unittest
import urllib.error
import urllib.request

import server


def _png_size(png: bytes) -> tuple[int, int]:
    assert png[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
    return struct.unpack(">II", png[16:24])


class Canary(http.server.BaseHTTPRequestHandler):
    hits: list = []

    def do_GET(self):
        Canary.hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h1>FROM THE INTERNAL SERVICE</h1>")

    def log_message(self, *args):
        pass


class RendererTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        threading.Thread(target=server._worker, daemon=True).start()
        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls.canary = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Canary)
        threading.Thread(target=cls.canary.serve_forever, daemon=True).start()
        cls.canary_url = f"http://127.0.0.1:{cls.canary.server_address[1]}"
        for _ in range(120):
            if server._state["ready"]:
                break
            time.sleep(0.5)
        assert server._state["ready"], "browser did not start"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.canary.shutdown()

    def post(self, body, path="/render"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        req = urllib.request.Request(self.base + path, data=data, method="POST",
                                     headers={"Content-Type": "text/html; charset=utf-8"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except (urllib.error.URLError, ConnectionError):
            # The server refused a body it did not read; the client may see the
            # connection close before the response (a refusal either way).
            return 0, b""

    def test_health(self):
        with urllib.request.urlopen(self.base + "/health", timeout=5) as resp:
            self.assertEqual(resp.status, 200)

    def test_short_mail_is_a_small_compressed_png_not_a_full_canvas(self):
        status, png = self.post("<html><body><h2>Invoice overdue</h2><p>Pay now</p></body></html>")
        self.assertEqual(status, 200)
        width, height = _png_size(png)
        self.assertEqual(width, server.WIDTH_PX)
        self.assertLess(height, 400)
        self.assertLess(len(png), 200 * 1024)

    def test_a_tall_page_is_clipped_to_the_maximum_height(self):
        status, png = self.post("<html><body><div style='height:900000px;background:#eee'>x</div></body></html>")
        self.assertEqual(status, 200)
        self.assertEqual(_png_size(png)[1], server.MAX_HEIGHT_PX)

    def test_pathological_markup_still_answers_within_limits(self):
        deep = "<div>" * 5000 + "x" + "</div>" * 5000
        rows = "<table>" + "<tr>" + "<td>c</td>" * 40 + "</tr>" * 1 + ("<tr>" + "<td>c</td>" * 40 + "</tr>") * 3000 + "</table>"
        for html in (deep, rows, "<p>" + "AAAA " * 300000 + "</p>"):
            started = time.monotonic()
            status, png = self.post(html)
            self.assertIn(status, (200, 500, 504))
            self.assertLess(time.monotonic() - started, server.REQUEST_TIMEOUT_S + 5)
            if status == 200:
                self.assertLessEqual(_png_size(png)[1], server.MAX_HEIGHT_PX)
                self.assertLess(len(png), 15 * 1024 * 1024)

    def test_nothing_is_fetched_whatever_the_page_asks_for(self):
        Canary.hits.clear()
        u = self.canary_url
        hostile = (
            f"<img src={u}/a.png><iframe src={u}/b></iframe><link rel=stylesheet href={u}/c.css>"
            f"<style>@import '{u}/d.css'; p{{background:url({u}/e.png)}}</style>"
            f"<object data={u}/f></object><embed src={u}/g><video src={u}/h poster={u}/i></video>"
            f"<body background={u}/j><meta http-equiv=refresh content='0;url={u}/k'><p>visible</p>"
        )
        status, _ = self.post(hostile)
        self.assertEqual(status, 200)
        self.assertEqual(Canary.hits, [], "the renderer reached out to the network")

    def test_javascript_does_not_run(self):
        status, png = self.post("<p id=x>js-off</p><script>document.getElementById('x').textContent='js-ran'; "
                                f"fetch('{self.canary_url}/js')</script>")
        self.assertEqual(status, 200)
        self.assertNotIn("/js", Canary.hits)

    def test_oversized_body_is_refused(self):
        status, _ = self.post(b"x" * (server.MAX_HTML_BYTES + 1))
        self.assertIn(status, (413, 0))

    def test_body_that_is_not_utf8_is_refused(self):
        status, _ = self.post(b"\xff\xfe\xfa not utf8")
        self.assertEqual(status, 400)

    def test_unknown_paths_are_404(self):
        self.assertEqual(self.post("<p>x</p>", path="/other")[0], 404)

    def test_the_browser_survives_a_failed_render(self):
        self.post("<p>" + "A" * 10)
        status, _ = self.post("<p>still alive</p>")
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
