"""The body must be sanitised before it is handed to the isolated renderer, and
the call to that renderer must not depend on, or leak through, the proxy
environment. (The network containment itself lives in mail-renderer/.)"""
from email.message import EmailMessage
from unittest import mock

import requests
from django.test import SimpleTestCase

from mail_feeder.utils.email_preview.eml2png_renderer import (
    _RENDERER_URL,
    Eml2PngRenderer,
)

HOST = "evil.test"


def _html_message(body_html: str, subject: str = "hello") -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = "a@example.com"
    msg.set_content("plain fallback")
    msg.add_alternative(body_html, subtype="html")
    return msg


def _response(status=200, content=b"PNG", text=""):
    return mock.Mock(status_code=status, content=content, text=text)


class RendererCallTests(SimpleTestCase):
    def _post(self, response=None, side_effect=None):
        with mock.patch("requests.Session.post", return_value=response, side_effect=side_effect) as post:
            out = Eml2PngRenderer()._render_html_to_png("<p>hi \u00e9</p>")
        return out, post

    def test_posts_the_html_to_the_renderer_service(self):
        out, post = self._post(_response())
        self.assertEqual(out, b"PNG")
        self.assertEqual(post.call_args.args[0], f"{_RENDERER_URL}/render")
        self.assertEqual(post.call_args.kwargs["data"], "<p>hi \u00e9</p>".encode("utf-8"))
        self.assertIn("utf-8", post.call_args.kwargs["headers"]["Content-Type"])

    def test_proxy_environment_is_not_used_for_the_internal_service(self):
        with mock.patch.dict("os.environ", {"HTTP_PROXY": "http://proxy:3128", "HTTPS_PROXY": "http://proxy:3128"}), \
                mock.patch("requests.Session.post", return_value=_response()) as post:
            seen = {}
            real_init = requests.Session.__init__

            def spy(self_, *a, **k):
                real_init(self_, *a, **k)
                seen["session"] = self_
            with mock.patch.object(requests.Session, "__init__", spy):
                Eml2PngRenderer()._render_html_to_png("<p>x</p>")
        self.assertIs(seen["session"].trust_env, False)
        self.assertTrue(post.called)

    def test_unreachable_renderer_gives_no_preview_instead_of_raising(self):
        out, _ = self._post(side_effect=requests.ConnectionError("no route"))
        self.assertIsNone(out)

    def test_a_timeout_gives_no_preview(self):
        out, _ = self._post(side_effect=requests.ReadTimeout("slow"))
        self.assertIsNone(out)

    def test_error_statuses_give_no_preview(self):
        for status in (400, 413, 500, 503, 504):
            with self.subTest(status=status):
                out, _ = self._post(_response(status=status, content=b"", text='{"detail":"x"}'))
                self.assertIsNone(out)


class BodySanitisationWiringTests(SimpleTestCase):
    HOSTILE = (
        f"<iframe src=http://{HOST}/a></iframe>"
        f'<body background="//{HOST}/b">'
        f'<div style="background:url(//{HOST}/c)">kept text</div>'
        '<meta name="imgkit-enable-local-file-access" content="">'
    )

    def test_preview_html_has_no_outbound_reference_or_imgkit_option_meta(self):
        html = Eml2PngRenderer()._build_preview_html(_html_message(self.HOSTILE))
        self.assertNotIn(HOST, html)
        self.assertNotIn("imgkit-", html)
        self.assertIn("kept text", html)

    def test_headers_are_still_escaped(self):
        html = Eml2PngRenderer()._build_preview_html(
            _html_message("<p>x</p>", subject="<script>alert(1)</script>")
        )
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_sanitiser_failure_falls_back_to_plain_text(self):
        with mock.patch(
            "mail_feeder.utils.email_preview.eml2png_renderer.sanitize_email_html",
            side_effect=RuntimeError("boom"),
        ):
            html = Eml2PngRenderer()._build_preview_html(_html_message(self.HOSTILE))
        self.assertIn("plain fallback", html)
        self.assertNotIn(HOST, html)


class HostileBodyReachesTheRendererSanitisedTests(SimpleTestCase):
    def test_the_html_sent_to_the_renderer_has_no_outbound_reference(self):
        renderer = Eml2PngRenderer()
        html = renderer._build_preview_html(
            _html_message(f"<iframe src=http://{HOST}/x></iframe><p>visible</p>")
        )
        with mock.patch("requests.Session.post", return_value=_response()) as post:
            renderer._render_html_to_png(html)
        sent = post.call_args.kwargs["data"].decode("utf-8")
        self.assertNotIn(HOST, sent)
        self.assertIn("visible", sent)


class BlankBodyFallbackTests(SimpleTestCase):
    def test_html_that_sanitises_to_nothing_falls_back_to_plain_text(self):
        for body in (
            f"<img src=http://{HOST}/x.gif>",
            f"<iframe src=http://{HOST}/x></iframe>",
            "   <div> </div>  ",
        ):
            with self.subTest(body=body):
                html = Eml2PngRenderer()._build_preview_html(_html_message(body))
                self.assertRegex(html, r"<pre>plain fallback\s*</pre>")
                self.assertNotIn(HOST, html)


class HeaderRowsCannotBeHiddenTests(SimpleTestCase):
    def test_header_cells_carry_inline_important_display(self):
        html = Eml2PngRenderer()._build_preview_html(
            _html_message("<p>x</p>", subject="Urgent invoice")
        )
        self.assertIn("Urgent invoice", html)
        row = html[html.index("<tr"):html.index("</tr>")]
        for cell in ("<tr", "<th", "<td"):
            self.assertIn("!important", row[row.index(cell):].split(">", 1)[0])
