"""The preview renderer must not reach the network, even if a hostile body
slips past the sanitiser, and must not hand the body to imgkit unsanitised."""
from email.message import EmailMessage
from unittest import mock

from django.test import SimpleTestCase

from mail_feeder.utils.email_preview.eml2png_renderer import (
    _CLOSED_PROXY,
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


class NetworkContainmentOptionsTests(SimpleTestCase):
    def _options(self):
        renderer = Eml2PngRenderer()
        renderer._imgkit_available = True
        with mock.patch("imgkit.from_string", return_value=b"PNG") as mocked:
            renderer._render_html_to_png("<p>hi</p>")
        return mocked.call_args.kwargs["options"]

    def test_all_fetches_go_through_a_closed_local_proxy(self):
        options = self._options()
        self.assertEqual(options["proxy"], _CLOSED_PROXY)
        self.assertTrue(_CLOSED_PROXY.startswith("http://127.0.0.1:"))
        self.assertIn("proxy-hostname-lookup", options)

    def test_load_errors_are_ignored(self):
        options = self._options()
        self.assertEqual(options["load-error-handling"], "ignore")
        self.assertEqual(options["load-media-error-handling"], "ignore")

    def test_render_failure_returns_none_instead_of_raising(self):
        # With the proxy closed, a fetch that slips past the sanitiser makes
        # wkhtmltoimage exit non-zero and imgkit raise: no preview, no fetch.
        renderer = Eml2PngRenderer()
        renderer._imgkit_available = True
        with mock.patch("imgkit.from_string", side_effect=OSError("Failed to load")):
            self.assertIsNone(renderer._render_html_to_png("<p>hi</p>"))

    def test_existing_hardening_flags_are_kept(self):
        options = self._options()
        for flag in ("no-images", "disable-javascript", "disable-local-file-access"):
            self.assertIn(flag, options)


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


class HostileRenderThroughOptionsTests(SimpleTestCase):
    def test_hostile_body_is_rendered_only_with_proxy_option_and_clean_html(self):
        renderer = Eml2PngRenderer()
        renderer._imgkit_available = True
        html = renderer._build_preview_html(
            _html_message(f"<iframe src=http://{HOST}/x></iframe><p>visible</p>")
        )
        with mock.patch("imgkit.from_string", return_value=b"PNG") as mocked:
            renderer._render_html_to_png(html)
        args, kwargs = mocked.call_args
        self.assertNotIn(HOST, args[0])
        self.assertEqual(kwargs["options"]["proxy"], _CLOSED_PROXY)
