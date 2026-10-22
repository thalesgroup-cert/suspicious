"""Size guard on what comes back from the renderer.

Root cause of a production incident: the old wkhtmltoimage renderer drew the
full page height with no bound (multi-hundred-MB PNGs). The renderer service now
clips to the content and compresses; `_render_html_to_png` still drops, never
stores, a render that comes back oversized.
"""
from unittest import mock

from django.test import SimpleTestCase

from mail_feeder.utils.email_preview.eml2png_renderer import _MAX_PNG_BYTES, Eml2PngRenderer


def _render(content):
    resp = mock.Mock(status_code=200, content=content, text="")
    with mock.patch("requests.Session.post", return_value=resp):
        return Eml2PngRenderer()._render_html_to_png("<p>hi</p>")


class RenderSizeGuardTests(SimpleTestCase):
    def test_oversized_render_is_dropped_not_stored(self):
        self.assertIsNone(_render(b"x" * (_MAX_PNG_BYTES + 1)))

    def test_render_at_or_under_limit_is_kept(self):
        at_limit = b"x" * _MAX_PNG_BYTES
        self.assertEqual(_render(at_limit), at_limit)
