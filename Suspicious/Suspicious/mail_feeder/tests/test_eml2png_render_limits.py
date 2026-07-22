"""Tests for the render-height cap and post-render size guard.

Root cause of a production incident: wkhtmltoimage renders the full page
height with no bound, so a pathologically tall email body produced
multi-hundred-MB to multi-GB preview PNGs. `_render_html_to_png` now caps
the rendered height and drops (never stores) any render that still comes
out oversized.
"""
from unittest import mock

from django.test import SimpleTestCase

from mail_feeder.utils.email_preview.eml2png_renderer import (
    _MAX_PNG_BYTES,
    _MAX_RENDER_HEIGHT_PX,
    Eml2PngRenderer,
)


class RenderHeightCapTests(SimpleTestCase):
    def test_height_option_passed_to_imgkit(self):
        renderer = Eml2PngRenderer()
        renderer._imgkit_available = True
        with mock.patch("imgkit.from_string", return_value=b"PNGDATA") as mocked:
            out = renderer._render_html_to_png("<p>hi</p>")
        self.assertEqual(out, b"PNGDATA")
        _, kwargs = mocked.call_args
        self.assertEqual(kwargs["options"]["height"], str(_MAX_RENDER_HEIGHT_PX))

    def test_oversized_render_is_dropped_not_stored(self):
        renderer = Eml2PngRenderer()
        renderer._imgkit_available = True
        oversized = b"x" * (_MAX_PNG_BYTES + 1)
        with mock.patch("imgkit.from_string", return_value=oversized):
            out = renderer._render_html_to_png("<p>hi</p>")
        self.assertIsNone(out)

    def test_render_at_or_under_limit_is_kept(self):
        renderer = Eml2PngRenderer()
        renderer._imgkit_available = True
        at_limit = b"x" * _MAX_PNG_BYTES
        with mock.patch("imgkit.from_string", return_value=at_limit):
            out = renderer._render_html_to_png("<p>hi</p>")
        self.assertEqual(out, at_limit)
