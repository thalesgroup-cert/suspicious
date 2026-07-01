from django.test import SimpleTestCase

from mail_feeder.utils.email_preview.eml2png_renderer import _strip_remote_css


class StripRemoteCssTests(SimpleTestCase):
    def test_strips_link_and_import(self):
        html = (
            '<link rel="stylesheet" href="http://evil.test/x.css">'
            '<style>@import url("http://evil.test/y.css"); body{color:red}</style>'
            "<p>hi</p>"
        )
        out = _strip_remote_css(html)
        self.assertNotIn("evil.test", out)
        self.assertNotIn("<link", out)
        self.assertNotIn("@import", out)
        # legit inline content survives
        self.assertIn("<p>hi</p>", out)
        self.assertIn("color:red", out)

    def test_noop_without_remote_css(self):
        html = "<p>plain <b>body</b></p>"
        self.assertEqual(_strip_remote_css(html), html)
