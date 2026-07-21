from django.test import SimpleTestCase

from mail_feeder.utils.email_preview.eml2png_renderer import _strip_remote_resources


class StripRemoteResourcesTests(SimpleTestCase):
    def test_strips_link_and_import(self):
        html = (
            '<link rel="stylesheet" href="http://evil.test/x.css">'
            '<style>@import url("http://evil.test/y.css"); body{color:red}</style>'
            "<p>hi</p>"
        )
        out = _strip_remote_resources(html)
        self.assertNotIn("evil.test", out)
        self.assertNotIn("<link", out)
        self.assertNotIn("@import", out)
        self.assertIn("<p>hi</p>", out)
        self.assertIn("color:red", out)

    def test_noop_without_remote_resources(self):
        html = "<p>plain <b>body</b></p>"
        self.assertEqual(_strip_remote_resources(html), html)

    def test_strips_css_background_image_url(self):
        html = '<style>.pixel{background-image:url(http://evil.test/track.gif)}</style><p>hi</p>'
        out = _strip_remote_resources(html)
        self.assertNotIn("evil.test", out)
        self.assertIn("<p>hi</p>", out)

    def test_strips_inline_style_background_url(self):
        html = '<div style="background:url(\'https://evil.test/track.gif\')">hi</div>'
        out = _strip_remote_resources(html)
        self.assertNotIn("evil.test", out)

    def test_strips_iframe_and_video_src(self):
        html = (
            '<iframe src="http://evil.test/x"></iframe>'
            '<video src="https://evil.test/y.mp4"></video>'
            "<p>hi</p>"
        )
        out = _strip_remote_resources(html)
        self.assertNotIn("evil.test", out)
        self.assertIn("<p>hi</p>", out)
