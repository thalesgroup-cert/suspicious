"""sanitize_email_html must leave no outbound reference in hostile mail
bodies, and must keep an ordinary newsletter readable."""
import re
from html.parser import HTMLParser

from django.test import SimpleTestCase

from mail_feeder.utils.email_preview.html_sanitizer import (
    ALLOWED_TAGS,
    sanitize_email_html,
)

HOST = "evil.test"
PIXEL = (
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4"
    "2mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)

HOSTILE = {
    "unquoted_iframe_src": f"<iframe src=http://{HOST}/x></iframe><p>t</p>",
    "protocol_relative_img": f'<img src="//{HOST}/p.gif">',
    "protocol_relative_unquoted": f"<img src=//{HOST}/p.gif>",
    "import_without_semicolon": f"<style>@import url(http://{HOST}/a.css)</style><p>t</p>",
    "import_string_form": f'<style>@import "//{HOST}/a.css"</style><p>t</p>',
    "body_background": f"<body background=http://{HOST}/b.png><p>t</p></body>",
    "td_background": f'<table><tr><td background="//{HOST}/c">t</td></tr></table>',
    "inline_url_protocol_relative": f'<div style="background:url(//{HOST}/x.gif)">t</div>',
    "style_block_url": f"<style>div{{background:url(//{HOST}/x.gif)}}</style><div>t</div>",
    "srcdoc": f'<iframe srcdoc="<img src=http://{HOST}/x>"></iframe><p>t</p>',
    "svg_image": f'<svg><image href="http://{HOST}/x.png"/></svg><p>t</p>',
    "svg_use": f'<svg><use xlink:href="http://{HOST}/s.svg#a"/></svg><p>t</p>',
    "meta_refresh": f'<meta http-equiv="refresh" content="0;url=http://{HOST}/"><p>t</p>',
    "css_image_set_inline": f"<div style=\"background-image:image-set('http://{HOST}/x' 1x)\">t</div>",
    "css_image_set_block": f"<style>div{{background:-webkit-image-set(url(http://{HOST}/x) 1x)}}</style>",
    "font_face": f"<style>@font-face{{font-family:x;src:url(http://{HOST}/f.woff)}}</style><p>t</p>",
    "entity_encoded_scheme": f'<img src="&#104;ttp://{HOST}/x.gif"><img src="http&colon;//{HOST}/y">',
    "entity_encoded_javascript": '<img src="&#106;avascript:alert(1)">',
    "uppercase_tags_and_attrs": f'<IMG SRC="HTTP://{HOST.upper()}/X.GIF"><IFRAME SRC="HTTP://{HOST.upper()}"></IFRAME>',
    "nul_in_tag_name": f'<im\x00g src="http://{HOST}/x"><ifr\x00ame src="http://{HOST}/"></iframe>',
    "nul_in_attr_name": f'<img sr\x00c="http://{HOST}/x">',
    "link_stylesheet": f"<link rel=stylesheet href=//{HOST}/s.css><p>t</p>",
    "base_href": f'<base href="http://{HOST}/"><img src=x.gif>',
    "object_embed": f"<object data=http://{HOST}/x></object><embed src=http://{HOST}/y>",
    "video_poster": f"<video src=http://{HOST}/a poster=http://{HOST}/p></video>",
    "input_image": f"<input type=image src=http://{HOST}/x>",
    "form_action": f'<form action=http://{HOST}><button>x</button></form>',
    "css_escape": f"<style>div{{background:\\75rl(http://{HOST}/x)}}</style><p>t</p>",
    "css_comment_split": f"<style>div{{background:u/**/rl(http://{HOST}/x)}}</style><p>t</p>",
    "unclosed_style": f"<p>t</p><style>@import url(http://{HOST}/a.css)",
    "leading_whitespace_src": f'<img src="  http://{HOST}/x">',
    "tab_inside_scheme": f'<img src="ht\ttp://{HOST}/x">',
    "conditional_comment": f'<!--[if mso]><img src="http://{HOST}/x"><![endif]--><p>t</p>',
    "anchor_href": f'<a href="http://{HOST}/">click</a>',
    "srcset": f'<img src="{PIXEL}" srcset="http://{HOST}/x 2x">',
    "svg_data_uri": '<img src="data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=">',
    "list_style_image": f"<ul style=\"list-style-image:url(http://{HOST}/x)\"><li>t</li></ul>",
    "nested_split_tag": f"<scr<script>ipt>x</scr</script>ipt><img src=http://{HOST}/n>",
    "imgkit_option_meta": '<meta name="imgkit-enable-local-file-access" content=""><p>t</p>',
    "huge_attribute": f'<img alt="{"A" * 1_000_000}" src="http://{HOST}/x">',
}

_FETCHING_ATTRS = {
    "href", "background", "srcset", "action", "formaction", "poster", "data",
    "xlink:href", "ping", "srcdoc", "longdesc", "usemap",
}


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.attrs, self.css = [], [], []
        self._in_style = False

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.extend((tag, k, v or "") for k, v in attrs)
        self._in_style = tag == "style"

    def handle_endtag(self, tag):
        if tag == "style":
            self._in_style = False

    def handle_data(self, data):
        if self._in_style:
            self.css.append(data)


def _parse(out):
    c = _Collector()
    c.feed(out)
    c.close()
    return c


class SanitizeEmailHtmlHostileTests(SimpleTestCase):
    def assert_no_outbound_reference(self, out):
        c = _parse(out)
        for tag in c.tags:
            self.assertTrue(tag in ALLOWED_TAGS or tag == "style", f"tag {tag!r} survived")
        for tag, name, value in c.attrs:
            self.assertNotIn(name, _FETCHING_ATTRS, f"{tag}[{name}] survived")
            if name == "src":
                self.assertRegex(value, r"(?i)^(data:image/(png|jpe?g|gif|webp|bmp)[;,]|cid:)")
            else:
                self.assertNotRegex(value, r"(?i)(https?:)?//|url\(|@import|javascript:|image-set")
        css = "".join(c.css)
        self.assertNotRegex(css, r"(?i)url|image|import|font-face|//|\\")
        blob = (" ".join(v for _, _, v in c.attrs) + css).lower()
        self.assertNotIn(HOST, blob)

    def test_hostile_payloads_leave_no_outbound_reference(self):
        self.assertGreaterEqual(len(HOSTILE), 15)
        for name, payload in HOSTILE.items():
            with self.subTest(payload=name):
                self.assert_no_outbound_reference(sanitize_email_html(payload))

    def test_output_is_stable_when_sanitised_twice(self):
        for name, payload in HOSTILE.items():
            with self.subTest(payload=name):
                once = sanitize_email_html(payload)
                self.assert_no_outbound_reference(sanitize_email_html(once))

    def test_text_that_looks_like_a_url_is_kept_as_text(self):
        out = sanitize_email_html(f"<p>see http://{HOST}/login now</p>")
        self.assertIn(f"http://{HOST}/login", out)
        self.assert_no_outbound_reference(out)

    def test_script_and_event_handlers_removed(self):
        out = sanitize_email_html('<p onclick="x()">a</p><script>alert(1)</script>')
        self.assertEqual(out, "<p>a</p>")


class SanitizeEmailHtmlBenignTests(SimpleTestCase):
    NEWSLETTER = f"""<html><head><title>News</title>
<style>.b{{color:#333;font-family:Arial}}@media (max-width:600px){{.b{{width:100%}}}}</style></head>
<body bgcolor="#ffffff"><table width="600" cellpadding="0" cellspacing="0" border="0">
<tr><td align="center" style="padding:10px;background-color:#eeeeee">
<img src="cid:logo@news" width="100" alt="Logo"><img src="{PIXEL}" alt="pixel">
<font color="red">Hello</font> <a href="https://example.com/x">Read more</a> <b>bold</b>
</td></tr></table><p class="b" style="color:red;font-size:14px">Café ü 日本語</p></body></html>"""

    def setUp(self):
        self.out = sanitize_email_html(self.NEWSLETTER)

    def test_text_is_kept(self):
        for text in ("Hello", "Read more", "bold", "Café ü 日本語"):
            self.assertIn(text, self.out)

    def test_table_structure_is_kept(self):
        c = _parse(self.out)
        for tag in ("table", "tr", "td"):
            self.assertIn(tag, c.tags)
        self.assertIn(("td", "align", "center"), c.attrs)
        self.assertIn(("table", "width", "600"), c.attrs)

    def test_cid_and_data_images_are_kept(self):
        srcs = [v for _, k, v in _parse(self.out).attrs if k == "src"]
        self.assertIn("cid:logo@news", srcs)
        self.assertIn(PIXEL, srcs)

    def test_style_without_remote_refs_is_kept(self):
        self.assertIn(".b{color:#333;font-family:Arial}", self.out)
        self.assertIn("@media (max-width:600px)", self.out)
        self.assertIn("background-color:#eeeeee", self.out)
        self.assertIn("color:red", self.out)

    def test_plain_fragment_is_unchanged(self):
        html = "<p>plain <b>body</b></p>"
        self.assertEqual(sanitize_email_html(html), html)

    def test_anchor_text_survives_without_href(self):
        self.assertIn("<a>Read more</a>", self.out)
