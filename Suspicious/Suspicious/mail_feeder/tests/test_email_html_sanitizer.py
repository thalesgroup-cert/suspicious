"""sanitize_email_html must leave no outbound reference in hostile mail
bodies, and must keep an ordinary newsletter readable."""
import re
import time
from html.parser import HTMLParser

from django.test import SimpleTestCase

from mail_feeder.utils.email_preview.html_sanitizer import (
    _ATTRIBUTES,
    ALLOWED_TAGS,
    MAX_HTML_CHARS,
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
    "uppercase_style_block": f"<STYLE>div{{background:URL(//{HOST}/x)}}</STYLE><p>t</p>",
    "style_close_with_space": f"<style>div{{background:url(//{HOST}/x)}}</style ><p>t</p>",
    "style_close_with_newline": f"<style>@import '//{HOST}/a'</STYLE\n><p>t</p>",
    "style_inside_svg": f"<svg><style>@import '//{HOST}/a';</style></svg><p>t</p>",
    "style_inside_noscript": f"<noscript><style>div{{background:url(//{HOST}/x)}}</style></noscript>",
    "style_inside_textarea": f"<textarea><style>@import '//{HOST}/a';</style></textarea><img src=//{HOST}/y>",
    "style_inside_xmp": f"<xmp><style>@import '//{HOST}/a';</style></xmp><img src=//{HOST}/y>",
    "vtab_in_tag": f"<img\x0bsrc=http://{HOST}/x>",
    "formfeed_in_attr_name": f"<img s\x0crc=http://{HOST}/x>",
    "cr_in_scheme": f'<img src="ht\rtp://{HOST}/x">',
    "formfeed_in_scheme": f'<img src="java\x0cscript:{HOST}">',
    "style_attr_css_escape": f'<div style="background:\\75rl(//{HOST}/x)">t</div>',
    "style_attr_comment_split": f'<div style="background:u/**/rl(//{HOST}/x)">t</div>',
    "moz_binding": f'<div style="-moz-binding:url(//{HOST}/b.xml#x)">t</div>',
    "behavior": f'<div style="behavior:url(//{HOST}/b.htc)">t</div>',
    "expression": f'<div style="width:expression(document.body.innerHTML=\'{HOST}\')">t</div>',
    "style_block_binding": f"<style>div{{-moz-binding:url(//{HOST}/b.xml)}}</style>",
    "style_block_expression": f"<style>div{{width:expression(alert(1))}}</style>",
}

_ALLOWED_ATTRS = set().union(*_ATTRIBUTES.values())


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
            self.assertIn(name, _ALLOWED_ATTRS, f"{tag}[{name}] survived")
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


SLOW_BUDGET_S = 3


class SanitizeEmailHtmlPerformanceTests(SimpleTestCase):
    # Every payload stays under MAX_HTML_TAGS / MAX_TAG_CHARS wherever the
    # HOST probe is appended, so the probe is not simply truncated away.
    PAYLOADS = {
        "unclosed_style_repeats": "<style>" * 9_000,
        "unclosed_style_comment_repeats": "<style>/* " * 9_000,
        "unclosed_comment_in_closed_style": "<style>" + "/* " * 300_000 + "</style>",
        "unclosed_style_tag_open": "<style " * 9_000,
        "nested_divs": "<div>" * 9_000,
        "nested_tables": "<table><tr><td>" * 3_000,
        "misnested_b_p": "<b><p>" * 4_000,
        "many_attributes_on_one_tag": "<td " + " ".join(f"a{i}=1" for i in range(3_000)) + ">x",
    }

    def test_hostile_sizes_finish_quickly_and_stay_safe(self):
        for name, payload in self.PAYLOADS.items():
            with self.subTest(payload=name):
                start = time.monotonic()
                out = sanitize_email_html(payload + f"<img src=//{HOST}/x>")
                self.assertLess(time.monotonic() - start, SLOW_BUDGET_S)
                self.assertNotIn(HOST, out)

    def test_oversized_inputs_are_cut_and_fast(self):
        payloads = {
            "nested_divs": "<div>" * 200_000,
            "one_huge_tag": "<td " + " ".join(f"a{i}=1" for i in range(100_000)) + ">x",
            "unclosed_style_repeats": "<style>" * 40_000,
        }
        for name, payload in payloads.items():
            with self.subTest(payload=name):
                start = time.monotonic()
                sanitize_email_html(payload)
                self.assertLess(time.monotonic() - start, SLOW_BUDGET_S)

    def test_input_is_capped(self):
        out = sanitize_email_html("a" * (MAX_HTML_CHARS + 500))
        self.assertEqual(len(out), MAX_HTML_CHARS)


class SanitizeEmailHtmlStyleBlockTests(SimpleTestCase):
    def test_block_with_fetching_token_is_dropped_whole(self):
        for css in (
            "p{color:red}@font-face{font-family:x}",
            "p{color:red}div{background:url(x)}",
            "p{color:red}@import 'x'",
        ):
            with self.subTest(css=css):
                self.assertNotIn("<style>", sanitize_email_html(f"<style>{css}</style><p>t</p>"))

    def test_every_resource_function_drops_the_block(self):
        for fn in ("src(x)", "image-set(x 1x)", "image(x)", "cross-fade(x,y)", "element(#a)"):
            with self.subTest(fn=fn):
                out = sanitize_email_html(f"<style>p{{color:red;background:{fn}}}</style><p>t</p>")
                self.assertNotIn("<style>", out)

    def test_blocks_that_could_hide_or_overlay_the_header_are_dropped(self):
        for rule in (
            ".hdr{display:none}", ".hdr{display : none !important}",
            "table{position:fixed;top:0}", "td{visibility:hidden}", "th{opacity:0}",
            "table{z-index:99}", "table{transform:scale(0)}", "th{float:right}",
        ):
            with self.subTest(rule=rule):
                self.assertNotIn("<style>", sanitize_email_html(f"<style>{rule}</style><p>t</p>"))

    def test_ordinary_newsletter_css_survives(self):
        css = "body{margin:0;color:#333;font-family:Arial}td{width:600px;text-align:center}"
        self.assertIn(css, sanitize_email_html(f"<style>{css}</style><p>t</p>"))

    def test_harmless_class_names_do_not_drop_the_block(self):
        out = sanitize_email_html("<style>.image-wrap{color:red}.src{margin:0}</style><p>t</p>")
        self.assertIn(".image-wrap{color:red}", out)


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
