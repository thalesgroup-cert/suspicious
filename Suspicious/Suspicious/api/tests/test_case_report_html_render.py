import re
from pathlib import Path

from django.template.loader import get_template, render_to_string
from django.test import SimpleTestCase

from api.tests.test_case_report_markdown_render import _FIELDS, _block, _report, _tainted_report
from api.utils.case_report_model import IndicatorRow
from api.utils.report_facts import LEGEND, ConnectorLine, DetailGroup


# The Markdown test's _FIELDS iterates the block field string character by character
# (so its per-block names are junk); rebuild the list with real names.
_FIELDS = [f for f in _FIELDS if len(f.split(".")[-1]) > 1] + [
    p + f for p in ("ca.", "b.") for f in
    "type why finding group key val conn_name conn_label vt_link via esc".split()]


def render(rep):
    return render_to_string("case_report/report.html", {"report": rep, "legend": LEGEND})


class HtmlRenderTests(SimpleTestCase):
    def test_block_has_details_and_no_raw_output(self):
        html = render(_report(blocks=[_block("ip", "203.0.113.7", "Dangerous", 87,
            details=[DetailGroup("Location", [("AS owner", "Evil Hosting LLC")])],
            connectors=[ConnectorLine("🔴", "VirusTotal_GetReport_3_1", "42/70 detections", "malicious", 1)])]))
        for s in ("Evil Hosting LLC", "42/70 detections", "confidence 87%", "band-Dangerous"):
            self.assertIn(s, html)
        self.assertNotIn("Raw report", html)
        self.assertNotIn("<pre>", html)

    def test_only_virustotal_is_linked(self):
        b = _block("url", "http://evil.test/<script>alert(1)</script>", "Dangerous", 90,
                   details=[DetailGroup("URL", [("Final URL", "https://collect.test/x")])])
        b.vt_link = "https://www.virustotal.com/gui/url/abc"
        html = render(_report(blocks=[b]))
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertEqual(re.findall(r'href="([^"]+)"', html), [b.vt_link])

    def test_screenshot_is_collapsed(self):
        b = _block("url", "http://a.test", "Suspicious", 50)
        b.screenshot_data_uri = "data:image/png;base64,AAAA"
        self.assertRegex(render(_report(blocks=[b])),
                         r"<details>\s*<summary>Screenshot</summary>\s*<img[^>]+data:image/png;base64,AAAA")
        b.screenshot_data_uri, b.screenshot_omitted = None, True
        self.assertIn("Screenshot omitted", render(_report(blocks=[b])))

    def test_mail_ai_card_and_table(self):
        ai = {"result": "Unwanted", "sub_class": "spam", "tier": "low", "runner_up": {"result": "Safe"},
              "model_version": "v3", "analysed_at": "t", "reads": "body text only, not headers or attachments",
              "similar_cases": [], "campaign": None, "cross_check": None}
        html = render(_report(kind="mail", ai=ai, more=2, rows=[IndicatorRow("ip", "203.0.113.7", "Dangerous", "x")],
                              blocks=[_block("ip", "203.0.113.7", "Dangerous", 80)]))
        for s in ("AI model assessment", "body text only, not headers or attachments", "runner-up: Safe",
                  "Dangerous", "+2 more flagged indicators"):
            self.assertIn(s, html)
        self.assertEqual(html.count(LEGEND), 1)
        self.assertIn("No indicator observables", render(_report(kind="none")))

    def test_no_unsafe_constructs_in_template(self):
        src = "".join(Path(get_template(n).origin.name).read_text()
                      for n in ("case_report/report.html", "case_report/_block.html"))
        for banned in ("|safe", "|pprint", "autoescape off", "mark_safe"):
            self.assertNotIn(banned, src)

    def test_every_printed_string_is_escaped(self):
        for field in _FIELDS:
            with self.subTest(field=field):
                html = render(_tainted_report(field))
                self.assertIn("evil", html, "field is not rendered at all")
                self.assertNotIn("<i>", html)
                self.assertNotRegex(html, r'="[^"]*"onmouseover')
                hrefs = re.findall(r'href="([^"]*)"', html)
                if field.endswith("vt_link"):
                    self.assertEqual(len(hrefs), 2)  # case_analysis + block, both validated links
                    self.assertTrue(all(h.startswith("https://") and "<" not in h for h in hrefs))
                else:
                    self.assertEqual(set(hrefs), {"https://ok"})
                self.assertEqual(len(re.findall(r"<a ", html)), len(hrefs))

    def test_attribute_breaking_payload(self):
        for field in ("band", "b.type", "ca.type", "b.key"):
            with self.subTest(field=field):
                rep = _tainted_report(field)
                for obj in (rep, rep.blocks[0], rep.case_analysis):
                    for attr in ("band", "type"):
                        if getattr(obj, attr, "") == "<i>[x](javascript:1)|http://evil.test":
                            setattr(obj, attr, '"onmouseover="x')
                html = render(rep)
                self.assertNotRegex(html, r'(?<!&quot;)"onmouseover=')
                self.assertNotIn("<i>", html)
