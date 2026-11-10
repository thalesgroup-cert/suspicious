import re

from django.test import SimpleTestCase

from api.utils.case_report_markdown import build_markdown_report
from api.utils.case_report_model import CaseReport, IndicatorBlock, IndicatorRow
from api.utils.report_facts import LEGEND, ConnectorLine, DetailGroup


def _report(**kw):
    base = dict(case_id=7, kind="group", band="Dangerous", confidence="87%", threat=None, health=None,
                lead=None, reporter="r@x.test", created="2026-11-09T08:00:00Z",
                generated="2026-11-10T08:00:00Z", description="", reporter_context="", why=[])
    base.update(kw)
    return CaseReport(**base)


def _block(dtype, value, band, conf, findings=(), details=(), connectors=()):
    return IndicatorBlock(dtype, value, band, conf, [], list(findings), list(details), list(connectors), None, None)


class RenderTests(SimpleTestCase):
    def test_block_layout(self):
        md = build_markdown_report(_report(blocks=[_block("ip", "203.0.113.7", "Dangerous", 87,
            findings=["2 of 91 VirusTotal engines flag it as malicious"],
            details=[DetailGroup("Location", [("Country", "NL")])],
            connectors=[ConnectorLine("🔴", "VirusTotal_GetReport_3_1", "2/91 detections", "malicious", 1)])]))
        self.assertIn("### IP · `203.0.113.7`", md)
        self.assertIn("Verdict: 🔴 Dangerous · confidence 87%", md)
        self.assertIn("- 🔴 VirusTotal_GetReport_3_1: 2/91 detections", md)
        self.assertIn("**Legend** " + LEGEND, md)
        self.assertNotIn("**Details**\n\n**Connectors**", md)

    def test_empty_groups_and_fields_are_not_rendered(self):
        md = build_markdown_report(_report(blocks=[_block("hash", "a" * 64, "Safe", 40)]))
        for word in ("**Key findings**", "**Details**", "VirusTotal: http"):
            self.assertNotIn(word, md)

    def test_indicator_value_and_details_are_escaped(self):
        v = "http://evil.test/`a`|b<script>alert(1)</script>[x](javascript:1)"
        md = build_markdown_report(_report(
            rows=[IndicatorRow("url", v, "Dangerous", "[y](javascript:2)")],
            blocks=[_block("url", v, "Dangerous", 90,
                           findings=["# Evil <b>"], connectors=[ConnectorLine("🔴", "<i>x", "[l](javascript:3)", "m", 1)],
                           details=[DetailGroup("Whois/RDAP", [("Registrar", "# Evil_ *Corp*")])])]))
        outside = re.sub(r"``.*?``", "", md)  # code spans are inert
        self.assertIsNone(re.search(r"(?<!\\)\]\(", outside))  # no live link outside a code span
        self.assertNotIn("<script>", outside)
        self.assertNotIn("<b>", md)
        self.assertNotIn("<i>", md)
        self.assertIn(r"Registrar: \# Evil\_ \*Corp\*", md)
        self.assertFalse(any(l.startswith("# Evil") for l in md.splitlines()))
        table = [l for l in md.splitlines() if l.startswith("| ") and "evil.test" in l]
        self.assertEqual(table[0].count("|") - table[0].count("\\|"), 5)

    def test_mail_ai_section(self):
        ai = {"result": "Unwanted", "sub_class": "spam", "tier": "low", "runner_up": {"result": "Safe"},
              "model_version": "v3", "analysed_at": "2026-11-09T08:00:00Z",
              "reads": "body text only, not headers or attachments", "similar_cases": [],
              "campaign": None, "cross_check": None}
        md = build_markdown_report(_report(kind="mail", ai=ai))
        self.assertIn("## AI model assessment", md)
        self.assertIn("runner-up: Safe", md)
        self.assertIn("body text only, not headers or attachments", md)
        self.assertNotIn("Decisive rule", md)

    def test_ai_fields_are_escaped_and_cross_check_rendered(self):
        ai = {"result": "Dangerous", "sub_class": "", "tier": "high", "runner_up": None, "model_version": "v3",
              "analysed_at": "t", "reads": "body", "campaign": {"ref": "# C_1 <b>", "size": 3, "labels": {"Safe*": 1}},
              "similar_cases": [{"case_id": 4, "label": "[x](javascript:1)"}],
              "cross_check": {"facts": [{"kind": "rule", "text": "Decisive rule: <u>r</u>"}], "disagrees": True}}
        md = build_markdown_report(_report(kind="mail", ai=ai))
        self.assertIn("Campaign \\# C_1 \\<b\\> · 3 mails · labels Safe\\* 1", md)
        self.assertIsNone(re.search(r"(?<!\\)\]\(", md))
        self.assertNotIn("<u>", md)
        self.assertIn("Decisive rule", md)
        self.assertIn("AI and evidence disagree", md)

    def test_more_line_and_no_indicators(self):
        rows = [IndicatorRow("ip", "203.0.113.7", "Dangerous", None)]
        self.assertIn("+3 more flagged indicators", build_markdown_report(_report(kind="mail", more=3, rows=rows)))
        self.assertIn("No indicator observables on this case.", build_markdown_report(_report(kind="none")))
