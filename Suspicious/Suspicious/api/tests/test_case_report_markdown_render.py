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

    def test_virustotal_link_is_a_copyable_code_span(self):
        b = _block("ip", "203.0.113.7", "Dangerous", 87)
        b.vt_link = "https://www.virustotal.com/gui/ip-address/203.0.113.7"
        md = build_markdown_report(_report(blocks=[b]))
        self.assertIn("VirusTotal: `https://www.virustotal.com/gui/ip-address/203.0.113.7`", md)

    def test_zero_confidence_is_not_printed(self):
        md = build_markdown_report(_report(blocks=[_block("ip", "203.0.113.7", "Dangerous", 0)],
                                           case_analysis=_block("file", "a" * 64, "Safe", 0)))
        self.assertNotIn("confidence 0", md)

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
        self.assertFalse(any(ln.startswith("# Evil") for ln in md.splitlines()))
        table = [ln for ln in md.splitlines() if ln.startswith("| ") and "evil.test" in ln]
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


_P = "<i>[x](javascript:1)|http://evil.test"
_SPAN = re.compile(r"``.*?``|`[^`]*`")


def _outside(md):
    return _SPAN.sub("", md)


def _pipes(line):
    return len(re.findall(r"(?<!\\)\|", line))


def _marker(field):
    return f"mk{_FIELDS.index(field)}x"  # distinct per field; "x" keeps mk1x apart from mk10x


def _tainted_report(target):
    def t(name):
        return _P + _marker(name) if name == target else "ok"

    def block(prefix, value):
        return IndicatorBlock(
            t(prefix + "type"), value, t(prefix + "band"), 90, [t(prefix + "why")], [t(prefix + "finding")],
            [DetailGroup(t(prefix + "group"), [(t(prefix + "key"), t(prefix + "val"))])],
            [ConnectorLine("🔴", t(prefix + "conn_name"), t(prefix + "conn_label"), "malicious", 1)],
            "https://" + t(prefix + "vt_link"),
            {"value": "http://evil.test/d", "via_analyzer": t(prefix + "via")},
            escalation_note=t(prefix + "esc"))

    ai = {"result": t("ai.result"), "sub_class": t("ai.sub_class"), "tier": t("ai.tier"),
          "runner_up": {"result": t("ai.runner_up")}, "model_version": t("ai.model_version"),
          "analysed_at": t("ai.analysed_at"), "reads": t("ai.reads"),
          "campaign": {"ref": t("ai.campaign_ref"), "size": 2, "labels": {t("ai.label"): 1}},
          "similar_cases": [{"case_id": 4, "label": t("ai.similar")}],
          "cross_check": {"facts": [{"kind": "rule", "text": t("ai.fact")}], "disagrees": True}}
    value = "http://evil.test/p"
    return _report(
        kind="mail", band=t("band"), confidence=t("confidence"), threat={"label": t("threat.label"), "category": t("threat.category")},
        health=t("health"), lead=t("lead"), reporter=t("reporter"), created=t("created"), generated=t("generated"), description=t("description"),
        reporter_context=t("reporter_context"), why=[t("why")], ai=ai,
        case_connectors=[ConnectorLine("🔴", t("cc.name"), t("cc.label"), "malicious", 1),
                         ConnectorLine("🔴", "Analyzer_1 (" + t("cc.attachment") + ")", "ok", "malicious", 1)],
        case_analysis=block("ca.", "ok"),
        rows=[IndicatorRow(t("row.type"), value, t("row.band"), t("row.top")), IndicatorRow("ip", "203.0.113.7", "Safe", None)],
        blocks=[block("b.", value)])


_FIELDS = (
    "band confidence threat.label threat.category health lead reporter description reporter_context why "
    "ai.result ai.sub_class ai.runner_up ai.model_version ai.analysed_at ai.reads ai.campaign_ref ai.label "
    "created generated row.band ai.tier ai.similar ai.fact cc.name cc.label cc.attachment row.type row.top"
).split() + [p + f for p in ("ca.", "b.") for f in (
    "type band why finding group key val conn_name conn_label vt_link via esc".split())
    if p + f != "ca.type"]  # the case-analysis heading is the constant "## Case analysis"


class AllFieldsEscapedTests(SimpleTestCase):
    def test_field_list_is_complete(self):
        self.assertEqual(len(_FIELDS), len(set(_FIELDS)))
        self.assertEqual(len(_FIELDS), 29 + 12 + 11)  # 29 case-level, 12 indicator-block, 11 case-analysis (no type)

    def test_every_printed_string_is_escaped(self):
        for field in _FIELDS:
            with self.subTest(field=field):
                md = build_markdown_report(_tainted_report(field))
                out = _outside(md)
                self.assertIn(_marker(field), md.lower(), "this field is not rendered")
                self.assertNotIn("<i>", out)
                self.assertIsNone(re.search(r"(?<!\\)\]\(", out))
                self.assertNotIn("://", out)
                table = [ln for ln in md.splitlines() if ln.startswith("|")]
                self.assertEqual({_pipes(ln) for ln in table}, {5})

    def test_indicator_value_is_a_code_span(self):
        md = build_markdown_report(_tainted_report("none"))
        self.assertRegex(md, r"### \w+ · `http://evil.test/p`")
        self.assertIn("| `http://evil.test/p` |", md)


class DefangTests(SimpleTestCase):
    def test_urls_and_mail_addresses_are_not_linkable(self):
        raw = "see http://evil.test/x, https://evil.test, www.evil.test and bob@evil.test"
        det = [DetailGroup("Redirects", [("Final URL", raw)])]
        md = build_markdown_report(_report(lead=raw, description=raw, reporter_context=raw, why=[raw],
                                           blocks=[_block("url", "http://evil.test/x", "Dangerous", 90, findings=[raw], details=det)]))
        out = _outside(md)
        for bad in ("://", "www.evil", "@evil"):
            self.assertNotIn(bad, out)
        self.assertIn(r"http\[:\]//evil.test", out)
        self.assertIn("`http://evil.test/x`", md)


class AiLayoutTests(SimpleTestCase):
    def test_ai_lines_are_separate_blocks(self):
        ai = {"result": "Dangerous", "sub_class": "", "tier": "high", "runner_up": None, "model_version": "v3",
              "analysed_at": "t", "reads": "body", "campaign": {"ref": "c1", "size": 3}, "similar_cases": [],
              "cross_check": {"facts": [{"kind": "rule", "text": "Decisive rule: r"}], "disagrees": True}}
        lines = build_markdown_report(_report(kind="mail", ai=ai)).split("\n")
        i = lines.index("AI and evidence disagree")
        self.assertEqual(lines[i - 1], "")
        for prefix in ("Model v3", "Reads:", "Campaign c1"):
            j = next(k for k, ln in enumerate(lines) if ln.startswith(prefix))
            self.assertTrue(lines[j].endswith("  ") or lines[j + 1] == "", prefix)
