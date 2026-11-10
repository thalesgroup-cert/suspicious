from html.parser import HTMLParser
from pathlib import Path

from django.template.loader import get_template, render_to_string
from django.test import SimpleTestCase

from api.utils.case_report_model import CaseReport, IndicatorBlock, IndicatorRow
from api.utils.report_facts import LEGEND, ConnectorLine, DetailGroup

# Attribute-breaking and tag-injecting payload; "javascript:1" survives autoescape as text
# (case-insensitively: |upper and |title change its case) and is the per-field marker.
P = "\"onmouseover=\"x'><i>[x](javascript:1)|http://evil.test"
MARKER = "javascript:1"
VT = "https://www.virustotal.com/gui/"

_CASE = ("band confidence threat.label threat.category health lead reporter created generated description "
         "reporter_context why ai.result ai.sub_class ai.tier ai.runner_up ai.model_version ai.analysed_at ai.reads "
         "ai.campaign_ref ai.label ai.similar ai.fact cc.name cc.label cc.icon cc.attachment "
         "row.type row.band row.top row.value").split()
_BLOCK = ("type band value why finding group key val conn_name conn_label conn_icon vt_link via via_value esc "
          "screenshot").split()
FIELDS = _CASE + [p + f for p in ("ca.", "b.") for f in _BLOCK]


def tainted(target):
    def t(name, default="ok"):
        return P if name == target else default

    def block(prefix):
        b = IndicatorBlock(
            t(prefix + "type"), t(prefix + "value", "http://ok.test/p"), t(prefix + "band", "Dangerous"), 90,
            [t(prefix + "why")], [t(prefix + "finding")],
            [DetailGroup(t(prefix + "group"), [(t(prefix + "key"), t(prefix + "val"))])],
            [ConnectorLine(t(prefix + "conn_icon", "🔴"), t(prefix + "conn_name"), t(prefix + "conn_label"), "malicious", 1)],
            VT + t(prefix + "vt_link", "ok"),
            {"value": t(prefix + "via_value"), "via_analyzer": t(prefix + "via")},
            escalation_note=t(prefix + "esc"))
        # every block carries a screenshot so alt (from the value) and src are always rendered
        b.screenshot_data_uri = t(prefix + "screenshot", "data:image/png;base64,AAAA")
        return b

    ai = {"result": t("ai.result"), "sub_class": t("ai.sub_class"), "tier": t("ai.tier", "low"),
          "runner_up": {"result": t("ai.runner_up")}, "model_version": t("ai.model_version"),
          "analysed_at": t("ai.analysed_at"), "reads": t("ai.reads"),
          "campaign": {"ref": t("ai.campaign_ref"), "size": 2, "labels": {t("ai.label"): 1}},
          "similar_cases": [{"case_id": 4, "label": t("ai.similar")}],
          "cross_check": {"facts": [{"kind": "rule", "text": t("ai.fact")}], "disagrees": True}}
    return CaseReport(
        case_id=7, kind="mail", band=t("band", "Dangerous"), confidence=t("confidence"),
        threat={"label": t("threat.label"), "category": t("threat.category")}, health=t("health"),
        lead=t("lead"), reporter=t("reporter"), created=t("created"), generated=t("generated"),
        description=t("description"), reporter_context=t("reporter_context"), why=[t("why")], ai=ai,
        case_connectors=[ConnectorLine(t("cc.icon", "🔴"), t("cc.name"), t("cc.label"), "malicious", 1),
                         ConnectorLine("🔴", "Analyzer_1 (" + t("cc.attachment") + ")", "ok", "malicious", 1)],
        case_analysis=block("ca."),
        rows=[IndicatorRow(t("row.type", "url"), t("row.value", "http://ok.test/p"), t("row.band", "Dangerous"), t("row.top")),
              IndicatorRow("ip", "203.0.113.7", "Safe", None)],
        blocks=[block("b.")])


def _report(**kw):
    base = dict(case_id=7, kind="group", band="Dangerous", confidence="87%", threat=None, health=None,
                lead=None, reporter="r@x.test", created="2026-11-09T08:00:00Z",
                generated="2026-11-10T08:00:00Z", description="", reporter_context="", why=[])
    base.update(kw)
    return CaseReport(**base)


def _block(dtype, value, band, conf, details=(), connectors=()):
    return IndicatorBlock(dtype, value, band, conf, [], [], list(details), list(connectors), None, None)


def render(rep):
    return render_to_string("case_report/report.html", {"report": rep, "legend": LEGEND})


class Dom(HTMLParser):
    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.tags, self.headings, self._open = [], [], None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs), [n for n, _ in attrs]))
        if tag in ("h3", "h4"):
            self._open = [tag, ""]

    def handle_data(self, data):
        if self._open:
            self._open[1] += data

    def handle_endtag(self, tag):
        if self._open and tag == self._open[0]:
            self.headings.append(tuple(self._open))
            self._open = None

    def of(self, name):
        return [a for t, a, _ in self.tags if t == name]


ALLOWED_TAGS = set("html head meta title style body div span p b a h2 h3 h4 ul li table thead tbody tr th td "
                   "details summary img footer".split())
ALLOWED_ATTRS = {"class", "href", "rel", "src", "alt", "lang", "charset", "name", "content", "colspan"}


class HtmlRenderTests(SimpleTestCase):
    def test_field_list_is_exact(self):
        self.assertEqual(len(FIELDS), len(set(FIELDS)))
        self.assertEqual(len(FIELDS), 31 + 2 * 16)

    def test_block_heading_and_sub_labels(self):
        html = render(_report(blocks=[_block("ip", "203.0.113.7", "Dangerous", 87,
            details=[DetailGroup("Location", [("AS owner", "Evil Hosting LLC")])],
            connectors=[ConnectorLine("🔴", "VirusTotal_GetReport_3_1", "42/70 detections", "malicious", 1)])]))
        dom = Dom(html)
        self.assertIn(("h3", "IP · 203.0.113.7"), dom.headings)
        self.assertIn(("h4", "Details"), dom.headings)
        self.assertIn(("h4", "Connectors"), dom.headings)
        for s in ("Evil Hosting LLC", "42/70 detections", "confidence 87%", "band-Dangerous"):
            self.assertIn(s, html)
        self.assertNotIn("Raw report", html)
        self.assertNotIn("<pre>", html)

    def test_zero_confidence_is_not_printed(self):
        html = render(_report(blocks=[_block("ip", "203.0.113.7", "Dangerous", 0)]))
        self.assertNotIn("confidence 0", html)

    def test_only_virustotal_is_linked(self):
        b = _block("url", "http://evil.test/<script>alert(1)</script>", "Dangerous", 90,
                   details=[DetailGroup("URL", [("Final URL", "https://collect.test/x")])])
        b.vt_link = VT + "url/abc"
        dom = Dom(render(_report(blocks=[b])))
        self.assertEqual(dom.of("a"), [{"href": b.vt_link, "rel": "noopener noreferrer"}])
        self.assertEqual(dom.of("script"), [])

    def test_screenshot_is_collapsed(self):
        b = _block("url", "http://a.test", "Suspicious", 50)
        b.screenshot_data_uri = "data:image/png;base64,AAAA"
        html = render(_report(blocks=[b]))
        self.assertRegex(html, r"<details>\s*<summary>Screenshot</summary>\s*<img[^>]+data:image/png;base64,AAAA")
        self.assertEqual(Dom(html).of("img"), [{"alt": "Screenshot of http://a.test", "src": b.screenshot_data_uri}])
        b.screenshot_data_uri, b.screenshot_omitted = None, True
        self.assertIn("Screenshot omitted", render(_report(blocks=[b])))

    def test_mail_ai_card_and_table(self):
        ai = {"result": "Unwanted", "sub_class": "spam", "tier": "low", "runner_up": {"result": "Safe"},
              "model_version": "v3", "analysed_at": "t", "reads": "body text only, not headers or attachments",
              "similar_cases": [], "campaign": None, "cross_check": None}
        from api.utils.case_report_model import IndicatorRow as R
        html = render(_report(kind="mail", ai=ai, more=2, rows=[R("ip", "203.0.113.7", "Dangerous", "x")],
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
        for field in FIELDS:
            with self.subTest(field=field):
                html = render(tainted(field))
                self.assertIn(MARKER, html.lower(), "field is not rendered at all")
                dom = Dom(html)
                self.assertLessEqual({t for t, _, _ in dom.tags}, ALLOWED_TAGS)  # no <i>, <script>, ...
                for tag, _, names in dom.tags:
                    self.assertLessEqual(set(names), ALLOWED_ATTRS, tag)  # no on*, no gained attribute
                links = dom.of("a")
                self.assertEqual(len(links), 2)  # case analysis + block
                for a in links:
                    self.assertEqual(a["rel"], "noopener noreferrer")
                    self.assertTrue(a["href"].startswith("https://www.virustotal.com/"))
                for img in dom.of("img"):
                    self.assertEqual(set(img), {"src", "alt"})
                self.assertEqual(len(dom.of("img")), 2)
