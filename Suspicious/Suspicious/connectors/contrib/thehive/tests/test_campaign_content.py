from datetime import datetime, timezone
from types import SimpleNamespace

from django.test import SimpleTestCase

from connectors.contrib.thehive.campaign_alert import (
    MAX_TOTAL_BYTES,
    MemberInfo,
    MemberMaterial,
    build_content,
    build_observables,
    merge_iocs,
    severity_for,
)
from connectors.contrib.thehive.campaign_iocs import Iocs, extract_iocs
from connectors.contrib.thehive.campaign_material import Attachment, MailMaterial, select_attachments

HEADERS = (
    'From: "HR Payroll" <hr@evil1.example>\r\nReply-To: help@portal.example\r\n'
    "Subject: Verify payroll\r\nMessage-ID: <m1@evil1.example>\r\n"
    "Authentication-Results: mx; spf=fail; dmarc=fail\r\n"
)
NEVER = lambda domain: False


def member(case_id, *, reporter="a@meridian.example", verdict="Dangerous", atts=(), html="", minute=10):
    text = "Pay at https://portal.example/login?u=%d" % case_id
    material = MailMaterial(headers=HEADERS, html=html, text=text,
                            eml=("From: x\r\n\r\n" + text).encode(), attachments=list(atts))
    kept, skipped = select_attachments(material.attachments)
    iocs = extract_iocs(material, kept, skipped, own_domains=("meridian.example",), is_allowed=NEVER)
    info = MemberInfo(case_id=case_id, reporter=reporter, verdict=verdict, malscore=9.0,
                      subject="Verify payroll",
                      created_at=datetime(2026, 10, 7, 10, minute, tzinfo=timezone.utc))
    return MemberMaterial(info, material, kept, skipped, iocs)


def campaign():
    return SimpleNamespace(ref="CAMP-261007-abc12", title="Verify payroll")


class ObservablesTest(SimpleTestCase):
    def setUp(self):
        self.obs = build_observables(merge_iocs([member(1).iocs, member(2).iocs]))

    def test_types_and_ioc_flags(self):
        by_type = {}
        for o in self.obs:
            by_type.setdefault(o["dataType"], []).append(o)
        for t in ("url", "domain", "mail", "mail-subject", "other"):
            self.assertIn(t, by_type)
        self.assertTrue(all(o["ioc"] for o in by_type["url"] + by_type["domain"] + by_type["mail"]))
        self.assertFalse(any(o["ioc"] for o in by_type["mail-subject"]))

    def test_amber_and_no_duplicates(self):
        self.assertTrue(all(o["tlp"] == 2 and o["pap"] == 2 for o in self.obs))
        keys = [(o["dataType"], o["data"]) for o in self.obs]
        self.assertEqual(len(keys), len(set(keys)))

    def test_every_observable_is_explained(self):
        self.assertTrue(all(o["message"] for o in self.obs))


class SeverityTest(SimpleTestCase):
    def test_levels(self):
        self.assertEqual(severity_for(["Dangerous"] * 3, 3), 3)
        self.assertEqual(severity_for(["Dangerous"] * 12, 12), 4)
        self.assertEqual(severity_for(["Suspicious", "Safe"], 2), 2)
        self.assertEqual(severity_for(["Safe"], 1), 1)


class ContentTest(SimpleTestCase):
    def _content(self, members):
        return build_content(campaign(), members, ui_base="https://sus.example")

    def test_alert_fields(self):
        c = self._content([member(1), member(2, reporter="b@meridian.example")])
        self.assertEqual(c.title, "Potential phishing campaign: Verify payroll")
        self.assertEqual((c.tlp, c.pap), (2, 2))
        self.assertIn("CAMP-261007-abc12", c.tags)
        self.assertEqual(c.source_ref, "CAMP-261007-abc12")

    def test_description_has_the_facts_an_analyst_needs(self):
        pdf = Attachment("Notice.pdf", b"%PDF-1")
        c = self._content([member(1, atts=[pdf, Attachment("empty.dat", b"")]),
                           member(2, reporter="b@meridian.example", minute=15)])
        d = c.description
        for needle in ("CAMP-261007-abc12", "2 mails", "2 reporters", "Dangerous", "spf=fail",
                       "portal.example", "evil1.example", "Notice.pdf", "empty", "10:10", "10:15",
                       "https://sus.example/investigation?open=1", "Verify payroll"):
            self.assertIn(needle, d)

    def test_only_relevant_files_are_uploaded_once(self):
        pdf = Attachment("Notice.pdf", b"%PDF-1")
        c = self._content([member(1, atts=[pdf, Attachment("empty.dat", b"")]),
                           member(2, atts=[Attachment("copy.pdf", b"%PDF-1")])])
        names = [f.filename for f in c.files]
        self.assertEqual(names.count("Notice.pdf"), 1)
        self.assertNotIn("empty.dat", names)
        self.assertNotIn("copy.pdf", names)
        self.assertIn("mail-source-case-1.eml", names)

    def test_upload_budget_is_enforced_and_reported(self):
        big = [Attachment(f"f{i}.bin", bytes([i]) * (9 * 1024 * 1024)) for i in range(8)]
        c = self._content([member(1, atts=big)])
        self.assertLessEqual(sum(len(f.data) for f in c.files), MAX_TOTAL_BYTES)
        self.assertIn("budget", c.description)
