from types import SimpleNamespace

from django.test import SimpleTestCase

from connectors.contrib.thehive.campaign_alert import build_observables
from connectors.contrib.thehive.challenge_alert import build_challenge_content
from connectors.contrib.thehive.tests.test_campaign_content import member


def _case(**over):
    base = dict(id=351, results="Dangerous", score=10.0, confidence=96.0, category_ai="Clone",
                results_ai="Dangerous", score_ai=10, confidence_ai=96,
                verdict_rationale=[], challenge_proposed_result="Safe", challenge_reason="This is a newsletter I subscribed to.")
    return SimpleNamespace(**{**base, **over})


CHALLENGER = {"firstname": "Jordan", "lastname": "Kim", "email": "jordan.kim@meridian.example"}


class ChallengeContentTest(SimpleTestCase):
    def build(self, case=None, **kw):
        return build_challenge_content(case or _case(), member(351, **kw), CHALLENGER,
                                       ref="261021-abcde", ui_base="https://ui.example")

    def test_same_observables_as_a_campaign_alert(self):
        m = member(351)
        content = self.build()
        self.assertEqual(content.observables, build_observables(m.iocs))
        self.assertIn("url", {o["dataType"] for o in content.observables})

    def test_original_mail_and_attachment_travel_with_the_alert(self):
        from connectors.contrib.thehive.campaign_material import Attachment
        content = self.build(atts=[Attachment("invoice.pdf", b"%PDF-1.4 invoice body" * 20)])
        self.assertEqual([f.filename for f in content.files], ["mail-source-case-351.eml", "invoice.pdf"])

    def test_description_carries_challenge_details(self):
        d = self.build().description
        for text in ("Jordan Kim", "jordan.kim@meridian.example", "This is a newsletter I subscribed to.",
                     "https://ui.example/investigation?open=351", "## Indicators", "## Attachments"):
            self.assertIn(text, d)

    def test_description_opens_with_the_dispute_and_the_reason(self):
        lines = self.build().description.splitlines()
        self.assertEqual(lines[0], "# Reporter disputes **Dangerous** and proposes **Safe**")
        self.assertEqual(lines[2], "> This is a newsletter I subscribed to.")

    def test_description_is_defanged_but_observables_are_not(self):
        c = self.build()
        self.assertNotIn("https://portal", c.description)
        self.assertIn("hxxps://portal[.]example/login?u=351", c.description)
        self.assertIn("hr@evil1[.]example", c.description)
        self.assertIn("https://portal.example/login?u=351", {o["data"] for o in c.observables})

    def test_why_the_verdict_and_pointer_to_the_tabs(self):
        c = self.build(_case(verdict_rationale=["2 trusted sources flag the URL", "Sender fails DMARC"]))
        self.assertIn("## Why this verdict\n- 2 trusted sources flag the URL\n- Sender fails DMARC", c.description)
        self.assertIn("Observables tab", c.description)
        self.assertNotIn("Why this verdict", self.build().description)

    def test_empty_indicator_lines_are_left_out(self):
        d = self.build().description
        self.assertNotIn("IP addresses", d)
        self.assertNotIn("| Mails |", d)

    def test_alert_shape(self):
        c = self.build()
        self.assertEqual((c.alert_type, c.source_ref, c.severity), ("user_challenge", "261021-abcde", 3))
        self.assertIn("challenge", c.tags)
        self.assertIn("suspicious:case:351", c.tags)

    def test_missing_reason_and_proposal_are_stated(self):
        d = self.build(_case(challenge_reason="", challenge_proposed_result="")).description
        self.assertIn("No reason provided.", d)


class ChallengeSendTest(SimpleTestCase):
    """Observables are what TheHive analyses (values, and files it hashes);
    the Attachments tab holds evidence files, so a file is never sent to both."""

    def send(self, preview):
        from unittest.mock import MagicMock
        from connectors.contrib.thehive.challenge_alert import send_challenge_alert
        client = MagicMock()
        client.create_alert.return_value = {"_id": "~1"}
        m = member(351)
        m.preview = preview
        send_challenge_alert(client, _case(), m, CHALLENGER, ref="r", ui_base="")
        return client

    def test_files_are_observables_only_and_preview_is_the_attachment(self):
        client = self.send(b"\x89PNG preview")
        content = client.create_alert.call_args.args[0]
        self.assertEqual([f.filename for f in content.files], ["mail-source-case-351.eml"])
        (alert_id, parts), _ = client.add_attachments.call_args
        self.assertEqual((alert_id, [p.filename for p in parts]), ("~1", ["mail-preview-case-351.png"]))

    def test_no_preview_means_nothing_to_attach(self):
        client = self.send(b"")
        self.assertEqual(client.add_attachments.call_args.args[1], [])
