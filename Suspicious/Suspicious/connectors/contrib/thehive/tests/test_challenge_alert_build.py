from types import SimpleNamespace

from django.test import SimpleTestCase

from connectors.contrib.thehive.campaign_alert import build_observables
from connectors.contrib.thehive.challenge_alert import build_challenge_content
from connectors.contrib.thehive.tests.test_campaign_content import member


def _case(**over):
    base = dict(id=351, results="Dangerous", score=10.0, confidence=96.0, category_ai="Clone",
                results_ai="Dangerous", score_ai=10, confidence_ai=96,
                challenge_proposed_result="Safe", challenge_reason="This is a newsletter I subscribed to.")
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
                     "Safe", "Dangerous", "https://ui.example/investigation?open=351", "## Indicators",
                     "## Attachments"):
            self.assertIn(text, d)

    def test_alert_shape(self):
        c = self.build()
        self.assertEqual((c.alert_type, c.source_ref, c.severity), ("user_challenge", "261021-abcde", 3))
        self.assertIn("challenge", c.tags)
        self.assertIn("suspicious:case:351", c.tags)

    def test_missing_reason_and_proposal_are_stated(self):
        d = self.build(_case(challenge_reason="", challenge_proposed_result="")).description
        self.assertIn("No reason provided.", d)
