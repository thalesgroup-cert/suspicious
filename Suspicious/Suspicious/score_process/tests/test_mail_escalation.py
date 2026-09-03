from django.test import SimpleTestCase
from case_handler.models import Result
from score_process.scoring.engine import CaseVerdict, mail_band_escalation
from score_process.scoring.observable_engine import ObservableVerdict


def cv(result, score=2):
    return CaseVerdict(final_score=score, final_confidence=80, result=result, n_malicious=0, n_scored=3)


def ov(band):
    return ObservableVerdict(band, 80, None, {}, [])


class MailBandEscalationTests(SimpleTestCase):
    def test_embedded_dangerous_escalates_safe_mail(self):
        out = mail_band_escalation(cv(Result.SAFE, score=2), [ov("Safe"), ov("Dangerous")])
        self.assertEqual(out.result, Result.DANGEROUS)
        self.assertEqual(out.final_score, 2)  # score unchanged
        self.assertTrue(out.rationale)

    def test_never_lowers(self):
        out = mail_band_escalation(cv(Result.DANGEROUS, score=9), [ov("Safe")])
        self.assertEqual(out.result, Result.DANGEROUS)

    def test_no_embedded_is_noop(self):
        v = cv(Result.SAFE)
        self.assertEqual(mail_band_escalation(v, []).result, Result.SAFE)

    def test_suspicious_embedded_escalates_safe_to_suspicious(self):
        out = mail_band_escalation(cv(Result.SAFE), [ov("Suspicious")])
        self.assertEqual(out.result, Result.SUSPICIOUS)

    def test_does_not_escalate_allowlisted_or_failure(self):
        for r in (Result.ALLOW_LISTED, Result.FAILURE, Result.UNCHALLENGED):
            out = mail_band_escalation(cv(r), [ov("Dangerous")])
            self.assertEqual(out.result, r)

    def test_old_positional_construction_still_works(self):
        v = CaseVerdict(2, 80, Result.SAFE, 0, 3, False, "")
        self.assertEqual(v.result, Result.SAFE)
        self.assertEqual(v.rationale, ())
        self.assertEqual(v.n_failed, 0)
        self.assertEqual(v.inconclusive_reason, "")
