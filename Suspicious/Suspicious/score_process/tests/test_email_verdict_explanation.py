"""Task 11: the reporter email guidance line prefers
Case.verdict_explanation.reporter_paragraph and falls back to _RESULT_GUIDANCE."""
from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case
from score_process.score_utils.send_mail.final_service import (
    FinalEmailService, _RESULT_GUIDANCE as FINAL_GUIDANCE,
)
from score_process.score_utils.send_mail.modification_service import (
    ModificationEmailService, _RESULT_GUIDANCE as MOD_GUIDANCE,
)

_PARAGRAPH = "Confirmed malicious. Do not click."


class EmailVerdictExplanationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="evx_u", password="x")

    def _case(self, verdict_explanation):
        return Case.objects.create(
            description="t", reporter=self.user, results="Dangerous",
            verdict_explanation=verdict_explanation,
        )

    def _final_ctx(self, case):
        svc = FinalEmailService(
            case=case, sender="s@x.test", recipient="r@x.test", recipient_name="R",
        )
        return svc._build_case_context()

    def _mod_ctx(self, case):
        svc = ModificationEmailService(
            subject="s", sender="s@x.test", recipient="r@x.test",
            recipient_name="R", case=case,
        )
        return svc._build_case_context()

    def test_final_uses_reporter_paragraph(self):
        case = self._case({"band": "Dangerous", "reporter_paragraph": _PARAGRAPH})
        self.assertEqual(self._final_ctx(case)["result_guidance"], _PARAGRAPH)

    def test_final_falls_back_to_guidance(self):
        case = self._case(None)
        self.assertEqual(
            self._final_ctx(case)["result_guidance"], FINAL_GUIDANCE["Dangerous"]
        )

    def test_modification_uses_reporter_paragraph(self):
        case = self._case({"band": "Dangerous", "reporter_paragraph": _PARAGRAPH})
        self.assertEqual(self._mod_ctx(case)["result_guidance"], _PARAGRAPH)

    def test_modification_falls_back_to_guidance(self):
        case = self._case(None)
        self.assertEqual(
            self._mod_ctx(case)["result_guidance"], MOD_GUIDANCE["Dangerous"]
        )
