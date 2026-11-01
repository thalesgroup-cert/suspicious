from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from case_handler.models import Case

User = get_user_model()


def _make_user(username, *, groups=()):
    user = User.objects.create_user(username=username, password="pw-12345")
    for name in groups:
        group, _ = Group.objects.get_or_create(name=name)
        user.groups.add(group)
    return user


class InvestigationGlobalEditVerdictExplanationTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.reporter = _make_user("ge_reporter")
        self.analyst = _make_user("ge_analyst", groups=["CERT"])

    @patch("api.views.investigations.emit")
    def test_patch_emits_case_modified_instead_of_mailing_inline(self, emit):
        case = Case.objects.create(reporter=self.reporter, description="", results="Dangerous")
        self.client.force_authenticate(self.analyst)
        resp = self.client.patch(
            reverse("investigation-edit-global", kwargs={"case_id": case.id}),
            {"score": 1, "confidence": 20, "classification": "SAFE"},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        emit.assert_called_once()
        self.assertEqual(emit.call_args.args[0], "case_modified")
        self.assertEqual(emit.call_args.args[1].id, case.id)

    @patch("api.views.investigations.emit")
    def test_patch_clears_stale_verdict_explanation(self, _emit):
        case = Case.objects.create(
            reporter=self.reporter, description="", results="Dangerous",
            verdict_explanation={"band": "Dangerous", "reporter_paragraph": "old"},
        )
        self.client.force_authenticate(self.analyst)
        resp = self.client.patch(
            reverse("investigation-edit-global", kwargs={"case_id": case.id}),
            {"score": 1, "confidence": 20, "classification": "SAFE"},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        case.refresh_from_db()
        self.assertEqual(case.results, "Safe")
        self.assertIsNone(case.verdict_explanation)


class InvestigationVerdictLedgerTest(TestCase):
    """Ruling D6: a verdict row while ai_model is enabled; a ledger failure never fails the verdict."""

    def setUp(self):
        self.client = APIClient()
        self.reporter = _make_user("vl_reporter")
        self.analyst = _make_user("vl_analyst", groups=["CERT"])
        self.case = Case.objects.create(reporter=self.reporter, description="", results="Dangerous")
        self.client.force_authenticate(self.analyst)

    def _enable(self, enabled):
        from connectors.models import ConnectorState
        ConnectorState.objects.update_or_create(name="ai_model", defaults={"enabled": enabled})

    def _patch(self):
        return self.client.patch(
            reverse("investigation-edit-global", kwargs={"case_id": self.case.id}),
            {"score": 1, "confidence": 20, "classification": "SAFE"},
            format="json",
        )

    @patch("api.views.investigations.emit")
    def test_enabled_writes_a_verdict_row(self, _emit):
        from ai_model.models import LabelRecord
        self._enable(True)
        self.assertEqual(self._patch().status_code, 200)
        row = LabelRecord.objects.get()
        self.assertEqual((row.case, row.source, row.label_class, row.source_ref),
                         (self.case, "analyst_verdict", "Safe", "vl_analyst"))

    @patch("api.views.investigations.emit")
    def test_disabled_writes_nothing(self, _emit):
        from ai_model.models import LabelRecord
        self._enable(False)
        self.assertEqual(self._patch().status_code, 200)
        self.assertFalse(LabelRecord.objects.exists())

    @patch("api.views.investigations.emit")
    def test_bulk_verdict_writes_a_row_per_case(self, _emit):
        from ai_model.models import LabelRecord
        self._enable(True)
        other = Case.objects.create(reporter=self.reporter, description="", results="Safe")
        resp = self.client.post(reverse("investigation-bulk-verdict"),
                                {"case_ids": [self.case.id, other.id], "classification": "DANGEROUS",
                                 "score": 9, "confidence": 90}, format="json")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(sorted(LabelRecord.objects.values_list("case_id", flat=True)),
                         sorted([self.case.id, other.id]))

    @patch("api.views.investigations.emit")
    @patch("ai_model.ledger.record_verdict", side_effect=RuntimeError("boom secret@mail.example"))
    def test_a_ledger_failure_keeps_the_verdict(self, _record, _emit):
        self._enable(True)
        with self.assertLogs("api.views.investigations", "WARNING") as logs:
            resp = self._patch()
        self.assertEqual(resp.status_code, 200)
        self.case.refresh_from_db()
        self.assertEqual(self.case.results, "Safe")
        self.assertIn("RuntimeError", logs.output[0])
        self.assertNotIn("secret@mail.example", logs.output[0])

    @patch("api.views.investigations.emit")
    def test_a_ledger_db_error_keeps_the_verdict(self, _emit):
        from django.db import IntegrityError, transaction
        from ai_model.models import LabelRecord
        self._enable(True)
        with patch.object(LabelRecord, "_save_table", side_effect=IntegrityError("x")), \
                self.assertLogs("api.views.investigations", "WARNING"):
            with transaction.atomic():
                resp = self._patch()
        self.assertEqual(resp.status_code, 200)
        self.case.refresh_from_db()
        self.assertEqual(self.case.results, "Safe")
