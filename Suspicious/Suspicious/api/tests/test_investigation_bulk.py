from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from case_handler.lifecycle import LifecycleState
from case_handler.models import Case, CaseHasNonFileIocs, Result
from url_process.models import URL

User = get_user_model()
VERDICT = {"classification": "DANGEROUS", "score": 9, "confidence": 90}


def _user(username, *groups):
    user = User.objects.create_user(username=username, password="pw-12345")
    for name in groups:
        user.groups.add(Group.objects.get_or_create(name=name)[0])
    return user


class BulkBase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.reporter = _user("bulk_reporter")
        self.cert = _user("bulk_cert", "CERT")
        self.admin = _user("bulk_admin", "Admin")
        self.ciso = _user("bulk_ciso", "CISO")

    def case(self, state=LifecycleState.FINALIZED, results=Result.SAFE, with_target=True):
        case = Case.objects.create(reporter=self.reporter, description="", lifecycle_state=state, results=results)
        if with_target:
            case.nonFileIocs = CaseHasNonFileIocs.objects.create(case=case, url=URL.objects.create(address="http://x.test"))
            case.save()
        return case

    def post(self, name, user, **body):
        self.client.force_authenticate(user)
        return self.client.post(reverse(name), body, format="json")

    @staticmethod
    def by_id(resp):
        return {r["case_id"]: r for r in resp.data["results"]}


class BulkVerdictTest(BulkBase):
    @patch("api.views.investigations.emit")
    def test_overrides_every_selected_case_and_emits_per_case(self, emit):
        a, b = self.case(), self.case()
        resp = self.post("investigation-bulk-verdict", self.cert, case_ids=[a.id, b.id], **VERDICT)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual([r["outcome"] for r in resp.data["results"]], ["updated", "updated"])
        for c in (a, b):
            c.refresh_from_db()
            self.assertEqual((c.results, c.final_score, c.final_confidence, c.last_update_by), ("Dangerous", 9, 90, self.cert))
        self.assertEqual(emit.call_count, 2)

    @patch("api.views.investigations.emit")
    def test_a_missing_case_fails_alone(self, emit):
        a = self.case()
        resp = self.post("investigation-bulk-verdict", self.admin, case_ids=[a.id, 999999], **VERDICT)
        out = self.by_id(resp)
        self.assertEqual(out[a.id]["outcome"], "updated")
        self.assertEqual(out[999999]["outcome"], "failed")

    def test_only_cert_and_admin_may_use_it(self):
        a = self.case()
        for user in (self.ciso, self.reporter):
            self.assertEqual(self.post("investigation-bulk-verdict", user, case_ids=[a.id], **VERDICT).status_code, 403)
        a.refresh_from_db()
        self.assertEqual(a.results, Result.SAFE)

    def test_validates_ids_and_verdict(self):
        for body in ({"case_ids": [], **VERDICT}, {"case_ids": list(range(1, 102)), **VERDICT},
                     {"case_ids": [1], "classification": "SAFE", "score": 11, "confidence": 5}):
            self.assertEqual(self.post("investigation-bulk-verdict", self.cert, **body).status_code, 400)

    @patch("api.views.investigations.emit")
    def test_duplicate_ids_are_applied_once(self, emit):
        a = self.case()
        resp = self.post("investigation-bulk-verdict", self.cert, case_ids=[a.id, a.id], **VERDICT)
        self.assertEqual(len(resp.data["results"]), 1)
        self.assertEqual(emit.call_count, 1)


class BulkRedoTest(BulkBase):
    @patch("api.views.investigations.dispatch_case_analysis")
    def test_queues_finalised_cases_and_skips_the_rest_with_a_reason(self, dispatch):
        done = self.case()
        busy = self.case(state=LifecycleState.ANALYZING)
        empty = self.case(with_target=False)
        resp = self.post("investigation-bulk-redo", self.cert, case_ids=[done.id, busy.id, empty.id])
        self.assertEqual(resp.status_code, 200)
        out = self.by_id(resp)
        self.assertEqual(out[done.id]["outcome"], "queued")
        self.assertEqual((out[busy.id]["outcome"], out[busy.id]["detail"]), ("skipped", "Case is still being analyzed."))
        self.assertEqual((out[empty.id]["outcome"], out[empty.id]["detail"]), ("skipped", "No analyzable artifacts on this case."))
        dispatch.delay.assert_called_once()
        done.refresh_from_db()
        self.assertEqual(done.lifecycle_state, LifecycleState.ANALYZING)

    def test_only_cert_and_admin_may_use_it(self):
        a = self.case()
        self.assertEqual(self.post("investigation-bulk-redo", self.ciso, case_ids=[a.id]).status_code, 403)

    def test_cap_is_enforced(self):
        self.assertEqual(self.post("investigation-bulk-redo", self.cert, case_ids=list(range(1, 102))).status_code, 400)
