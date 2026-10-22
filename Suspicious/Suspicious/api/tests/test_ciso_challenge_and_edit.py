"""A CISO challenges for a user in their scope but does not edit case details."""
from unittest import mock

from django.urls import reverse

from api.tests.test_ciso_submission_scope import CisoSubmissionScopeBase, _user
from case_handler.lifecycle import LifecycleState
from case_handler.models import Case

CHALLENGE_BODY = {"proposed_result": "Dangerous", "reason": "this is a real phish"}


class CisoChallengeTests(CisoSubmissionScopeBase):
    def setUp(self):
        super().setUp()
        for case in (self.in_scope, self.out_scope):
            case.is_challengeable = True
            case.lifecycle_state = LifecycleState.FINALIZED
            case.status = "Done"
            case.results = "Safe"
            case.save()

    def _challenge(self, user, case):
        return self.as_user(user).post(
            reverse("submission-challenge", args=[case.id]), CHALLENGE_BODY, format="json"
        )

    @mock.patch("api.views.submissions.notify_and_record_challenge")
    def test_ciso_challenges_for_a_user_in_scope(self, notify):
        resp = self._challenge(self.ciso, self.in_scope)
        self.assertEqual(resp.status_code, 200, resp.content)
        self.in_scope.refresh_from_db()
        self.assertTrue(self.in_scope.is_challenged)
        comment = self.in_scope.comments.get()
        self.assertEqual(comment.author, self.ciso)
        self.assertIn(f"on behalf of {self.emea_reporter.username}", comment.body)
        notify.assert_called_once()
        self.assertEqual(notify.call_args.kwargs["challenger"], self.ciso)

    @mock.patch("api.views.submissions.notify_and_record_challenge")
    def test_ciso_cannot_challenge_outside_scope(self, notify):
        resp = self._challenge(self.ciso, self.out_scope)
        self.assertEqual(resp.status_code, 404)
        self.out_scope.refresh_from_db()
        self.assertFalse(self.out_scope.is_challenged)
        notify.assert_not_called()

    @mock.patch("api.views.submissions.notify_and_record_challenge")
    def test_ciso_without_a_scope_cannot_challenge_others(self, notify):
        self.set_scope("Not defined")
        self.assertEqual(self._challenge(self.ciso, self.in_scope).status_code, 404)
        notify.assert_not_called()

    @mock.patch("api.views.submissions.notify_and_record_challenge")
    def test_a_plain_user_still_cannot_challenge_someone_elses_case(self, notify):
        other = _user("ss_plain")
        self.assertEqual(self._challenge(other, self.in_scope).status_code, 404)
        notify.assert_not_called()

    @mock.patch("api.views.submissions.notify_and_record_challenge")
    def test_the_reporter_still_challenges_their_own(self, notify):
        resp = self._challenge(self.emea_reporter, self.in_scope)
        self.assertEqual(resp.status_code, 200, resp.content)
        comment = self.in_scope.comments.get()
        self.assertEqual(comment.author, self.emea_reporter)
        self.assertNotIn("on behalf of", comment.body)


class CisoCannotEditCaseDetailsTests(CisoSubmissionScopeBase):
    def _edit(self, user, case):
        with mock.patch("api.views.investigations.emit"):
            return self.as_user(user).patch(
                reverse("investigation-edit-global", kwargs={"case_id": case.id}),
                {"score": 1, "confidence": 20, "classification": "SAFE"},
                format="json",
            )

    def test_ciso_is_refused_even_inside_scope(self):
        self.assertEqual(self._edit(self.ciso, self.in_scope).status_code, 403)

    def test_cert_may_edit(self):
        cert = _user("ss_cert_edit", groups=["CERT"])
        self.assertEqual(self._edit(cert, self.in_scope).status_code, 200)

    def test_a_user_who_is_both_cert_and_ciso_may_edit(self):
        both = _user("ss_cert_ciso_edit", groups=["CERT", "CISO"])
        self.assertEqual(self._edit(both, self.out_scope).status_code, 200)
