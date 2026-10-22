from django.test import SimpleTestCase
from api.serializers.challenge import SubmissionChallengeSerializer


class SubmissionChallengeSerializerTest(SimpleTestCase):
    def test_reason_is_required(self):
        for data in ({"proposed_result": "Safe"}, {"proposed_result": "Safe", "reason": "  "},
                     {"proposed_result": "Safe", "reason": "too short"}):
            s = SubmissionChallengeSerializer(data=data)
            self.assertFalse(s.is_valid(), data)
            self.assertIn("reason", s.errors)

    def test_valid_with_reason(self):
        s = SubmissionChallengeSerializer(
            data={"proposed_result": "Dangerous", "reason": "it is phishing"}
        )
        self.assertTrue(s.is_valid(), s.errors)
        self.assertEqual(s.validated_data["reason"], "it is phishing")

    def test_proposed_result_required(self):
        s = SubmissionChallengeSerializer(data={"reason": "a proper reason"})
        self.assertFalse(s.is_valid())
        self.assertIn("proposed_result", s.errors)

    def test_proposed_result_limited(self):
        s = SubmissionChallengeSerializer(data={"proposed_result": "Suspicious", "reason": "a proper reason"})
        self.assertFalse(s.is_valid())
        self.assertIn("proposed_result", s.errors)

    def test_reason_max_length(self):
        s = SubmissionChallengeSerializer(
            data={"proposed_result": "Safe", "reason": "x" * 2001}
        )
        self.assertFalse(s.is_valid())
        self.assertIn("reason", s.errors)
