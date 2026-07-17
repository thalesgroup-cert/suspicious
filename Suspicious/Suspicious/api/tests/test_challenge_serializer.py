from django.test import SimpleTestCase
from api.serializers.challenge import SubmissionChallengeSerializer


class SubmissionChallengeSerializerTest(SimpleTestCase):
    def test_valid_minimal(self):
        s = SubmissionChallengeSerializer(data={"proposed_result": "Safe"})
        self.assertTrue(s.is_valid(), s.errors)
        self.assertEqual(s.validated_data["proposed_result"], "Safe")
        self.assertEqual(s.validated_data.get("reason", ""), "")

    def test_valid_with_reason(self):
        s = SubmissionChallengeSerializer(
            data={"proposed_result": "Dangerous", "reason": "phishing"}
        )
        self.assertTrue(s.is_valid(), s.errors)
        self.assertEqual(s.validated_data["reason"], "phishing")

    def test_proposed_result_required(self):
        s = SubmissionChallengeSerializer(data={"reason": "x"})
        self.assertFalse(s.is_valid())
        self.assertIn("proposed_result", s.errors)

    def test_proposed_result_limited(self):
        s = SubmissionChallengeSerializer(data={"proposed_result": "Suspicious"})
        self.assertFalse(s.is_valid())
        self.assertIn("proposed_result", s.errors)

    def test_reason_max_length(self):
        s = SubmissionChallengeSerializer(
            data={"proposed_result": "Safe", "reason": "x" * 2001}
        )
        self.assertFalse(s.is_valid())
        self.assertIn("reason", s.errors)
