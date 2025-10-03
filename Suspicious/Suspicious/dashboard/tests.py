from django.test import TestCase
from django.contrib.auth.models import User
from .models import UserCasesMonthlyStats

class UserCasesMonthlyStatsTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.stats = UserCasesMonthlyStats.objects.create(
            user=self.user,
            month='January',
            year='2022',
            suspicious_cases=5,
            inconclusive_cases=3,
            failure_cases=2,
            dangerous_cases=1,
            safe_cases=10,
            challenged_cases=4,
            allow_listed_cases=7,
            total_cases=32
        )

    def test_str_representation(self):
        self.assertEqual(str(self.stats), 'testuser - January - 2022')

    def test_update_case_results(self):
        self.stats.update_case_results('Safe')
        self.assertEqual(self.stats.safe_cases, 11)

        self.stats.update_case_results('Suspicious')
        self.assertEqual(self.stats.suspicious_cases, 6)

        self.stats.update_case_results('Failure')
        self.assertEqual(self.stats.failure_cases, 3)

        self.stats.update_case_results('InvalidCase')  # Invalid case should not update any counts
        self.assertEqual(self.stats.safe_cases, 11)
        self.assertEqual(self.stats.suspicious_cases, 6)
        self.assertEqual(self.stats.failure_cases, 3)