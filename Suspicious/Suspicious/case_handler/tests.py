# from django.test import TestCase
# from django.contrib.auth import get_user_model
# from django.utils import timezone
# from cases.models import Case, CaseHasFileOrMail, CaseHasNonFileIocs
# from mail_process.models import Mail
# from file_process.models import File, Hash
# from url_process.models import URL
# from ip_process.models import IP

# User = get_user_model()

# class CaseModelTest(TestCase):
#     def setUp(self):
#         self.user = User.objects.create_user(username='analyst', password='securepass')
#         self.file = File.objects.create(file_path='example.exe')
#         self.mail = Mail.objects.create(subject='Test Mail')
#         self.url = URL.objects.create(address='http://example.com')
#         self.ip = IP.objects.create(address='192.168.0.1')
#         self.hash = Hash.objects.create(value='1234567890abcdef')

#         self.file_or_mail = CaseHasFileOrMail.objects.create(file=self.file, mail=self.mail)
#         self.non_file_iocs = CaseHasNonFileIocs.objects.create(url=self.url, ip=self.ip, hash=self.hash)

#         self.case = Case.objects.create(
#             description='Suspicious file attached',
#             reporter=self.user,
#             fileOrMail=self.file_or_mail,
#             nonFileIocs=self.non_file_iocs
#         )

#     def test_case_str(self):
#         self.assertEqual(str(self.case), str(self.case.pk).zfill(6))

#     def test_case_recent_publication(self):
#         self.assertTrue(self.case.was_published_recently())

#     def test_case_has_file_or_mail_str(self):
#         expected = f"{self.case} - {self.file}"
#         self.assertIn(str(self.case.fileOrMail), [
#             f"{self.case} - {self.file}",
#             f"{self.case} - {self.mail}"
#         ])

#     def test_case_has_non_file_iocs_str(self):
#         expected_strings = [str(self.url.address), str(self.ip.address), str(self.hash.value)]
#         self.assertTrue(any(e in str(self.case.nonFileIocs) for e in expected_strings))

#     def test_case_get_iocs(self):
#         iocs = self.case.fileOrMail.get_iocs()
#         self.assertEqual(iocs['file'], self.file)
#         self.assertEqual(iocs['mail'], self.mail)

#         iocs_non_file = self.case.nonFileIocs.get_iocs()
#         self.assertEqual(iocs_non_file['url'], self.url)
#         self.assertEqual(iocs_non_file['ip'], self.ip)
#         self.assertEqual(iocs_non_file['hash'], self.hash)

#     def test_case_defaults(self):
#         self.assertEqual(self.case.status, 'To Do')
#         self.assertEqual(self.case.results, 'Suspicious')
#         self.assertEqual(self.case.resultsAI, 'Suspicious')
#         self.assertEqual(self.case.categoryAI, 'Uncategorized')
