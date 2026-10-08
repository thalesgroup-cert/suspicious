from types import SimpleNamespace

from django.contrib.auth.models import User
from django.test import TestCase

from case_handler.case_utils.case_creator import CaseCreator, unexpected_case_shape
from mail_feeder.models import Mail
from url_process.models import URL
from django.utils import timezone

OBJ = SimpleNamespace  # stands in for a model instance (truthy, has attributes)


def _file(hash_pk=1):
    return OBJ(pk=10, linked_hash_id=hash_pk)


class UnexpectedCaseShapeTests(TestCase):
    def test_allowed_shapes_return_none(self):
        h = OBJ(pk=1)
        for artifacts in (
            {},
            {"mail_instance": OBJ()},
            {"file_instance": _file()},
            {"file_instance": _file(1), "hash_instance": h},          # the 97 prod cases
            {"url_instance": OBJ()},
            {"ip_instance": OBJ(), "url_instance": OBJ(), "hash_instance": OBJ(pk=2)},
            {"observable_group_instance": OBJ()},
        ):
            self.assertIsNone(unexpected_case_shape(artifacts), artifacts)

    def test_non_artifact_keys_and_falsy_values_are_ignored(self):
        h = OBJ(pk=1)
        self.assertIsNone(unexpected_case_shape({
            "allow_listed": True, "allow_reason": "x",
            "file_instance": _file(1), "hash_instance": h,
            "mail_instance": None, "url_instance": None, "ip_instance": None,
        }))

    def test_unexpected_shapes_are_described(self):
        self.assertEqual(unexpected_case_shape({"mail_instance": OBJ(), "url_instance": OBJ()}), "mail+url")
        self.assertEqual(unexpected_case_shape({"file_instance": _file(1), "hash_instance": OBJ(pk=99)}), "file+hash")
        self.assertEqual(unexpected_case_shape({"file_instance": _file(), "url_instance": OBJ()}), "file+url")
        self.assertEqual(unexpected_case_shape({"observable_group_instance": OBJ(), "url_instance": OBJ()}), "group+url")


class CreateCaseWarnsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("u", "u@x.io", "pw")

    def test_mail_plus_url_warns_but_still_creates_the_case(self):
        mail = Mail.objects.create(subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id="m1")
        url = URL.objects.create(address="http://a.test/")
        with self.assertLogs("case_handler.case_utils.case_creator", "WARNING") as logs:
            case = CaseCreator(self.user).create_case(mail_instance=mail, url_instance=url)
        self.assertIsNotNone(case)
        self.assertIn("mail+url", logs.output[0])
        self.assertIn(str(case.id), logs.output[0])

    def test_url_alone_does_not_warn(self):
        url = URL.objects.create(address="http://b.test/")
        with self.assertNoLogs("case_handler.case_utils.case_creator", "WARNING"):
            self.assertIsNotNone(CaseCreator(self.user).create_case(url_instance=url))


class RealModelShapeTests(TestCase):
    def test_file_with_own_hash_is_allowed_other_hash_is_not(self):
        from file_process.models import File
        from hash_process.models import Hash

        h = Hash.objects.create(value="a" * 64)
        other = Hash.objects.create(value="b" * 64)
        f = File.objects.create(linked_hash=h, file_path="x.bin", tmp_path="", other_names="")
        self.assertIsNone(unexpected_case_shape({"file_instance": f, "hash_instance": h}))
        self.assertEqual(unexpected_case_shape({"file_instance": f, "hash_instance": other}), "file+hash")
