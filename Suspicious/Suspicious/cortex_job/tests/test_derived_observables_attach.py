from datetime import datetime, timezone as tz

from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case, CaseHasFileOrMail, ObservableGroup
from cortex_job.cortex_utils.derived_observables import _attach_to_case, _resolve_observable
from domain_process.models import Domain
from mail_feeder.models import Mail, MailArtifact
from url_process.models import URL


def _reporter():
    return get_user_model().objects.create_user(username="dobs_reporter", password="x")


class ResolveObservableTests(TestCase):
    def test_url_created_once(self):
        a = _resolve_observable("https://evil.example/x", "url")
        b = _resolve_observable("https://evil.example/x", "url")
        self.assertEqual(a.pk, b.pk)
        self.assertEqual(URL.objects.filter(address="https://evil.example/x").count(), 1)

    def test_domain_created_once(self):
        a = _resolve_observable("evil.example", "domain")
        b = _resolve_observable("evil.example", "domain")
        self.assertEqual(a.pk, b.pk)
        self.assertEqual(Domain.objects.filter(value="evil.example").count(), 1)

    def test_unknown_type_returns_none(self):
        self.assertIsNone(_resolve_observable("x", "bitcoin"))


class AttachToCaseTests(TestCase):
    def test_ioc_group_case_gets_observable_group_artifact(self):
        group = ObservableGroup.objects.create(label="g")
        case = Case.objects.create(observable_group=group, description="", reporter=_reporter())
        obj = _resolve_observable("https://evil.example/x", "url")
        _attach_to_case(case, obj, "url")
        _attach_to_case(case, obj, "url")  # idempotent
        self.assertEqual(group.artifacts.filter(artifact_type="URL", url=obj).count(), 1)

    def test_mail_case_gets_mail_artifact(self):
        mail = Mail.objects.create(
            subject="s", reportedBy="r@x.test",
            date=datetime(2026, 1, 1, tzinfo=tz.utc), to="a@x.test", mail_id="m1",
        )
        case = Case.objects.create(description="", reporter=_reporter())
        case.fileOrMail = CaseHasFileOrMail.objects.create(mail=mail, case=case)
        case.save()
        obj = _resolve_observable("https://evil.example/x", "url")
        _attach_to_case(case, obj, "url")
        _attach_to_case(case, obj, "url")  # idempotent
        self.assertEqual(
            MailArtifact.objects.filter(
                mail=mail, artifact_type="URL", artifactIsUrl__url=obj
            ).count(),
            1,
        )
