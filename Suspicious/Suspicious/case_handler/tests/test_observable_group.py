from django.test import TestCase
from ip_process.models import IP
from url_process.models import URL
from case_handler.models import ObservableGroup, ObservableGroupArtifact


class ObservableGroupTests(TestCase):
    def test_group_holds_many_artifacts(self):
        g = ObservableGroup.objects.create(label="alert #1")
        ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=IP.objects.create(address="1.1.1.1"))
        ObservableGroupArtifact.objects.create(group=g, artifact_type="URL", url=URL.objects.create(address="http://x.test"))
        self.assertEqual(g.artifacts.count(), 2)

    def test_artifact_str(self):
        g = ObservableGroup.objects.create()
        a = ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=IP.objects.create(address="9.9.9.9"))
        self.assertIn("9.9.9.9", str(a))


from django.contrib.auth.models import User
from case_handler.models import Case


class CaseObservableGroupTests(TestCase):
    def test_case_links_group_and_legacy_stays_null(self):
        u = User.objects.create_user("u", password="p")
        legacy = Case.objects.create(description="legacy", reporter=u)
        self.assertIsNone(legacy.observable_group_id)
        g = ObservableGroup.objects.create()
        c = Case.objects.create(description="grp", reporter=u, observable_group=g)
        self.assertEqual(c.observable_group_id, g.id)
        self.assertIn(c, g.cases.all())
