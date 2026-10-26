import hashlib
from contextlib import closing
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone

from case_handler.models import Campaign, CampaignMember, Case, CaseHasFileOrMail
from connectors.contrib.thehive.campaign_material import Attachment, MailMaterial
from connectors.contrib.thehive.campaign_sync import sync_campaign
from common.storage import StoreError
from common.storage.fake import FakeObjectStore, _Stream
from mail_feeder.models import Mail

S = "connectors.contrib.thehive.campaign_sync"
HEADERS = 'From: "HR" <hr@evil.example>\r\nSubject: Verify payroll\r\n'


class FakeStore(FakeObjectStore):
    def open(self, bucket, key):
        return closing(_Stream(b"PNG:" + key.encode()))


class FakeHive:
    """In-memory TheHive: just enough state to check what was sent."""

    def __init__(self):
        self.alerts, self.observables, self.comments, self.next = {}, {}, {}, 1
        self.creates = 0
        self.attachments = {}

    def _id(self):
        self.next += 1
        return f"~{self.next}"

    def create_alert(self, content):
        self.creates += 1
        aid = self._id()
        self.alerts[aid] = {"_id": aid, "title": content.title, "description": content.description,
                            "severity": content.severity, "sourceRef": content.source_ref}
        self.observables[aid] = [dict(o) for o in content.observables] + [
            {"dataType": "file", "name": f.filename, "sha": hashlib.sha256(f.data).hexdigest()} for f in content.files]
        self.comments[aid] = []
        self.attachments[aid] = {}
        return self.alerts[aid]

    def get_alert(self, aid):
        return self.alerts.get(aid)

    def find_by_source_ref(self, ref):
        return next((a for a in self.alerts.values() if a["sourceRef"] == ref), None)

    def list_observables(self, aid):
        out = []
        for o in self.observables[aid]:
            if o["dataType"] == "file":
                out.append({"dataType": "file", "attachment": {"hashes": [o["sha"]]}})
            else:
                out.append({**o, "_id": f"~o{id(o)}"})
        return out

    def add_observable_tags(self, observable_id, tags):
        for obs in self.observables_by_id(observable_id):
            obs["tags"] = tags

    def observables_by_id(self, observable_id):
        return [o for obs in self.observables.values() for o in obs if f"~o{id(o)}" == observable_id]

    def add_observable(self, aid, obs):
        self.observables[aid].append(dict(obs))

    def add_file_observable(self, aid, part, tlp=2, pap=2):
        self.observables[aid].append({"dataType": "file", "name": part.filename,
                                      "sha": hashlib.sha256(part.data).hexdigest()})

    def patch_alert(self, aid, fields):
        self.alerts[aid].update(fields)

    def add_attachments(self, aid, parts):
        added = present = 0
        for part in parts:
            if part.filename in self.attachments[aid]:
                present += 1
            else:
                self.attachments[aid][part.filename] = part.data
                added += 1
        return added, present, []

    def add_comment(self, aid, message):
        self.comments[aid].append(message)


def _member(campaign, n, *, atts=()):
    user, _ = get_user_model().objects.get_or_create(username=f"r{n}", defaults={"email": f"r{n}@meridian.example"})
    case = Case.objects.create(reporter=user, description="t", results="Dangerous", score_ai=9.0)
    mail = Mail.objects.create(subject="Verify payroll", reportedBy=user.email, to="s@x", mail_id=f"2610-{n:04d}",
                               date=timezone.now(), preview_bucket="b", preview_object_key=f"2610-{n:04d}/p.png")
    case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
    case.save(update_fields=["fileOrMail"])
    CampaignMember.objects.create(campaign=campaign, case=case)
    return case, MailMaterial(headers=HEADERS, text=f"pay https://evil{n}.example/x", eml=b"eml%d" % n,
                              attachments=list(atts))


class SyncTest(TestCase):
    def setUp(self):
        self.hive = FakeHive()
        self.campaign = Campaign.objects.create(title="Verify payroll")
        self.materials = {}
        cache.clear()

    def _add(self, n, **kw):
        case, material = _member(self.campaign, n, **kw)
        self.materials[case.fileOrMail.mail.mail_id] = material
        return case

    def _sync(self):
        with patch(f"{S}.fetch_mail_material", side_effect=lambda client, mail_id: self.materials[mail_id]):
            return sync_campaign(self.campaign, self.hive, store=FakeStore(), ui_base="https://sus.example",
                                 own_domains=("meridian.example",))

    def test_first_sync_creates_the_alert_and_marks_members(self):
        for n in (1, 2, 3):
            self._add(n, atts=[Attachment("notice.pdf", b"%PDF-1")])
        self.assertEqual(self._sync(), "created")
        self.campaign.refresh_from_db()
        alert_id = self.campaign.external_refs["thehive"]
        self.assertEqual(self.hive.alerts[alert_id]["sourceRef"], self.campaign.ref)
        self.assertTrue(all("thehive" in m.synced for m in self.campaign.members.all()))
        files = [o for o in self.hive.observables[alert_id] if o["dataType"] == "file"]
        self.assertEqual(len([f for f in files if f["name"] == "notice.pdf"]), 1)  # same hash, uploaded once

    def test_nothing_new_means_no_calls(self):
        self._add(1)
        self._sync()
        self.assertEqual(self._sync(), "up-to-date")
        self.assertEqual(self.hive.creates, 1)

    def test_a_new_member_updates_the_alert_without_duplicating_observables(self):
        self._add(1)
        self._add(2)
        self._sync()
        alert_id = self.campaign.refresh_from_db() or self.campaign.external_refs["thehive"]
        before = len(self.hive.observables[alert_id])
        late = self._add(3)
        self.assertEqual(self._sync(), "updated")
        keys = [(o["dataType"], o.get("data")) for o in self.hive.observables[alert_id] if o["dataType"] != "file"]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertGreater(len(self.hive.observables[alert_id]), before)  # evil3.example is new
        self.assertIn("3 mails", self.hive.alerts[alert_id]["description"])
        self.assertIn(str(late.id), self.hive.comments[alert_id][0])
        self.assertEqual(self.hive.creates, 1)

    def test_a_deleted_alert_is_recreated(self):
        self._add(1)
        self._sync()
        self.hive.alerts.clear()  # TheHive was reset
        CampaignMember.objects.update(synced=[])
        self.assertEqual(self._sync(), "created")
        self.assertEqual(self.hive.creates, 2)

    def test_a_failed_push_leaves_members_unsynced_for_the_retry(self):
        self._add(1)
        self.hive.create_alert = lambda content: (_ for _ in ()).throw(RuntimeError("403"))
        with self.assertRaises(RuntimeError):
            self._sync()
        self.assertFalse(any("thehive" in m.synced for m in self.campaign.members.all()))


    def test_alert_attachments_are_previews_while_files_stay_observables(self):
        case = self._add(1, atts=[Attachment("notice.pdf", b"%PDF-1")])
        self._sync()
        alert_id = self.campaign.refresh_from_db() or self.campaign.external_refs["thehive"]
        self.assertEqual(sorted(self.hive.attachments[alert_id]), [f"mail-preview-case-{case.id}.png"])
        files = sorted(o["name"] for o in self.hive.observables[alert_id] if o["dataType"] == "file")
        self.assertEqual(files, [f"mail-source-case-{case.id}.eml", "notice.pdf"])
        second = self._add(2)
        self.assertEqual(self._sync(), "updated")
        self.assertEqual(len(self.hive.attachments[alert_id]), 2)
        self.assertIn(f"mail-preview-case-{second.id}.png", self.hive.attachments[alert_id])

    def test_hash_observables_name_their_file_and_old_ones_get_the_tags(self):
        self._add(1, atts=[Attachment("notice.pdf", b"%PDF-1")])
        self._sync()
        alert_id = self.campaign.refresh_from_db() or self.campaign.external_refs["thehive"]
        sha = hashlib.sha256(b"%PDF-1").hexdigest()
        digest = next(o for o in self.hive.observables[alert_id] if o["dataType"] == "hash")
        self.assertEqual((digest["data"], "filename:notice.pdf" in digest["tags"]), (sha, True))
        digest["tags"] = []                       # an alert created before the tags existed
        self._add(2)
        self._sync()
        self.assertIn("filename:notice.pdf", digest["tags"])
        self.assertIn("attachment", digest["tags"])

    def test_attachment_failures_are_logged_but_do_not_fail_the_sync(self):
        self._add(1, atts=[Attachment("notice.pdf", b"%PDF-1")])
        self.hive.add_attachments = lambda aid, parts: (0, 0, ["notice.pdf: 403 license"])
        with self.assertLogs("tasp.cron.update_ongoing_case_jobs", "WARNING") as logs:
            self.assertEqual(self._sync(), "created")
        self.assertTrue(any("notice.pdf: 403 license" in line for line in logs.output))
        self.assertTrue(all("thehive" in m.synced for m in self.campaign.members.all()))


class OutageSyncTest(TestCase):
    def test_an_unavailable_store_creates_no_alert_and_marks_nothing_synced(self):
        class Down(FakeObjectStore):
            def list_buckets(self):
                raise StoreError("unavailable", "connection refused")

        hive, campaign = FakeHive(), Campaign.objects.create(title="Verify payroll")
        _member(campaign, 1)
        cache.clear()
        with self.assertRaises(StoreError):
            sync_campaign(campaign, hive, store=Down(), ui_base="https://sus.example")
        self.assertEqual(hive.creates, 0)
        self.assertFalse(any("thehive" in m.synced for m in campaign.members.all()))
        self.assertNotIn("thehive", Campaign.objects.get(pk=campaign.pk).external_refs)
