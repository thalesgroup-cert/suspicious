"""Who added / removed Settings allow/deny list entries (ListChangeLog audit trail)."""
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from rest_framework.test import APIClient

from domain_process.models import Domain
from settings.models import AllowListDomain, ListChangeLog, WatcherLegitDomain

User = get_user_model()


def _admin(name):
    u = User.objects.create_user(name, password="p")
    u.groups.add(Group.objects.get_or_create(name="Admin")[0])
    return u


def _client(user):
    c = APIClient()
    c.force_authenticate(user)
    return c


class ListHistoryTests(TestCase):
    def setUp(self):
        self.alice = _admin("alice")
        self.bob = _admin("bob")
        self.ca = _client(self.alice)
        self.cb = _client(self.bob)

    def _list(self, section="domains_allow"):
        return reverse("settings-list", kwargs={"section": section})

    def _hist(self, section="domains_allow"):
        return reverse("settings-list-history", kwargs={"section": section})

    def _add(self, client, *values, section="domains_allow"):
        r = client.post(self._list(section), {"values": list(values)}, format="json")
        self.assertEqual(r.status_code, 201, r.content)
        return r.json()

    def _delete(self, client, item_id, section="domains_allow"):
        return client.delete(
            reverse("settings-list-delete", kwargs={"section": section, "item_id": item_id})
        )

    def test_added_by_present_after_create_with_two_users(self):
        self._add(self.ca, "a.example")
        self._add(self.cb, "b.example")
        rows = {r["value"]: r for r in self.ca.get(self._list()).json()["results"]}
        self.assertEqual(rows["a.example"]["added_by"], "alice")
        self.assertEqual(rows["b.example"]["added_by"], "bob")

    def test_create_logs_added_row_per_created_value(self):
        self._add(self.ca, "a.example", "b.example")
        logs = ListChangeLog.objects.filter(action="added", section="domains_allow", user=self.alice)
        self.assertEqual(sorted(logs.values_list("value", flat=True)), ["a.example", "b.example"])
        self.assertEqual({entry.username for entry in logs}, {"alice"})

    def test_duplicates_and_watcher_conflicts_write_nothing(self):
        self._add(self.ca, "a.example")
        wd, _ = Domain.objects.get_or_create(value="w.example")
        WatcherLegitDomain.objects.create(domain=wd, watcher_id=1)
        before = ListChangeLog.objects.count()
        res = self._add(self.cb, "a.example", "w.example")
        self.assertEqual(res["created"], [])
        self.assertEqual(ListChangeLog.objects.count(), before)

    def test_delete_logs_removed_with_deleting_user(self):
        self._add(self.ca, "a.example")
        item = AllowListDomain.objects.get(domain__value="a.example")
        r = self._delete(self.cb, item.id)
        self.assertEqual(r.status_code, 200)
        entry = ListChangeLog.objects.get(action="removed")
        self.assertEqual((entry.value, entry.username, entry.user), ("a.example", "bob", self.bob))
        self.assertEqual(entry.section, "domains_allow")

    def test_removed_row_survives_user_deletion(self):
        self._add(self.ca, "a.example")
        item = AllowListDomain.objects.get(domain__value="a.example")
        self._delete(self.cb, item.id)
        self.bob.delete()
        entry = ListChangeLog.objects.get(action="removed")
        self.assertIsNone(entry.user)
        self.assertEqual(entry.username, "bob")

    def test_delete_nonexistent_is_404_and_writes_nothing(self):
        r = self._delete(self.ca, 99999)
        self.assertEqual(r.status_code, 404)
        self.assertEqual(ListChangeLog.objects.count(), 0)

    def test_readding_removed_value_logs_second_added(self):
        self._add(self.ca, "a.example")
        item = AllowListDomain.objects.get(domain__value="a.example")
        self._delete(self.ca, item.id)
        self._add(self.cb, "a.example")
        actions = list(
            ListChangeLog.objects.filter(value="a.example").order_by("id").values_list("action", "username")
        )
        self.assertEqual(actions, [("added", "alice"), ("removed", "alice"), ("added", "bob")])

    def test_history_newest_first_and_section_scoped(self):
        self._add(self.ca, "a.example")
        self._add(self.cb, "z.example", section="domains_deny")
        item = AllowListDomain.objects.get(domain__value="a.example")
        self._delete(self.cb, item.id)
        body = self.ca.get(self._hist()).json()
        self.assertEqual([(e["action"], e["value"], e["username"]) for e in body["results"]],
                         [("removed", "a.example", "bob"), ("added", "a.example", "alice")])
        self.assertEqual(set(body["results"][0]), {"id", "value", "action", "username", "created_at"})

    def test_history_is_paginated(self):
        self._add(self.ca, *[f"d{i}.example" for i in range(5)])
        body = self.ca.get(self._hist(), {"page_size": 2}).json()
        self.assertEqual(body["count"], 5)
        self.assertEqual(len(body["results"]), 2)
        self.assertIsNotNone(body["next"])

    def test_history_requires_admin_or_cert(self):
        plain = User.objects.create_user("plain", password="p")
        self.assertEqual(_client(plain).get(self._hist()).status_code, 403)
        self.assertIn(APIClient().get(self._hist()).status_code, (401, 403))

    def test_history_rejects_unknown_and_read_only_sections(self):
        for section in ("nope", "watcher_legit_domains", "watcher_monitored_domains", "ciso_users"):
            self.assertEqual(self.ca.get(self._hist(section)).status_code, 400, section)

    def test_read_only_lists_have_null_added_by(self):
        wd, _ = Domain.objects.get_or_create(value="w.example")
        WatcherLegitDomain.objects.create(domain=wd, watcher_id=1)
        rows = self.ca.get(self._list("watcher_legit_domains")).json()["results"]
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["added_by"])

    def test_list_query_count_does_not_grow_with_rows(self):
        def count():
            with CaptureQueriesContext(connection) as ctx:
                self.assertEqual(self.ca.get(self._list()).status_code, 200)
            return len(ctx)

        self._add(self.ca, "a.example")
        small = count()
        self._add(self.cb, *[f"d{i}.example" for i in range(20)])
        self.assertEqual(count(), small)


class OtherSectionsHistoryTests(TestCase):
    def setUp(self):
        self.alice = _admin("alice")
        self.c = _client(self.alice)

    def _roundtrip(self, section, posted, shown):
        url = reverse("settings-list", kwargs={"section": section})
        self.assertEqual(self.c.post(url, {"values": [posted]}, format="json").status_code, 201)
        rows = self.c.get(url).json()["results"]
        self.assertEqual([r["value"] for r in rows], [shown])
        self.assertEqual(ListChangeLog.objects.get(section=section, action="added").value, shown)
        self.assertEqual(rows[0]["added_by"], "alice")
        r = self.c.delete(reverse("settings-list-delete", kwargs={"section": section, "item_id": rows[0]["id"]}))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(ListChangeLog.objects.get(section=section, action="removed").value, shown)

    def test_ip_logs_the_normalised_value_the_list_shows(self):
        self._roundtrip("ips_allow", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1")

    def test_hash_section_logs_add_and_remove(self):
        self._roundtrip("emails_files_allow", "a" * 64, "a" * 64)

    def test_filetype_section_logs_add_and_remove(self):
        self._roundtrip("filetypes_allow", "pdf", "pdf")

    def test_history_query_count_constant_for_1_vs_21_events(self):
        url = reverse("settings-list-history", kwargs={"section": "domains_allow"})

        def count():
            with CaptureQueriesContext(connection) as ctx:
                self.assertEqual(self.c.get(url, {"page_size": 100}).status_code, 200)
            return len(ctx)

        ListChangeLog.objects.create(section="domains_allow", value="a", action="added", username="alice")
        small = count()
        ListChangeLog.objects.bulk_create(
            ListChangeLog(section="domains_allow", value=f"v{i}", action="added", username="alice") for i in range(20)
        )
        self.assertEqual(count(), small)
