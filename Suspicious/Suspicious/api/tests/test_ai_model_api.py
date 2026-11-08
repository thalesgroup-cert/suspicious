"""Plan F, Task 10: /api/ai-model/ shadow, promotion and review endpoints."""
from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from rest_framework.test import APITestCase

from ai_model.models import ModelVersion, RetrainJob, ShadowCampaignEffect, ShadowResult, ShadowReview
from ai_model.registry import set_shadow
from ai_model.retrain import RetrainRefused
from ai_model.serversync import ReloadRefused
from ai_model.tests.test_registry import cand
from ai_model.tests.test_retrain import RetrainBase
from case_handler.models import Case

U = get_user_model()
S = ModelVersion.Status
BASE = "/api/ai-model/"
SYNC = "ai_model.promotion.serversync.sync"


def user(name, *groups):
    u = U.objects.create_user(username=name, password="x", email=f"{name}@e.c")
    for g in groups:
        u.groups.add(Group.objects.get_or_create(name=g)[0])
    return u


class AiModelApiTest(APITestCase):
    def setUp(self):
        self.admin = user("adm", "Admin")
        self.ciso = user("ciso", "CISO")
        self.cert = user("cert", "CERT")
        self.client.force_authenticate(self.admin)
        self.reporter = user("rep")

    def case(self):
        return Case.objects.create(reporter=self.reporter, description="MAILTEXT-SECRET")

    def shadow(self, vid="v2"):
        v = cand(vid, manifest={"eligible": True})
        with mock.patch("ai_model.registry._queue_seeding"):
            set_shadow(v, self.admin)
        v.refresh_from_db()
        return v

    def flip(self, v, kind="critical"):
        return ShadowResult.objects.create(
            case=self.case(), version=v, origin="live", result="SAFE", score=1, confidence=90,
            live_result="Dangerous", would_be_result="Safe", flip=kind)

    def events(self, v):
        return list(v.events.values_list("action", flat=True))

    # permissions
    def test_reads_admin_and_ciso_only(self):
        for path in ("status/", "versions/", "shadow/", "reviews/"):
            for u, code in ((self.admin, 200), (self.ciso, 200), (self.cert, 403), (self.reporter, 403)):
                self.client.force_authenticate(u)
                self.assertEqual(self.client.get(BASE + path).status_code, code, (path, u))
            self.client.force_authenticate(None)
            self.assertEqual(self.client.get(BASE + path).status_code, 401)

    def test_writes_admin_only(self):
        for path in ("shadow/start/", "promote/", "rollback/", "discard/", "extend/", "reviews/", "recheck/"):
            for u in (self.ciso, self.cert, self.reporter):
                self.client.force_authenticate(u)
                self.assertEqual(self.client.post(BASE + path, {}, format="json").status_code, 403, path)
            self.client.force_authenticate(None)
            self.assertEqual(self.client.post(BASE + path, {}, format="json").status_code, 401)

    def test_superuser_without_the_admin_group_is_refused(self):
        root = U.objects.create_superuser(username="root", password="x", email="r@e.c")  # F14: group Admin only
        self.client.force_authenticate(root)
        self.assertEqual(self.client.get(BASE + "status/").status_code, 403)
        self.assertEqual(self.client.post(BASE + "promote/", {}, format="json").status_code, 403)

    # reads
    def test_versions_counters_purity_warnings_and_no_secrets(self):
        v = cand("v1", manifest={"eligible": True, "url": "https://presigned/x"})
        v.bundle_prefix = "ai-models/secret-key/"
        v.save()
        body = self.client.get(BASE + "versions/").json()
        self.assertEqual(body["count"], 1)
        row = body["results"][0]
        self.assertEqual(row["version_id"], "v1")
        for key in ("status", "purity", "age_warning", "stats"):
            self.assertIn(key, row)
        text = str(body)
        self.assertNotIn("secret-key", text)
        self.assertNotIn("presigned", text)

    def test_versions_paginated_and_bounded(self):
        for i in range(5):
            cand(f"v{i}")
        body = self.client.get(BASE + "versions/?limit=2").json()
        self.assertEqual((len(body["results"]), body["count"]), (2, 5))
        self.assertLessEqual(len(self.client.get(BASE + "versions/?limit=100000").json()["results"]), 100)

    def test_status(self):
        v = self.shadow()
        body = self.client.get(BASE + "status/").json()
        self.assertEqual(body["shadow"]["version_id"], v.version_id)
        self.assertIsNone(body["active"])
        self.assertIn("job_running", body)

    def test_status_extension(self):
        from connectors.delivery import get_state
        st = get_state("ai_model")
        st.last_health_ok, st.last_health_detail, st.last_health_at = False, "down", timezone.now()
        st.save()
        v = self.shadow()
        v.manifest = {"eligible": True, "url": "https://presigned.example/x"}
        v.bundle_prefix = "ai-models/secret-prefix/"
        v.save()
        cand("c1")
        cand("c2")
        ModelVersion.objects.filter(version_id="c2").update(status=S.DISCARDED)
        for i in range(7):
            RetrainJob.objects.create(job_id=f"j{i}", target_version="t", state="failed", prefix="p/",
                                      trigger="manual", error="E" * 200,
                                      started_at=timezone.now() - timedelta(hours=10 - i))
        cfg = {"retrain_enabled": True, "retrain_interval_days": 10}
        with mock.patch("ai_model.schedule.config", return_value=cfg), \
                mock.patch("ai_model.ledger.enabled", return_value=True):
            body = self.client.get(BASE + "status/").json()
        self.assertEqual(body["health"]["ok"], False)
        self.assertEqual(body["health"]["detail"], "down")
        self.assertIsNotNone(body["health"]["checked_at"])
        self.assertEqual(body["breaker"], {"state": "unknown", "since": None})
        newest = max(ModelVersion.objects.exclude(status=S.DISCARDED).values_list("created_at", flat=True))
        self.assertEqual(body["schedule"], {
            "enabled": True, "interval_days": 10, "backoff_until": None,
            "next_run": (newest + timedelta(days=10)).isoformat().replace("+00:00", "Z")})
        self.assertEqual(body["counts"], {"candidate": 1, "shadow": 1, "active": 0, "previous": 0,
                                          "discarded": 1, "failed": 0})
        self.assertEqual([j["job_id"] for j in body["jobs"]], ["j6", "j5", "j4", "j3", "j2"])
        self.assertEqual(set(body["jobs"][0]), {"job_id", "state", "trigger", "rows", "excluded_rows",
                                                "started_at", "finished_at", "error"})
        from ai_model.ledger import ledger_summary
        self.assertEqual(body["ledger"], ledger_summary())
        text = str(body)
        for secret in ("http", "secret-prefix", "presigned", "manifest"):
            self.assertNotIn(secret, text)

    def test_job_row_caps_error(self):
        from api.serializers.ai_model import job_row
        self.assertEqual(len(job_row(RetrainJob(job_id="j", error="E" * 300))["error"]), 200)

    def test_candidates(self):
        gate = {"checks": {"calibration_error": {"passed": False, "value": 0.2, "detail": "D" * 400},
                           "high_tier_precision": {"passed": False, "value": 0.5}, "ok": True},
                "candidate": {"auc": 0.9}, "baseline": {"auc": 0.8}, "campaign": {"n": 3},
                "tier_cutoffs": {"high": 0.9}, "secret_key": "LEAK", "url": "http://x/y"}
        manifest = {"eligible": False, "rows": 10, "excluded_rows": 2, "gate": gate,
                    "link": "http://leak", "seed": 7}
        c1 = cand("c1", manifest=manifest)
        c2 = cand("c2", manifest={"eligible": True, "rows": 5, "excluded_rows": 0,
                                  "gate": {"checks": {"n": "see http://leak.example/p"}}})
        sh = self.shadow("sh")
        old = cand("old", manifest={})
        ModelVersion.objects.filter(pk=old.pk).update(status=S.DISCARDED)
        r = self.client.get(BASE + "candidates/")
        self.assertEqual(r.status_code, 200)
        data = r.json()
        ids = [x["version_id"] for x in data["results"]]
        self.assertEqual(set(ids), {"c1", "c2", "sh"})
        self.assertEqual(ids, [v.version_id for v in ModelVersion.objects.filter(
            version_id__in=ids).order_by("-created_at", "-pk")])
        text = r.content.decode()
        for bad in ("LEAK", "secret_key", "bundle_prefix", "http", "seed", c1.bundle_prefix):
            self.assertNotIn(bad, text)
        row = next(x for x in data["results"] if x["version_id"] == "c1")
        self.assertIs(row["eligible"], False)
        self.assertEqual((row["rows"], row["excluded_rows"]), (10, 2))
        self.assertEqual(set(row["gate"]), {"checks", "candidate", "baseline", "campaign", "tier_cutoffs"})
        self.assertEqual(row["gate"]["checks"]["calibration_error"]["value"], 0.2)
        self.assertIn("high_tier_precision", row["gate"]["checks"])
        self.assertEqual(len(row["gate"]["checks"]["calibration_error"]["detail"]), 300)
        self.assertIsNone(next(x for x in data["results"] if x["version_id"] == "sh")["gate"])
        self.assertIs(next(x for x in data["results"] if x["version_id"] == "c2")["eligible"], True)
        for u, code in ((self.ciso, 200), (self.cert, 403), (self.reporter, 403)):
            self.client.force_authenticate(u)
            self.assertEqual(self.client.get(BASE + "candidates/").status_code, code)
        self.client.force_authenticate(None)
        self.assertEqual(self.client.get(BASE + "candidates/").status_code, 401)

    def test_shadow_comparison(self):
        v = self.shadow()
        f = self.flip(v)
        ShadowResult.objects.create(case=self.case(), version=v, origin="live", result="DANGEROUS", score=9,
                                    confidence=90, live_result="Dangerous", would_be_result="Dangerous")
        ShadowResult.objects.create(case=self.case(), version=v, origin="seed", result="SAFE", score=1,
                                    confidence=90)
        from ai_model.models import AiAssessment
        for r in ShadowResult.objects.filter(origin="live"):
            AiAssessment.objects.create(case=r.case, model_version="v1", result="DANGEROUS", score=9, confidence=90)
        c = self.case()
        ShadowCampaignEffect.objects.create(case=c, version=v, effect="would_create")
        body = self.client.get(BASE + "shadow/").json()
        self.assertEqual(body["version_id"], "v2")
        self.assertEqual(body["live_results"], 2)
        self.assertEqual(body["agreement"]["class"], {"agree": 1, "total": 2})
        self.assertEqual(body["agreement"]["verdict"], {"agree": 1, "total": 2})
        [flip] = body["flips"]["results"]
        self.assertEqual((flip["case_id"], flip["flip"], flip["reviewed"]), (f.case_id, "critical", False))
        self.assertEqual(body["campaign_effects"]["count"], 1)
        self.assertEqual(body["alert_delta"]["candidate_only"], {"count": 1, "results": [c.id]})
        self.assertIn("unreviewed_flips", body["conditions"])
        self.assertIn("too_young", body["conditions"])
        self.assertNotIn("MAILTEXT-SECRET", str(body))

    def test_shadow_without_shadow_is_null(self):
        self.assertEqual(self.client.get(BASE + "shadow/").json(), {"shadow": None})

    # writes
    def test_shadow_start_and_errors(self):
        v = cand("v2", manifest={"eligible": True})
        with mock.patch("ai_model.registry._queue_seeding"):
            r = self.client.post(BASE + "shadow/start/", {"version_id": "v2", "note": "go"}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertIn("set_shadow", self.events(v))
        bad = cand("v3", manifest={"eligible": True})
        r = self.client.post(BASE + "shadow/start/", {"version_id": "v3"}, format="json")
        self.assertEqual(r.status_code, 409)
        self.assertNotIn("discard", str(r.json()))  # fixed message, not exception text
        self.assertEqual(self.client.post(BASE + "shadow/start/", {}, format="json").status_code, 400)
        self.assertEqual(self.client.post(BASE + "shadow/start/", {"version_id": "nope"}, format="json").status_code, 404)
        bad.refresh_from_db()
        self.assertEqual(bad.status, S.CANDIDATE)

    def test_promote_unmet_is_409_with_codes(self):
        self.shadow()
        r = self.client.post(BASE + "promote/", {"note": "x"}, format="json")
        self.assertEqual(r.status_code, 409)
        self.assertIn("too_young", r.json()["codes"])

    def test_promote_ok_writes_event(self):
        v = self.shadow()
        with mock.patch(SYNC, return_value=True), mock.patch("ai_model.promotion.can_promote", return_value=[]):
            r = self.client.post(BASE + "promote/", {"note": "ship"}, format="json")
        self.assertEqual(r.status_code, 200)
        v.refresh_from_db()
        self.assertEqual(v.status, S.ACTIVE)
        self.assertIn("promote", self.events(v))

    def test_promote_reload_refused_is_409_fixed_message(self):
        self.shadow()
        with mock.patch("ai_model.promotion.can_promote", return_value=[]), \
                mock.patch(SYNC, side_effect=ReloadRefused("http://presigned/leak")):
            r = self.client.post(BASE + "promote/", {}, format="json")
        self.assertEqual(r.status_code, 409)
        self.assertNotIn("presigned", str(r.json()))

    def test_promote_with_a_cleared_token_is_a_transient_sync_failure(self):
        v = self.shadow()
        with mock.patch("ai_model.promotion.can_promote", return_value=[]), \
                mock.patch("connectors.registry.registry.instantiate") as inst:
            inst.return_value._client.side_effect = ValueError("token not configured")
            r = self.client.post(BASE + "promote/", {}, format="json")
        self.assertEqual(r.status_code, 200)
        v.refresh_from_db()
        self.assertEqual(v.status, S.ACTIVE)

    def test_shadow_start_refused_by_the_server_is_409_and_back_to_candidate(self):
        v = cand("v2", manifest={"eligible": True})
        with mock.patch("ai_model.registry._queue_seeding"), \
                mock.patch(SYNC, side_effect=ReloadRefused("http://presigned/leak")) as sync:
            r = self.client.post(BASE + "shadow/start/", {"version_id": "v2"}, format="json")
        sync.assert_called_once_with(shadow_must_load=True)
        self.assertEqual(r.status_code, 409)
        self.assertNotIn("presigned", str(r.json()))
        v.refresh_from_db()
        self.assertEqual(v.status, S.CANDIDATE)
        self.assertIn("shadow_refused", self.events(v))

    def test_discard_syncs_the_server(self):
        self.shadow()
        with mock.patch(SYNC, return_value=True) as sync:
            r = self.client.post(BASE + "discard/", {"version_id": "v2"}, format="json")
        self.assertEqual(r.status_code, 200)
        sync.assert_called_once_with()

    def test_promote_without_shadow_409(self):
        self.assertEqual(self.client.post(BASE + "promote/", {}, format="json").status_code, 409)

    def test_rollback(self):
        self.assertEqual(self.client.post(BASE + "rollback/", {}, format="json").status_code, 409)
        a = cand("a")
        b = cand("b")
        from ai_model import registry
        registry.set_active(a, self.admin)
        registry.set_active(b, self.admin)
        with mock.patch(SYNC, return_value=True):
            r = self.client.post(BASE + "rollback/", {"note": "bad"}, format="json")
        self.assertEqual(r.status_code, 200)
        a.refresh_from_db()
        self.assertEqual(a.status, S.ACTIVE)
        self.assertIn("rollback", self.events(a) + self.events(b))

    def test_discard(self):
        v = self.shadow()
        r = self.client.post(BASE + "discard/", {"version_id": "v2"}, format="json")
        self.assertEqual(r.status_code, 200)
        self.assertIn("discard", self.events(v))
        self.assertEqual(self.client.post(BASE + "discard/", {"version_id": "v2"}, format="json").status_code, 409)

    def test_extend(self):
        v = self.shadow()
        r = self.client.post(BASE + "extend/", {"days": 14, "note": "more"}, format="json")
        self.assertEqual(r.status_code, 200)
        v.refresh_from_db()
        self.assertEqual(v.shadow_min_days, 14)
        self.assertIn("extend", self.events(v))
        for bad, code in ((14, 409), (3, 409), (400, 400), ("x", 400), (None, 400), (True, 400)):
            self.assertEqual(self.client.post(BASE + "extend/", {"days": bad}, format="json").status_code, code, bad)
        v.refresh_from_db()
        self.assertEqual(v.shadow_min_days, 14)

    def test_reviews(self):
        v = self.shadow()
        f = self.flip(v)
        ok = {"kind": "flip", "case_id": str(f.case_id), "note": "looked"}  # case_id cast to int
        r = self.client.post(BASE + "reviews/", ok, format="json")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(ShadowReview.objects.get().case_id, f.case_id)
        self.assertEqual(list(v.events.filter(action="review").values_list("user__username", "note")),
                         [("adm", f"flip {f.case_id}")])
        listed = self.client.get(BASE + "reviews/").json()
        self.assertEqual(listed["count"], 1)
        self.assertEqual(listed["results"][0]["user"], "adm")
        self.client.force_authenticate(self.ciso)
        self.assertEqual(self.client.get(BASE + "reviews/").status_code, 200)
        self.client.force_authenticate(self.admin)
        for bad in ({**ok, "kind": "x"}, {**ok, "case_id": "abc"}, {**ok, "case_id": True}, {**ok, "case_id": -1},
                    {**ok, "note": ""}, {**ok, "note": "  "}, {**ok, "note": "a" * 2001}, {"kind": "flip"}):
            self.assertEqual(self.client.post(BASE + "reviews/", bad, format="json").status_code, 400, bad)
        r = self.client.post(BASE + "reviews/", {**ok, "case_id": 999999}, format="json")  # no such flip
        self.assertEqual(r.status_code, 409)
        self.assertEqual(ShadowReview.objects.count(), 1)

    def test_recheck_refusal_is_a_fixed_409(self):
        self.shadow()
        with mock.patch("api.views.ai_model.retrain.start_recheck", side_effect=RetrainRefused("http://x/leak")):
            r = self.client.post(BASE + "recheck/", {}, format="json")
        self.assertEqual(r.status_code, 409)
        self.assertNotIn("leak", str(r.json()))

    def test_flips_page_and_review_state(self):
        v = self.shadow()
        crit = [self.flip(v) for _ in range(3)]
        changed = self.flip(v, "changed")
        promotion_review = {"kind": "flip", "case_id": crit[0].case_id, "note": "ok"}
        self.assertEqual(self.client.post(BASE + "reviews/", promotion_review, format="json").status_code, 201)
        body = self.client.get(BASE + "shadow/?flips_limit=2&flips_offset=1").json()["flips"]
        self.assertEqual((body["count"], len(body["results"])), (4, 2))
        rows = {r["case_id"]: r for r in self.client.get(BASE + "shadow/").json()["flips"]["results"]}
        self.assertEqual((rows[crit[0].case_id]["reviewable"], rows[crit[0].case_id]["reviewed"]), (True, True))
        self.assertEqual((rows[crit[1].case_id]["reviewable"], rows[crit[1].case_id]["reviewed"]), (True, False))
        self.assertFalse(rows[changed.case_id]["reviewable"])
        self.assertNotIn("reviewed", rows[changed.case_id])
        r = self.client.post(BASE + "reviews/", {"kind": "flip", "case_id": changed.case_id, "note": "n"},
                             format="json")
        self.assertEqual(r.status_code, 409)

    def test_alert_delta_counts_and_pages(self):
        v = self.shadow()
        ids = sorted(self.case().id for _ in range(3))
        for i in ids:
            ShadowCampaignEffect.objects.create(case_id=i, version=v, effect="would_join")
        d = self.client.get(BASE + "shadow/?candidate_only_limit=2&candidate_only_offset=2").json()["alert_delta"]
        self.assertEqual(d["candidate_only"]["count"], 3)
        self.assertEqual(d["candidate_only"]["results"], ids[2:])
        self.assertEqual(d["active_only"], {"count": 0, "results": []})
        effects = self.client.get(BASE + "shadow/?effects_limit=1&effects_offset=2").json()["campaign_effects"]
        self.assertEqual((effects["count"], len(effects["results"])), (3, 1))
        self.assertTrue(effects["results"][0]["reviewable"])

    def test_bad_paging_params_stay_bounded(self):
        v = self.shadow()
        for _ in range(105):
            self.flip(v)
            ShadowCampaignEffect.objects.create(case=self.case(), version=v, effect="would_join")
        for q in ("flips_limit=-1&flips_offset=abc", "candidate_only_limit=99999", "effects_offset=1000000000",
                  "flips_limit=99999&effects_limit=99999"):
            r = self.client.get(BASE + "shadow/?" + q)
            self.assertEqual(r.status_code, 200, q)
            body = r.json()
            for rows in (body["flips"], body["campaign_effects"], body["alert_delta"]["candidate_only"],
                         body["alert_delta"]["active_only"]):
                self.assertLessEqual(len(rows["results"]), 100, q)
        body = self.client.get(BASE + "shadow/?candidate_only_limit=99999").json()
        self.assertEqual(len(body["alert_delta"]["candidate_only"]["results"]), 100)
        self.assertEqual(body["alert_delta"]["candidate_only"]["count"], 105)


class RecheckApiTest(RetrainBase, APITestCase):
    """The real start_recheck runs; only the inference server and the object store are faked."""

    def setUp(self):
        super().setUp()
        self.admin = user("adm", "Admin")
        self.client.force_authenticate(self.admin)
        v = cand("v1", manifest={"eligible": True, "seed": 7})
        with mock.patch("ai_model.registry._queue_seeding"):
            self.shadow = set_shadow(v, self.admin)

    def test_recheck_starts_a_job_and_writes_its_event(self):
        r = self.client.post(BASE + "recheck/", {"version_id": "v1"}, format="json")
        self.assertEqual(r.status_code, 202)
        job_id = r.json()["job_id"]
        self.assertTrue(RetrainJob.objects.filter(job_id=job_id, state="running").exists())
        self.assertEqual(list(self.shadow.events.filter(action="start_recheck").values_list("user", "note")),
                         [(self.admin.pk, job_id)])
        again = self.client.post(BASE + "recheck/", {}, format="json")  # a job is running
        self.assertEqual(again.status_code, 409)
        self.assertNotIn(job_id, str(again.json()))


class CandidatesEdgeTest(APITestCase):
    def setUp(self):
        self.client.force_authenticate(user("adm2", "Admin"))

    def test_counts_coerced_nan_depth_list_cap_and_paging(self):
        deep = {"a": {"b": {"c": {"d": {"e": 1}}}}}
        gate = {"checks": {"list": list(range(80)), "deep": deep}}
        cand("e1", manifest={"rows": {"x": 1}, "excluded_rows": "7", "gate": gate})
        data = self.client.get(BASE + "candidates/").json()
        row = data["results"][0]
        self.assertIsNone(row["rows"])
        self.assertIsNone(row["excluded_rows"])
        checks = row["gate"]["checks"]
        from api.serializers.ai_model import _plain  # a JSON column cannot store NaN, so call it directly
        self.assertEqual(_plain([float("nan"), float("inf"), 1.5]), [None, None, 1.5])
        self.assertEqual(checks["list"], list(range(50)))
        self.assertEqual(checks["deep"], {"a": {"b": {"c": None}}})

    def test_order_and_paging(self):
        now = timezone.now()
        for i, vid in enumerate(("p1", "p2", "p3")):
            v = cand(vid, manifest={})
            ModelVersion.objects.filter(pk=v.pk).update(created_at=now - timedelta(days=10 - i))
        ids = lambda q: [x["version_id"] for x in self.client.get(BASE + "candidates/" + q).json()["results"]]
        self.assertEqual(ids(""), ["p3", "p2", "p1"])
        self.assertEqual(ids("?limit=1&offset=1"), ["p2"])
        self.assertEqual(self.client.get(BASE + "candidates/?limit=1").json()["count"], 3)
