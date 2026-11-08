"""Plan F, Task 9 (Rulings F12, F13): promotion conditions, promote, rollback, extend, reviews."""
import threading
from datetime import timedelta
from unittest import mock, skipIf

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from ai_model import promotion, registry, serversync
from ai_model.models import (ModelEvent, ModelVersion, RetrainJob, ShadowCampaignEffect, ShadowResult,
                             ShadowReview)
from ai_model.promotion import PromotionRefused
from ai_model.registry import RegistryError
from ai_model.serversync import ReloadRefused
from ai_model.tests.test_registry import cand
from case_handler.models import Campaign, CampaignMember, Case

S = ModelVersion.Status
SYNC = "ai_model.promotion.serversync.sync"


def make_case():
    user, _ = get_user_model().objects.get_or_create(username="rep", defaults={"email": "r@e.c"})
    return Case.objects.create(reporter=user, description="t")


def result(version, case=None, origin="live", flip="none", would_be="Safe"):
    return ShadowResult.objects.create(
        case=case or make_case(), version=version, origin=origin, result="SAFE", score=1,
        confidence=90, flip=flip, would_be_result=would_be)


def effect(version, case=None, kind="none", days_ago=0, base=None):
    row = ShadowCampaignEffect.objects.create(case=case or make_case(), version=version, effect=kind)
    at = (base or timezone.now()) - timedelta(days=days_ago)
    ShadowCampaignEffect.objects.filter(pk=row.pk).update(created_at=at)
    return row


class PromotionBase(TestCase):
    """v0 active, v1 the shadow for 8 days, 2 live results (the minimum is patched to 2),
    a passing recheck from yesterday: every condition holds."""

    def setUp(self):
        patcher = mock.patch.object(promotion, "SHADOW_MIN_RESULTS", 2)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.admin = get_user_model().objects.create(username="admin")
        self.v0 = registry.ensure_version_zero()
        with self.captureOnCommitCallbacks(execute=False):
            self.v1 = registry.set_shadow(cand("v1", manifest={"eligible": True},
                                               campaign_profile=self.v0.campaign_profile))
        self.age(8)
        self.recheck(days_ago=1)
        result(self.v1)
        result(self.v1)

    def age(self, days):
        ModelVersion.objects.filter(pk=self.v1.pk).update(shadow_since=timezone.now() - timedelta(days=days))
        self.v1.refresh_from_db()

    def recheck(self, passed=True, days_ago=1, **extra):
        finished = (timezone.now() - timedelta(days=days_ago)).isoformat()
        value = {"job_id": "r1", "passed": passed, "finished_at": finished, **extra}
        ModelVersion.objects.filter(pk=self.v1.pk).update(recheck=value)
        self.v1.refresh_from_db()

    def unmet(self):
        self.v1.refresh_from_db()
        return promotion.can_promote(self.v1)


class ConditionsTest(PromotionBase):
    def test_all_conditions_hold(self):
        self.assertEqual(self.unmet(), [])

    def test_not_shadow(self):
        registry.discard(self.v1)
        self.assertEqual(self.unmet(), ["not_shadow"])

    def test_too_young_and_extend_raises_the_minimum(self):
        self.age(6)
        self.assertEqual(self.unmet(), ["too_young", "recheck_stale"])
        self.age(8)
        promotion.extend(self.v1, 10, self.admin, "more data")
        self.assertIn("too_young", self.unmet())
        self.assertEqual(self.v1.shadow_min_days, 10)
        self.assertEqual(self.v1.events.last().action, "extend")

    def test_extend_never_lowers(self):
        with self.assertRaises(RegistryError):
            promotion.extend(self.v1, 5, self.admin, "")
        self.v1.refresh_from_db()
        self.assertEqual(self.v1.shadow_min_days, 7)

    def test_only_live_results_count(self):
        ShadowResult.objects.filter(version=self.v1).first().delete()
        result(self.v1, origin="seed")
        self.assertEqual(self.unmet(), ["too_few_results"])

    def test_live_results_without_a_would_be_verdict_do_not_count(self):
        ShadowResult.objects.filter(version=self.v1).update(would_be_result="")
        result(self.v1, would_be="Dangerous")
        self.assertEqual(self.unmet(), ["too_few_results"])

    def test_only_critical_flips_need_a_review(self):
        result(self.v1, flip="changed")
        result(self.v1, flip="critical", would_be="")  # no would-be: not a flip
        result(self.v1, origin="seed", flip="critical")
        self.assertEqual(self.unmet(), [])
        flip = result(self.v1, flip="critical", would_be="Dangerous")
        self.assertEqual(self.unmet(), ["unreviewed_flips"])
        promotion.review(self.v1, "flip", flip.case_id, self.admin, "checked")
        self.assertEqual(self.unmet(), [])

    def test_candidate_only_and_active_only_need_a_review(self):
        effect(self.v1, kind="would_join")
        self.assertEqual(self.unmet(), ["unreviewed_campaigns"])
        joined = make_case()
        CampaignMember.objects.create(campaign=Campaign.objects.create(), case=joined)
        effect(self.v1, case=joined, kind="would_create")  # in a live campaign too: no delta
        in_live = make_case()
        CampaignMember.objects.create(campaign=Campaign.objects.create(), case=in_live)
        effect(self.v1, case=in_live, kind="no_check")
        delta = promotion.alert_delta(self.v1)
        self.assertEqual(delta["active_only"], [in_live.pk])
        self.assertEqual(len(delta["candidate_only"]), 1)
        promotion.review(self.v1, "campaign", delta["candidate_only"][0], self.admin, "")
        self.assertEqual(self.unmet(), ["unreviewed_campaigns"])
        promotion.review(self.v1, "campaign", in_live.pk, self.admin, "")
        self.assertEqual(self.unmet(), [])

    def test_a_snapshot_gives_the_same_codes(self):
        flips = [result(self.v1, flip="critical", would_be="Dangerous") for _ in range(2)]
        effect(self.v1, kind="would_join")
        for state in ("unreviewed", "partly reviewed"):
            snap = promotion.snapshot(self.v1)
            codes = promotion.can_promote(self.v1)
            self.assertEqual(codes, promotion.can_promote(self.v1, snap))
            self.assertEqual(set(codes), {"unreviewed_flips", "unreviewed_campaigns"}, state)
            self.assertEqual(promotion.latest_reviews(self.v1), promotion.latest_reviews(self.v1, snap))
            promotion.review(self.v1, "flip", flips[0].case_id, self.admin, "one")
            promotion.review(self.v1, "campaign", promotion.alert_delta(self.v1)["candidate_only"][0], self.admin, "c")
            if state == "unreviewed":
                flips = flips[1:]  # the second pass: one flip left unreviewed, the campaign reviewed
                effect(self.v1, kind="would_join")  # and a new unreviewed campaign
        self.v1.refresh_from_db()
        self.assertEqual(promotion.can_promote(self.v1), promotion.can_promote(self.v1, promotion.snapshot(self.v1)))

    def test_recheck_missing_failed_stale(self):
        ModelVersion.objects.filter(pk=self.v1.pk).update(recheck={})
        self.assertEqual(self.unmet(), ["recheck_missing"])
        self.recheck(passed=False)
        self.assertEqual(self.unmet(), ["recheck_failed"])
        self.recheck(days_ago=8)  # more than 7 days ago, and before the minimum was met
        self.assertEqual(self.unmet(), ["recheck_stale"])
        self.age(30)
        self.recheck(days_ago=14)  # after the minimum, but too old
        self.assertEqual(self.unmet(), ["recheck_stale"])
        self.recheck(days_ago=2)
        self.assertEqual(self.unmet(), [])

    def test_a_naive_or_unparsable_recheck_time_is_missing(self):
        naive = (timezone.now() - timedelta(days=1)).replace(tzinfo=None).isoformat()
        ModelVersion.objects.filter(pk=self.v1.pk).update(
            recheck={"job_id": "r", "passed": True, "finished_at": naive})
        self.assertEqual(self.unmet(), ["recheck_missing"])
        ModelVersion.objects.filter(pk=self.v1.pk).update(
            recheck={"job_id": "r", "passed": True, "finished_at": "yesterday"})
        self.assertEqual(self.unmet(), ["recheck_missing"])

    def test_recheck_before_the_minimum_was_met_does_not_count(self):
        self.age(10)
        promotion.extend(self.v1, 9, self.admin, "")
        self.recheck(days_ago=1.5)  # finished at 8.5 days, before the 9 day minimum
        self.assertEqual(self.unmet(), ["recheck_stale"])
        self.recheck(days_ago=0.5)
        self.assertEqual(self.unmet(), [])

    def test_a_different_profile_needs_15_days_of_dry_run(self):
        ModelVersion.objects.filter(pk=self.v1.pk).update(
            campaign_profile=dict(self.v0.campaign_profile, distance_threshold=0.99))
        self.assertEqual(self.unmet(), ["profile_window"])
        base = timezone.now()
        effect(self.v1, days_ago=0, base=base)
        effect(self.v1, days_ago=14.99, base=base)  # 15 calendar dates, under 15 days
        self.assertEqual(self.unmet(), ["profile_window"])
        effect(self.v1, days_ago=15, base=base)
        self.assertEqual(self.unmet(), [])

    def test_job_running(self):
        RetrainJob.objects.create(job_id="j", target_version="v9", state="running", running_slot=1,
                                  prefix="p", trigger="manual")
        self.assertEqual(self.unmet(), ["job_running"])


class DefaultsTest(TestCase):
    def test_constants(self):
        self.assertEqual((promotion.SHADOW_MIN_RESULTS, promotion.DEFAULT_MIN_DAYS, promotion.WINDOW_DAYS,
                          promotion.RECHECK_MAX_AGE_DAYS), (500, 7, 15, 7))


class ReviewTest(PromotionBase):
    def test_a_review_writes_its_model_event(self):
        flip = result(self.v1, flip="critical", would_be="Dangerous")
        promotion.review(self.v1, "flip", flip.case_id, self.admin, "checked")
        self.assertEqual(list(self.v1.events.filter(action="review").values_list("user", "note")),
                         [(self.admin.pk, f"flip {flip.case_id}")])

    def test_review_is_append_only_and_refuses_a_missing_item(self):
        flip = result(self.v1, flip="critical", would_be="Dangerous")
        first = promotion.review(self.v1, "flip", flip.case_id, self.admin, "one")
        second = promotion.review(self.v1, "flip", flip.case_id, self.admin, "two")
        self.assertEqual(ShadowReview.objects.count(), 2)
        self.assertEqual(promotion.latest_reviews(self.v1)[("flip", flip.case_id)].pk, second.pk)
        first.note = "edited"
        with self.assertRaises(ValueError):
            first.save()
        with self.assertRaises(ValueError):
            first.delete()
        with self.assertRaises(RegistryError):
            promotion.review(self.v1, "flip", make_case().pk, self.admin, "")
        with self.assertRaises(RegistryError):
            promotion.review(self.v1, "campaign", flip.case_id, self.admin, "")
        with self.assertRaises(RegistryError):
            promotion.review(self.v1, "other", flip.case_id, self.admin, "")
        self.assertEqual(ShadowReview.objects.count(), 2)

    def test_a_review_of_a_version_that_is_not_the_shadow_is_refused(self):
        flip = result(self.v1, flip="critical", would_be="Dangerous")
        registry.discard(self.v1)
        with self.assertRaises(RegistryError):
            promotion.review(self.v1, "flip", flip.case_id, self.admin, "")
        self.assertFalse(ShadowReview.objects.exists())

    def test_a_review_of_an_item_that_went_away_does_not_count(self):
        flip = result(self.v1, flip="critical", would_be="Dangerous")
        promotion.review(self.v1, "flip", flip.case_id, self.admin, "")
        ShadowResult.objects.filter(pk=flip.pk).update(flip="changed")
        self.assertEqual(self.unmet(), [])
        self.assertEqual(ShadowReview.objects.count(), 1)


class ActionsTest(PromotionBase):
    def actions(self, v):
        return list(v.events.order_by("pk").values_list("action", flat=True))

    def test_promote_refused_changes_nothing(self):
        self.age(2)
        events = ModelEvent.objects.count()
        with mock.patch(SYNC) as sync, self.assertRaises(PromotionRefused) as ctx:
            promotion.promote(self.v1, self.admin, "go")
        self.assertEqual(ctx.exception.codes, ["too_young", "recheck_stale"])
        sync.assert_not_called()
        self.v1.refresh_from_db()
        self.assertEqual(self.v1.status, S.SHADOW)
        self.assertEqual(ModelEvent.objects.count(), events)

    def test_promote_during_a_running_job_is_refused(self):
        RetrainJob.objects.create(job_id="j", target_version="v9", state="running", running_slot=1,
                                  prefix="p", trigger="manual")
        with mock.patch(SYNC), self.assertRaises(PromotionRefused) as ctx:
            promotion.promote(self.v1, self.admin, "go")
        self.assertEqual(ctx.exception.codes, ["job_running"])

    def test_promote(self):
        with mock.patch(SYNC, return_value=True) as sync:
            promotion.promote(self.v1, self.admin, "go")
        sync.assert_called_once_with()
        self.v1.refresh_from_db()
        self.v0.refresh_from_db()
        self.assertEqual((self.v1.status, self.v1.active_slot, self.v1.shadow_slot), (S.ACTIVE, 1, None))
        self.assertEqual(self.v0.status, S.PREVIOUS)
        ev = self.v1.events.get(action="promote")
        self.assertEqual((ev.user, ev.note), (self.admin, "go"))
        self.assertEqual(ShadowResult.objects.filter(version=self.v1).count(), 2)

    def test_promote_then_sync_refused_reverts(self):
        old_prev = cand("v-old")
        registry.set_active(old_prev)
        registry.set_active(self.v0)  # v0 active, v-old previous, v1 shadow
        with mock.patch(SYNC, side_effect=ReloadRefused("no")), self.assertRaises(ReloadRefused):
            promotion.promote(self.v1, self.admin, "go")
        for v in (self.v1, self.v0, old_prev):
            v.refresh_from_db()
        self.assertEqual((self.v1.status, self.v1.shadow_slot, self.v1.active_slot), (S.SHADOW, 1, None))
        self.assertEqual((self.v0.status, self.v0.active_slot), (S.ACTIVE, 1))
        self.assertEqual(old_prev.status, S.PREVIOUS)
        acts = self.actions(self.v1)
        self.assertLess(acts.index("promote"), acts.index("promote_reverted"))

    def test_promote_revert_when_a_new_shadow_appeared_keeps_going_and_reraises(self):
        v2 = cand("v2", manifest={"eligible": True})

        def refuse():
            with self.captureOnCommitCallbacks(execute=False):
                registry.set_shadow(v2)
            raise ReloadRefused("no")

        with mock.patch(SYNC, side_effect=refuse), self.assertRaises(ReloadRefused):
            promotion.promote(self.v1, self.admin, "go")
        for v in (self.v1, self.v0, v2):
            v.refresh_from_db()
        self.assertEqual((self.v1.status, self.v1.shadow_slot, self.v1.active_slot), (S.CANDIDATE, None, None))
        self.assertEqual((self.v0.status, v2.status), (S.ACTIVE, S.SHADOW))
        self.assertIn("promote_reverted", self.actions(self.v1))
        self.assertIn("promote_reverted", self.actions(self.v0))

    def test_promote_revert_does_nothing_if_a_row_moved(self):
        def refuse():
            registry.set_active(self.v0)  # v0 active again, v1 previous
            raise ReloadRefused("no")

        with self.assertLogs("ai_model.registry", "WARNING") as logs, mock.patch(SYNC, side_effect=refuse), \
                self.assertRaises(ReloadRefused):
            promotion.promote(self.v1, self.admin, "go")
        self.assertIn("moved meanwhile", logs.output[0])
        self.v1.refresh_from_db()
        self.assertEqual(self.v1.status, S.PREVIOUS)
        self.assertFalse(ModelEvent.objects.filter(action="promote_reverted").exists())

    def test_a_failing_revert_never_masks_the_refusal(self):
        with mock.patch(SYNC, side_effect=ReloadRefused("no")), \
                mock.patch("ai_model.registry.revert_promote", side_effect=RegistryError("x")), \
                self.assertRaises(ReloadRefused):
            promotion.promote(self.v1, self.admin, "go")
        with mock.patch(SYNC, side_effect=ReloadRefused("no")), \
                mock.patch("ai_model.registry.revert_rollback", side_effect=RegistryError("x")), \
                self.assertRaises(ReloadRefused):
            promotion.rollback(self.admin, "")

    def test_promote_then_transient_sync_failure_keeps_the_new_active(self):
        with mock.patch(SYNC, return_value=False):
            promotion.promote(self.v1, self.admin, "go")
        self.v1.refresh_from_db()
        self.assertEqual(self.v1.status, S.ACTIVE)
        self.assertNotIn("promote_reverted", self.actions(self.v1))

    def test_second_promote_is_refused(self):
        with mock.patch(SYNC, return_value=True):
            promotion.promote(self.v1, self.admin, "go")
            with self.assertRaises(PromotionRefused) as ctx:
                promotion.promote(self.v1, self.admin, "again")
        self.assertIn("not_shadow", ctx.exception.codes)
        self.assertEqual(ModelVersion.objects.filter(status=S.ACTIVE).count(), 1)

    def test_promote_locks_the_rows(self):
        real = ModelVersion.objects.select_for_update
        with mock.patch.object(ModelVersion.objects, "select_for_update", side_effect=real) as sfu, \
                mock.patch(SYNC, return_value=True):
            promotion.promote(self.v1, self.admin, "go")
        self.assertTrue(sfu.called)

    def test_rollback(self):
        with mock.patch(SYNC, return_value=True):
            promotion.promote(self.v1, self.admin, "go")
        with mock.patch(SYNC, return_value=True) as sync:
            promotion.rollback(self.admin, "bad")
        sync.assert_called_once_with()
        self.v0.refresh_from_db()
        self.v1.refresh_from_db()
        self.assertEqual((self.v0.status, self.v1.status), (S.ACTIVE, S.PREVIOUS))
        ev = self.v0.events.get(action="rollback")
        self.assertEqual((ev.user, ev.note), (self.admin, "bad"))

    def test_rollback_refused_by_the_server_reverts(self):
        with mock.patch(SYNC, return_value=True):
            promotion.promote(self.v1, self.admin, "go")
        with mock.patch(SYNC, side_effect=ReloadRefused("no")), self.assertRaises(ReloadRefused):
            promotion.rollback(self.admin, "bad")
        self.v0.refresh_from_db()
        self.v1.refresh_from_db()
        self.assertEqual((self.v0.status, self.v1.status), (S.PREVIOUS, S.ACTIVE))
        self.assertIn("rollback_reverted", self.actions(self.v1))

    def test_rollback_needs_a_previous(self):
        with mock.patch(SYNC) as sync, self.assertRaises(PromotionRefused) as ctx:
            promotion.rollback(self.admin, "")
        self.assertEqual(ctx.exception.codes, ["no_previous"])
        sync.assert_not_called()

    def test_rollback_never_activates_a_previous_that_was_discarded(self):
        with mock.patch(SYNC, return_value=True):
            promotion.promote(self.v1, self.admin, "go")
        registry.discard(self.v0)  # what a concurrent promote does to the old previous
        with mock.patch(SYNC) as sync, self.assertRaises(PromotionRefused) as ctx:
            promotion.rollback(self.admin, "")
        self.assertEqual(ctx.exception.codes, ["no_previous"])
        sync.assert_not_called()
        self.v0.refresh_from_db()
        self.v1.refresh_from_db()
        self.assertEqual((self.v0.status, self.v1.status), (S.DISCARDED, S.ACTIVE))

    def test_rollback_picks_its_target_under_the_lock(self):
        with mock.patch(SYNC, return_value=True):
            promotion.promote(self.v1, self.admin, "go")
        real = ModelVersion.objects.select_for_update
        with mock.patch.object(ModelVersion.objects, "select_for_update", side_effect=real) as sfu, \
                mock.patch.object(ModelVersion.objects, "filter", side_effect=AssertionError("unlocked")), \
                mock.patch(SYNC, return_value=True):
            promotion.rollback(self.admin, "")
        self.assertGreaterEqual(sfu.call_count, 2)  # the target pick, then set_active

    def test_discard_keeps_results_for_audit(self):
        registry.discard(self.v1)
        self.v1.refresh_from_db()
        self.assertEqual((self.v1.status, self.v1.shadow_slot), (S.DISCARDED, None))
        self.assertEqual(ShadowResult.objects.filter(version=self.v1).count(), 2)


class ShadowSyncTest(TestCase):
    """start_shadow and discard push the new state to the server after commit (Ruling F2)."""

    def setUp(self):
        self.admin = get_user_model().objects.create(username="admin")
        registry.ensure_version_zero()
        self.v1 = cand("v1", manifest={"eligible": True})

    def start(self, **sync):
        with mock.patch(SYNC, **sync) as call, self.captureOnCommitCallbacks(execute=True), \
                mock.patch("ai_model.registry._queue_seeding"):
            try:
                return promotion.start_shadow(self.v1, self.admin, "go")
            finally:
                self.calls = call.call_args_list

    def test_start_shadow_syncs_and_requires_the_shadow_to_load(self):
        self.start(return_value=True)
        self.assertEqual([c.kwargs for c in self.calls], [{"shadow_must_load": True}])
        self.v1.refresh_from_db()
        self.assertEqual(self.v1.status, S.SHADOW)

    def test_start_shadow_transient_failure_keeps_the_shadow(self):
        self.start(return_value=False)
        self.v1.refresh_from_db()
        self.assertEqual(self.v1.status, S.SHADOW)

    def test_start_shadow_refused_goes_back_to_candidate(self):
        for exc in (serversync.ShadowRefused("x"), ReloadRefused("x")):
            with self.assertRaises(ReloadRefused):
                self.start(side_effect=exc)
            self.v1.refresh_from_db()
            self.assertEqual((self.v1.status, self.v1.shadow_slot, self.v1.shadow_since),
                             (S.CANDIDATE, None, None))
            ev = self.v1.events.order_by("pk").last()
            self.assertEqual((ev.action, ev.user), ("shadow_refused", self.admin))
        # back to candidate, so it can be started again
        self.start(return_value=True)
        self.v1.refresh_from_db()
        self.assertEqual(self.v1.status, S.SHADOW)

    def test_discard_syncs_best_effort(self):
        with self.captureOnCommitCallbacks(execute=False):
            registry.set_shadow(self.v1)
        for i, kw in enumerate(({"return_value": False}, {"side_effect": ReloadRefused("x")})):
            v = cand(f"d{i}")
            with mock.patch(SYNC, **kw) as sync, self.assertLogs("ai_model.promotion", "WARNING"):
                promotion.discard(v, self.admin, "bye")
            sync.assert_called_once_with()
            v.refresh_from_db()
            self.assertEqual(v.status, S.DISCARDED)
        with mock.patch(SYNC, return_value=True) as sync:
            promotion.discard(self.v1, self.admin, "bye")
        sync.assert_called_once_with()
        self.v1.refresh_from_db()
        self.assertEqual((self.v1.status, self.v1.shadow_slot), (S.DISCARDED, None))
        self.assertEqual(self.v1.events.last().user, self.admin)


@skipIf(connection.vendor == "sqlite", "needs row locks and real connections (MariaDB)")
class ConcurrentPromoteTest(TransactionTestCase):
    def test_two_threads_one_success_one_refusal(self):
        v0 = registry.ensure_version_zero()
        v1 = cand("v1", manifest={"eligible": True}, campaign_profile=v0.campaign_profile)
        with mock.patch("ai_model.registry._queue_seeding"):
            registry.set_shadow(v1)
        # the recheck must have finished after the minimum period was met (day 7), so day 8 minus 12 h
        finished = (timezone.now() - timedelta(hours=12)).isoformat()
        ModelVersion.objects.filter(pk=v1.pk).update(
            shadow_since=timezone.now() - timedelta(days=8),
            recheck={"job_id": "r", "passed": True, "finished_at": finished})
        result(v1)
        results = []

        def run():
            try:
                promotion.promote(ModelVersion.objects.get(pk=v1.pk), None, "go")
                results.append("ok")
            except Exception as exc:  # record every type
                results.append(type(exc).__name__)
            finally:
                connection.close()

        with mock.patch.object(promotion, "SHADOW_MIN_RESULTS", 1), mock.patch(SYNC, return_value=True):
            self.assertEqual(promotion.can_promote(ModelVersion.objects.get(pk=v1.pk)), [])
            threads = [threading.Thread(target=run) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertEqual(sorted(results), ["PromotionRefused", "ok"])
        self.assertEqual(ModelVersion.objects.filter(status=S.ACTIVE).count(), 1)
        self.assertEqual(ModelEvent.objects.filter(action="promote").count(), 1)
