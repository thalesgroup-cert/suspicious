"""Live regional summary (dashboard/dash_utils/regional.py) and the B1
reporter-count regression."""
from datetime import date, datetime, timezone as dt_tz
from unittest import mock

from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from django.utils import timezone

from api.views.investigations import InvestigationListView
from case_handler.models import (
    Case,
    CaseHasFileOrMail,
    CaseHasNonFileIocs,
    ObservableGroup,
    Status,
)
from dashboard.dash_utils.dashboard import update_monthly_reporter_stats
from dashboard.dash_utils.regional import summarise
from dashboard.models import DashboardSnapshot, Kpi
from dashboard.snapshot import materialise_snapshot
from hash_process.models import Hash
from ip_process.models import IP
from mail_feeder.models import Mail
from url_process.models import URL


def utc(*args):
    return datetime(*args, tzinfo=dt_tz.utc)


def make_user(username, groups, joined=utc(2025, 1, 1)):
    user = User.objects.create_user(username, password="x")
    for name in groups:
        user.groups.add(Group.objects.get_or_create(name=name)[0])
    User.objects.filter(pk=user.pk).update(date_joined=joined)
    return user


def make_case(reporter, when, *, kind="UNKNOWN", status=Status.DONE, results="Inconclusive", category="Uncategorized"):
    case = Case.objects.create(
        description="d", reporter=reporter, status=status, results=results, category_ai=category
    )
    if kind == "MAIL":
        mail = Mail.objects.create(subject="s", reportedBy="r", date=when, to="t", mail_id=f"m{case.pk}")
        case.fileOrMail = CaseHasFileOrMail.objects.create(case=case, mail=mail)
    elif kind == "URL":
        case.nonFileIocs = CaseHasNonFileIocs.objects.create(case=case, url=URL.objects.create(address="http://x.example"))
    elif kind == "IP":
        case.nonFileIocs = CaseHasNonFileIocs.objects.create(case=case, ip=IP.objects.create(address="8.8.8.8"))
    elif kind == "HASH":
        case.nonFileIocs = CaseHasNonFileIocs.objects.create(case=case, hash=Hash.objects.create(value="ab" * 32))
    elif kind == "IOC":
        case.observable_group = ObservableGroup.objects.create()
    case.save()
    # auto_now_add ignores create(); force the date.
    Case.objects.filter(pk=case.pk).update(creation_date=when)
    return case


def seed():
    """AU/NZ/US reporters with cases in September and October 2026."""
    au1 = make_user("au1@meridian.example", ["AU", "APAC", "Off GBU"], joined=utc(2026, 10, 3))
    au2 = make_user("au2@meridian.example", ["AU", "APAC"])
    nz1 = make_user("nz1@meridian.example", ["NZ", "APAC"])
    us1 = make_user("us1@meridian.example", ["US", "NORAM"])
    oct5, oct20 = utc(2026, 10, 5, 10), utc(2026, 10, 20, 10)
    make_case(au1, oct5, kind="URL", results="Dangerous", category="Classic_phishing")
    make_case(au1, oct5, kind="IP", status=Status.CHALLENGED, results="Safe")
    make_case(au1, oct5, kind="HASH", status=Status.TODO)  # running: default Inconclusive
    make_case(au1, oct5, kind="IOC", status=Status.ONGOING)
    make_case(au2, oct5, kind="MAIL", results="Failure")
    make_case(au2, oct20, kind="UNKNOWN", results="Inconclusive")
    make_case(nz1, oct5, kind="URL", results="Suspicious")
    make_case(us1, oct5, kind="IP", results="Safe")
    sep = utc(2026, 9, 10, 10)
    make_case(au1, sep, results="Safe")
    make_case(au1, sep, results="Dangerous")
    make_case(us1, sep, results="Safe")
    return au1, au2, nz1, us1


class SummariseTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        seed()

    def test_country_counts(self):
        s = summarise(10, 2026, ["AU"])
        self.assertEqual(s["reports"], 6)
        self.assertEqual(
            s["outcomes"],
            {"safe": 1, "inconclusive": 1, "suspicious": 0, "dangerous": 1, "failure": 1},
        )
        self.assertEqual(s["in_progress"], 2)
        self.assertEqual(s["reporters"], 2)
        self.assertEqual(s["new_users"], 1)

    def test_running_case_is_not_an_outcome(self):
        # The TODO HASH case carries the default "Inconclusive": only the DONE
        # UNKNOWN case may count as inconclusive.
        s = summarise(10, 2026, ["AU"])
        self.assertEqual(s["outcomes"]["inconclusive"], 1)
        self.assertEqual(sum(s["outcomes"].values()) + s["in_progress"], s["reports"])

    def test_previous_month_block(self):
        s = summarise(10, 2026, ["AU"])
        self.assertEqual(s["previous"]["reports"], 2)
        self.assertEqual(
            s["previous"]["outcomes"],
            {"safe": 1, "inconclusive": 0, "suspicious": 0, "dangerous": 1, "failure": 0},
        )

    def test_previous_month_wraps_year(self):
        make_case(User.objects.get(username="us1@meridian.example"), utc(2026, 12, 15, 10))
        self.assertEqual(summarise(1, 2027, None)["previous"]["reports"], 1)

    def test_snapshot_carries_no_names(self):
        materialise_snapshot(10, 2026)
        payload = DashboardSnapshot.objects.get(month=10, year=2026).payload
        self.assertEqual(payload["reports"], 8)
        self.assertIsNone(payload["top_reporters"])

    def test_by_type_vocabulary(self):
        self.assertEqual(
            summarise(10, 2026, ["AU"])["by_type"],
            {"MAIL": 1, "FILE": 0, "URL": 1, "IP": 1, "HASH": 1, "IOC": 1, "UNKNOWN": 1},
        )

    def test_multi_group_reporter_counted_once(self):
        # au1 is in AU, APAC and Off GBU: one row per case whatever the scope.
        self.assertEqual(summarise(10, 2026, ["AU"])["reports"], 6)
        apac = summarise(10, 2026, ["APAC"])
        self.assertEqual(apac["reports"], 7)
        self.assertEqual(apac["reporters"], 3)
        both = summarise(10, 2026, ["AU", "APAC"])
        self.assertEqual(both["reports"], 6)
        self.assertEqual(both["reporters"], 2)
        # AND semantics: only au1 is in both AU and Off GBU.
        self.assertEqual(summarise(10, 2026, ["AU", "Off GBU"])["reports"], 4)

    def test_overall(self):
        s = summarise(10, 2026, None)
        self.assertEqual(s["reports"], 8)
        self.assertEqual(s["reporters"], 4)
        self.assertEqual(s["new_users"], 1)

    @mock.patch("dashboard.dash_utils.regional.timezone.localdate", return_value=date(2026, 11, 15))
    def test_trend_weekly(self, _today):
        # A past month: every week touching it, zeros included.
        self.assertEqual(
            summarise(10, 2026, ["AU"])["trend"],
            [
                {"week_start": "2026-09-28", "reports": 0},
                {"week_start": "2026-10-05", "reports": 5},
                {"week_start": "2026-10-12", "reports": 0},
                {"week_start": "2026-10-19", "reports": 1},
                {"week_start": "2026-10-26", "reports": 0},
            ],
        )

    @mock.patch("dashboard.dash_utils.regional.timezone.localdate", return_value=date(2026, 10, 14))
    def test_trend_stops_at_the_current_week(self, _today):
        # The current month: weeks that have not started yet are not zeros, they do not exist.
        self.assertEqual(
            summarise(10, 2026, ["AU"])["trend"],
            [
                {"week_start": "2026-09-28", "reports": 0},
                {"week_start": "2026-10-05", "reports": 5},
                {"week_start": "2026-10-12", "reports": 0},
            ],
        )

    def test_zero_report_scope(self):
        s = summarise(10, 2026, ["FR"])
        self.assertEqual(s["reports"], 0)
        self.assertEqual(s["in_progress"], 0)
        self.assertEqual(set(s["outcomes"].values()), {0})
        self.assertEqual(set(s["by_type"].values()), {0})
        self.assertEqual(s["reporters"], 0)
        self.assertEqual(s["trend"], [])
        self.assertEqual(s["previous"]["reports"], 0)

    def test_top_reporters_only_when_asked(self):
        self.assertIsNone(summarise(10, 2026, ["AU"])["top_reporters"])
        self.assertEqual(
            summarise(10, 2026, ["AU"], include_names=True)["top_reporters"],
            [{"label": "au1", "value": 4}, {"label": "au2", "value": 2}],
        )


class MonthBoundaryTests(TestCase):
    """The month bucket must match the Investigation list's date filter."""

    def setUp(self):
        self.user = make_user("edge@meridian.example", ["XX"])
        make_case(self.user, utc(2026, 10, 31, 23, 30))
        make_case(self.user, utc(2026, 11, 1, 0, 30))

    def _list_count(self, first, last):
        qs = InvestigationListView().filter_case_queryset(
            Case.objects.filter(reporter=self.user), {"from_date": first, "to_date": last}
        )
        return qs.count()

    def _assert_matches_list(self):
        october = self._list_count(date(2026, 10, 1), date(2026, 10, 31))
        november = self._list_count(date(2026, 11, 1), date(2026, 11, 30))
        self.assertEqual(summarise(10, 2026, ["XX"])["reports"], october)
        self.assertEqual(summarise(11, 2026, ["XX"])["reports"], november)
        return october, november

    @override_settings(TIME_ZONE="UTC")
    def test_utc(self):
        self.assertEqual(self._assert_matches_list(), (1, 1))

    @override_settings(TIME_ZONE="Australia/Sydney")
    def test_server_timezone(self):
        # Sydney is UTC+11 in November: both cases fall on 1 November.
        self.assertEqual(self._assert_matches_list(), (0, 2))


class MonthlyReporterStatsB1Tests(TestCase):
    def test_total_reporters_refreshed_on_update(self):
        now = timezone.now()
        kpi = Kpi.objects.create(month=str(now.month), year=str(now.year))
        a = make_user("a@meridian.example", [])
        b = make_user("b@meridian.example", [])
        make_case(a, now)
        update_monthly_reporter_stats(kpi, now.month, now.year)
        self.assertEqual(kpi.monthly_reporter_stats.total_reporters, 1)
        make_case(b, now)
        update_monthly_reporter_stats(kpi, now.month, now.year)
        kpi.monthly_reporter_stats.refresh_from_db()
        self.assertEqual(kpi.monthly_reporter_stats.total_reporters, 2)
