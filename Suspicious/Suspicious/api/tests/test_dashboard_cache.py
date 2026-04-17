"""
Unit tests for DashboardSummaryView caching logic.

Patches django.core.cache.cache so no Redis connection is needed.
"""
import sys
import unittest
from unittest.mock import MagicMock, patch, call


# ---------------------------------------------------------------------------
# Stub Django internals so views/dashboard.py can be imported standalone
# ---------------------------------------------------------------------------

def _identity_decorator(*args, **kwargs):
    """Identity decorator: returns the decorated function unchanged."""
    def _wrapper(fn):
        return fn
    # Handle both @extend_schema(...) and @extend_schema usage
    if len(args) == 1 and callable(args[0]) and not kwargs:
        return args[0]
    return _wrapper


def _setup_stubs():
    django_stub        = MagicMock()
    drf_stub           = MagicMock()
    conf_stub          = MagicMock()
    conf_stub.settings = MagicMock()
    conf_stub.settings.SUSPICIOUS_EMAIL = None

    # Use a real base class for APIView so class definitions don't hit metaclass conflicts
    class _FakeAPIView:
        pass

    class _FakeGenerics(MagicMock):
        ListAPIView = _FakeAPIView
        RetrieveAPIView = _FakeAPIView

    drf_views_stub = MagicMock()
    drf_views_stub.APIView = _FakeAPIView

    drf_generics_stub = MagicMock()
    drf_generics_stub.ListAPIView = _FakeAPIView
    drf_generics_stub.RetrieveAPIView = _FakeAPIView

    # MonthYearQueryMixin needs to be a real class too
    class _FakeMonthYearQueryMixin:
        def get_month_year(self):
            return 4, 2026

    mixins_stub = MagicMock()
    mixins_stub.MonthYearQueryMixin = _FakeMonthYearQueryMixin

    # drf_spectacular.utils.extend_schema must be an identity decorator so that
    # the @extend_schema(...) decorator on get() doesn't replace the real method
    drf_spectacular_utils_stub = MagicMock()
    drf_spectacular_utils_stub.extend_schema = _identity_decorator
    drf_spectacular_utils_stub.OpenApiParameter = MagicMock()

    sys.modules.setdefault("django",                                  django_stub)
    sys.modules.setdefault("django.conf",                             conf_stub)
    sys.modules.setdefault("django.core",                             MagicMock())
    sys.modules.setdefault("django.core.cache",                       MagicMock())
    sys.modules.setdefault("django.db",                               MagicMock())
    sys.modules.setdefault("django.db.models",                        MagicMock())
    sys.modules.setdefault("django.db.models.functions",              MagicMock())
    sys.modules.setdefault("django_filters",                          MagicMock())
    sys.modules.setdefault("django_filters.rest_framework",           MagicMock())
    sys.modules.setdefault("drf_spectacular",                         MagicMock())
    sys.modules.setdefault("drf_spectacular.utils",                   drf_spectacular_utils_stub)
    sys.modules.setdefault("rest_framework",                          drf_stub)
    sys.modules.setdefault("rest_framework.generics",                 drf_generics_stub)
    sys.modules.setdefault("rest_framework.permissions",              MagicMock())
    sys.modules.setdefault("rest_framework.response",                 MagicMock())
    sys.modules.setdefault("rest_framework.views",                    drf_views_stub)
    sys.modules.setdefault("dashboard",                               MagicMock())
    sys.modules.setdefault("dashboard.models",                        MagicMock())
    sys.modules.setdefault("api.serializers",                         MagicMock())
    sys.modules.setdefault("api.serializers.dashboard",               MagicMock())
    sys.modules.setdefault("api.views.filters",                       MagicMock())
    sys.modules.setdefault("api.views.mixins",                        mixins_stub)


_setup_stubs()

for _k in list(sys.modules):
    if "api.views.dashboard" in _k:
        del sys.modules[_k]

import django.core.cache as _cache_module  # noqa: E402


class TestDashboardSummaryViewCache(unittest.TestCase):

    def _get_view(self):
        sys.modules.pop("api.views.dashboard", None)
        from api.views.dashboard import DashboardSummaryView
        return DashboardSummaryView

    def test_cache_miss_builds_payload_and_sets_cache(self):
        """On cache miss, _build_summary_payload is called and result is cached."""
        fake_payload = {"month": 4, "year": 2026, "scope": "ALL", "kpis": {}}

        # Import the module fresh first, then patch the module-level 'cache' name directly
        view_cls = self._get_view()

        with patch("api.views.dashboard.cache") as mock_cache, \
             patch.object(view_cls, "_build_summary_payload", return_value=fake_payload) as mock_build, \
             patch("api.views.dashboard.DashboardSummaryQuerySerializer") as mock_serial, \
             patch("api.views.dashboard.DashboardSummaryResponseSerializer") as mock_resp:

            view = view_cls()
            view.request = MagicMock()
            view.request.user.groups.filter.return_value.exists.return_value = False
            view.request.query_params = {"month": "4", "year": "2026"}

            mock_serial.return_value.is_valid.return_value = True
            mock_serial.return_value.validated_data = {"month": 4, "year": 2026, "scope": "ALL"}
            mock_cache.get.return_value = None  # cache miss

            view.get(view.request)

            mock_cache.get.assert_called_once_with("dashboard:summary:2026:4:ALL")
            mock_build.assert_called_once_with(month=4, year=2026, scope="ALL")
            mock_cache.set.assert_called_once_with(
                "dashboard:summary:2026:4:ALL", fake_payload, 120
            )

    def test_cache_hit_skips_build(self):
        """On cache hit, _build_summary_payload is NOT called."""
        cached_payload = {"month": 4, "year": 2026, "scope": "ALL", "kpis": {}}

        view_cls = self._get_view()

        with patch("api.views.dashboard.cache") as mock_cache, \
             patch.object(view_cls, "_build_summary_payload") as mock_build, \
             patch("api.views.dashboard.DashboardSummaryQuerySerializer") as mock_serial, \
             patch("api.views.dashboard.DashboardSummaryResponseSerializer"):

            view = view_cls()
            view.request = MagicMock()
            view.request.user.groups.filter.return_value.exists.return_value = False
            view.request.query_params = {"month": "4", "year": "2026"}

            mock_serial.return_value.is_valid.return_value = True
            mock_serial.return_value.validated_data = {"month": 4, "year": 2026, "scope": "ALL"}
            mock_cache.get.return_value = cached_payload  # cache hit

            view.get(view.request)

            mock_build.assert_not_called()
            mock_cache.set.assert_not_called()

    def test_cache_key_includes_scope(self):
        """CISO scope produces a different cache key than ALL scope."""
        view_cls = self._get_view()

        with patch("api.views.dashboard.cache") as mock_cache, \
             patch.object(view_cls, "_build_summary_payload", return_value={}), \
             patch("api.views.dashboard.DashboardSummaryQuerySerializer") as mock_serial, \
             patch("api.views.dashboard.DashboardSummaryResponseSerializer"):

            view = view_cls()
            view.request = MagicMock()
            # Simulate CISO user
            view.request.user.groups.filter.return_value.exists.return_value = True
            view.request.query_params = {"month": "4", "year": "2026", "scope": "CISO"}

            mock_serial.return_value.is_valid.return_value = True
            mock_serial.return_value.validated_data = {"month": 4, "year": 2026, "scope": "CISO"}
            mock_cache.get.return_value = None

            view.get(view.request)

            key_used = mock_cache.get.call_args[0][0]
            self.assertIn("CISO", key_used)
            self.assertNotIn("ALL", key_used)


class TestMonthlyCasesSummaryAggregateViewCache(unittest.TestCase):

    def _get_view(self):
        sys.modules.pop("api.views.dashboard", None)
        from api.views.dashboard import MonthlyCasesSummaryAggregateView
        return MonthlyCasesSummaryAggregateView

    def test_cache_miss_runs_aggregate_and_caches(self):
        view_cls = self._get_view()
        view = view_cls()

        fake_data = {"suspicious_cases": 5, "safe_cases": 3}

        with patch("api.views.dashboard.cache") as mock_cache, \
             patch.object(view_cls, "get_month_year", return_value=(4, 2026)), \
             patch("api.views.dashboard.MonthlyCasesSummary") as mock_model, \
             patch("api.views.dashboard.MonthlyCasesSummaryAggregateSerializer") as mock_serial:

            mock_cache.get.return_value = None
            mock_model.objects.filter.return_value.aggregate.return_value = fake_data
            mock_serial.return_value.data = fake_data

            view.get(MagicMock())

            mock_cache.get.assert_called_once_with("dashboard:monthly-cases:2026:4")
            mock_cache.set.assert_called_once()
            args = mock_cache.set.call_args[0]
            self.assertEqual(args[0], "dashboard:monthly-cases:2026:4")
            self.assertEqual(args[2], 120)

    def test_cache_hit_skips_aggregate(self):
        view_cls = self._get_view()
        view = view_cls()

        cached_data = {"suspicious_cases": 5}

        with patch("api.views.dashboard.cache") as mock_cache, \
             patch.object(view_cls, "get_month_year", return_value=(4, 2026)), \
             patch("api.views.dashboard.MonthlyCasesSummary") as mock_model, \
             patch("api.views.dashboard.MonthlyCasesSummaryAggregateSerializer") as mock_serial:

            mock_cache.get.return_value = cached_data
            mock_serial.return_value.data = cached_data

            view.get(MagicMock())

            mock_model.objects.filter.assert_not_called()
            mock_cache.set.assert_not_called()


class TestUserCasesMonthlyStatsAggregateViewCache(unittest.TestCase):

    def _get_view(self):
        sys.modules.pop("api.views.dashboard", None)
        from api.views.dashboard import UserCasesMonthlyStatsAggregateView
        return UserCasesMonthlyStatsAggregateView

    def test_cache_miss_runs_query_and_caches(self):
        view_cls = self._get_view()
        view = view_cls()

        fake_payload = [{"username": "alice", "total_cases": 3}]

        with patch("api.views.dashboard.cache") as mock_cache, \
             patch.object(view_cls, "get_month_year", return_value=(4, 2026)), \
             patch("api.views.dashboard.UserCasesMonthlyStats") as mock_model, \
             patch("api.views.dashboard.UserCasesMonthlyStatsAggregateRowSerializer") as mock_serial:

            mock_cache.get.return_value = None
            # Simulate queryset chain
            mock_qs = MagicMock()
            mock_model.objects.filter.return_value.values.return_value.annotate.return_value.order_by.return_value = mock_qs
            mock_qs.__iter__ = MagicMock(return_value=iter([]))
            mock_serial.return_value.data = []

            view.get(MagicMock())

            mock_cache.get.assert_called_once_with("dashboard:user-stats:2026:4")
            mock_cache.set.assert_called_once()
            key_used = mock_cache.set.call_args[0][0]
            self.assertEqual(key_used, "dashboard:user-stats:2026:4")

    def test_cache_hit_returns_early(self):
        view_cls = self._get_view()
        view = view_cls()

        cached_payload = [{"username": "alice", "total_cases": 3}]

        with patch("api.views.dashboard.cache") as mock_cache, \
             patch.object(view_cls, "get_month_year", return_value=(4, 2026)), \
             patch("api.views.dashboard.UserCasesMonthlyStats") as mock_model, \
             patch("api.views.dashboard.UserCasesMonthlyStatsAggregateRowSerializer") as mock_serial:

            mock_cache.get.return_value = cached_payload
            mock_serial.return_value.data = cached_payload

            view.get(MagicMock())

            mock_model.objects.filter.assert_not_called()
            mock_cache.set.assert_not_called()
