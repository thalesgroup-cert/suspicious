from django.urls import path
from .views import (
    # Monthly global stats
    MonthlyCasesSummaryListView,
    MonthlyCasesSummaryAggregateView,
    MonthlyReporterStatsListView,
    TotalCasesStatsListView,

    # User stats
    UserCasesMonthlyStatsListView,
    UserCasesMonthlyStatsDetailView,
    UserCasesMonthlyStatsAggregateView,

    # Downloads
    DownloadCaseArchiveView,
    CaseChallengeTokenView,
)
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
urlpatterns = [
    path("schema/", SpectacularAPIView.as_view(), name="schema"),
    path("docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    # ------------------------------------------------------------------
    # Global monthly statistics
    # ------------------------------------------------------------------
    path(
        "stats/monthly-cases/",
        MonthlyCasesSummaryListView.as_view(),
        name="monthly-cases-list",
    ),
    path(
        "stats/monthly-cases/aggregate/",
        MonthlyCasesSummaryAggregateView.as_view(),
        name="monthly-cases-aggregate",
    ),
    path(
        "stats/monthly-reporters/",
        MonthlyReporterStatsListView.as_view(),
        name="monthly-reporters-list",
    ),
    path(
        "stats/total-cases/",
        TotalCasesStatsListView.as_view(),
        name="total-cases-list",
    ),

    # ------------------------------------------------------------------
    # User monthly statistics
    # ------------------------------------------------------------------
    path(
        "stats/user-cases/",
        UserCasesMonthlyStatsListView.as_view(),
        name="user-cases-list",
    ),
    path(
        "stats/user-cases/<int:pk>/",
        UserCasesMonthlyStatsDetailView.as_view(),
        name="user-cases-detail",
    ),
    path(
        "stats/user-cases/aggregate/",
        UserCasesMonthlyStatsAggregateView.as_view(),
        name="user-cases-aggregate",
    ),

    # ------------------------------------------------------------------
    # Case artifacts
    # ------------------------------------------------------------------
    path(
        "cases/<int:case_id>/download/",
        DownloadCaseArchiveView.as_view(),
        name="case-download",
    ),
    path(
        "cases/<int:case_id>/challenge",
        CaseChallengeTokenView.as_view(),
        name="case-challenge",
    ),
]
