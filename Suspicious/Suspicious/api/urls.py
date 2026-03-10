from django.urls import path
from .views import (
    # Authentication
    LogoutView,
    LoginView,
    MeView,

    # Monthly global stats
    MonthlyCasesSummaryListView,
    MonthlyCasesSummaryAggregateView,
    MonthlyReporterStatsListView,
    TotalCasesStatsListView,

    # User stats
    UserCasesMonthlyStatsListView,
    UserCasesMonthlyStatsDetailView,
    UserCasesMonthlyStatsAggregateView,
    
    # Dashboard stats
    DashboardSummaryView,
    
    # Dashboard Campaigns stats
    CampaignClassificationCountsView,
    CampaignPcaView,
    CampaignMailVolumeView,
    
    # Home stats
    HomeSummaryView,
    
    # Submissions
    SubmissionListView,
    
    # Profile
    ProfileView,
    ProfilePreferencesView,
    ProfileAppearanceView,

    # Downloads
    DownloadCaseArchiveView,
    CaseChallengeTokenView,
)
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
urlpatterns = [
    path("schema/", SpectacularAPIView.as_view(), name="schema"),
    path("docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/logout/", LogoutView.as_view(), name="logout"),
    path("auth/me/", MeView.as_view(), name="me"),

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
    
    # ------------------------------------------------------------------
    # Dashboard summary
    # ------------------------------------------------------------------
    path(
        "dashboard/summary/",
        DashboardSummaryView.as_view(),
        name="dashboard-summary",
    ),
    
    # ------------------------------------------------------------------
    # Dashboard Campaigns stats
    # ------------------------------------------------------------------
    path(
        "campaigns/classification-counts/",
        CampaignClassificationCountsView.as_view(),
        name="campaign-classification-counts",
    ),
    path(
        "campaigns/pca/",
        CampaignPcaView.as_view(),
        name="campaign-pca",
    ),
    path(
        "campaigns/mail-volume/",
        CampaignMailVolumeView.as_view(),
        name="campaign-mail-volume",
    ),
    
    # ------------------------------------------------------------------
    # Profile
    # ------------------------------------------------------------------
    path(
        "profile/",
        ProfileView.as_view(),
        name="profile",
    ),
    path(
        "profile/preferences/",
        ProfilePreferencesView.as_view(),
        name="profile-preferences",
    ),
    path(
        "profile/appearance/",
        ProfileAppearanceView.as_view(),
        name="profile-appearance",
    ),
    
    # ------------------------------------------------------------------
    # submissions summary
    # ------------------------------------------------------------------
    path(
        "submissions/",
        SubmissionListView.as_view(),
        name="submissions-list",
    ),
    
    # ------------------------------------------------------------------
    # Home summary
    # ------------------------------------------------------------------
    path(
        "home/summary/",
        HomeSummaryView.as_view(),
        name="home-summary",
    ),
]
