from django.urls import path
from rest_framework.views import APIView
from api.views.auth import LoginView, LogoutView, MeView
from api.views.dashboard import DashboardSummaryView, MonthlyCasesSummaryListView, MonthlyCasesSummaryAggregateView, MonthlyReporterStatsListView, TotalCasesStatsListView, UserCasesMonthlyStatsListView, UserCasesMonthlyStatsDetailView, UserCasesMonthlyStatsAggregateView
from api.views.profile import ProfileView, ProfilePreferencesView, ProfileAppearanceView
from api.views.challenge import CaseChallengeTokenView

from api.views.submissions import SubmissionListView, MySubmissionsView, SubmissionDetailsView, SubmissionChallengeView
from api.views.settings import SettingsListView, SettingsListItemDeleteView, EmailFeederSettingsView, AnalyzerSettingsListView, AnalyzerSettingsDetailView
from api.views.investigations import InvestigationListView, InvestigationDetailsView, InvestigationGlobalEditView
from api.views.home import HomeSummaryView
from api.views.challenge import CaseChallengeTokenView
from api.views.downloads import DownloadCaseArchiveView
from api.views.campaigns import CampaignClassificationCountsView, CampaignPcaView, CampaignMailVolumeView

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
    path(
        "submissions/mine/",
        MySubmissionsView.as_view(),
        name="my-submissions",
    ),
    path("submissions/<int:submission_id>/", SubmissionDetailsView.as_view(), name="submission-details"),
    path("submissions/<int:submission_id>/challenge/", SubmissionChallengeView.as_view(), name="submission-challenge"),

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------
    path("settings/list/<str:section>/", SettingsListView.as_view(), name="settings-list"),
    path("settings/list/<str:section>/<int:item_id>/", SettingsListItemDeleteView.as_view(), name="settings-list-delete"),

    path("settings/email-feeder/", EmailFeederSettingsView.as_view(), name="settings-email-feeder"),

    path("settings/analyzers/", AnalyzerSettingsListView.as_view(), name="settings-analyzers"),
    path("settings/analyzers/<int:analyzer_id>/", AnalyzerSettingsDetailView.as_view(), name="settings-analyzer-detail"),

    path("investigations/", InvestigationListView.as_view(), name="investigation-list"),
    path("investigations/<int:case_id>/", InvestigationDetailsView.as_view(), name="investigation-details"),
    path("investigations/<int:case_id>/edit-global/", InvestigationGlobalEditView.as_view(), name="investigation-edit-global"),

    # ------------------------------------------------------------------
    # Home summary
    # ------------------------------------------------------------------
    path(
        "home/summary/",
        HomeSummaryView.as_view(),
        name="home-summary",
    ),
]
