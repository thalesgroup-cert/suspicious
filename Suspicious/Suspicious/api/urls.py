from django.urls import path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from api.views.auth import LoginView, LogoutView, MeView
from api.views.campaigns import (
    CampaignClassificationCountsView,
    CampaignMailVolumeView,
    CampaignPcaView,
)
from api.views.challenge import CaseChallengeTokenView
from api.views.comments import CaseCommentListCreateView
from api.views.dashboard import (
    DashboardSummaryView,
    MonthlyCasesSummaryAggregateView,
    MonthlyCasesSummaryListView,
    MonthlyReporterStatsListView,
    TotalCasesStatsListView,
    UserCasesMonthlyStatsAggregateView,
    UserCasesMonthlyStatsDetailView,
    UserCasesMonthlyStatsListView,
    TopPrefixesView,
)
from api.views.downloads import DownloadCaseArchiveView
from api.views.home import HomeSummaryView
from api.views.feeder_health import FeederHealthView
from api.views.health import HealthView
from api.views.mail_preview import MailPreviewView
from api.views.investigations import (
    InvestigationDetailsView,
    InvestigationGlobalEditView,
    InvestigationListView,
)
from api.views.profile import (
    ProfileView,
    AppearanceView,
    AvatarUploadView,
    PreferencesView,
    SemanticColorsView,
    ResetSemanticColorsView,
)
from api.views.settings import (
    AnalyzerSettingsDetailView,
    AnalyzerSettingsListView,
    EmailFeederSettingsView,
    SettingsListItemDeleteView,
    SettingsListView,
)
from api.views.submit import (
    SubmitConfigView,
    SubmitFileView,
    SubmitOtherView,
    SubmitUrlView,
)
from api.views.submissions import (
    SubmissionChallengeView,
    SubmissionDetailsView,
    SubmissionListView,
)
from api.views.oidc import OIDCCallbackView, OIDCLoginView
from api.views.cortex_webhook import CortexWebhookView
from api.views.config import ServiceConfigView
from api.views.connectors import (
    ConnectorConfigView,
    ConnectorDeliveriesView,
    ConnectorListView,
    ConnectorStateView,
    ConnectorTestView,
)
from api.views.url_analysis import SubmissionUrlAnalyzeView

urlpatterns = [
    path("schema/", SpectacularAPIView.as_view(), name="schema"),
    path("docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),

    path("auth/login/", LoginView.as_view(), name="login"),
    path("auth/logout/", LogoutView.as_view(), name="logout"),
    path("auth/me/", MeView.as_view(), name="me"),

    path("oidc/login/",    OIDCLoginView.as_view(),    name="oidc-login"),
    path("oidc/callback/", OIDCCallbackView.as_view(), name="oidc-callback"),

    path("stats/monthly-cases/", MonthlyCasesSummaryListView.as_view(), name="monthly-cases-list"),
    path("stats/monthly-cases/aggregate/", MonthlyCasesSummaryAggregateView.as_view(), name="monthly-cases-aggregate"),
    path("stats/monthly-reporters/", MonthlyReporterStatsListView.as_view(), name="monthly-reporters-list"),
    path("stats/total-cases/", TotalCasesStatsListView.as_view(), name="total-cases-list"),

    path("stats/user-cases/", UserCasesMonthlyStatsListView.as_view(), name="user-cases-list"),
    path("stats/user-cases/<int:pk>/", UserCasesMonthlyStatsDetailView.as_view(), name="user-cases-detail"),
    path("stats/user-cases/aggregate/", UserCasesMonthlyStatsAggregateView.as_view(), name="user-cases-aggregate"),
    path("stats/top-prefixes/", TopPrefixesView.as_view(), name="top-prefixes"),

    path("cases/<int:case_id>/download/", DownloadCaseArchiveView.as_view(), name="case-download"),
    path("cases/<int:case_id>/mail-preview.png", MailPreviewView.as_view(), name="case-mail-preview"),
    path("cases/<int:case_id>/challenge/<str:token>/", CaseChallengeTokenView.as_view(), name="case-challenge"),
    path("cases/<int:case_id>/challenge/", CaseChallengeTokenView.as_view(), name="case-challenge-legacy"),
    path("cases/<int:case_id>/comments/", CaseCommentListCreateView.as_view(), name="case-comments"),

    path("dashboard/summary/", DashboardSummaryView.as_view(), name="dashboard-summary"),

    path("campaigns/classification-counts/", CampaignClassificationCountsView.as_view(), name="campaign-classification-counts"),
    path("campaigns/pca/", CampaignPcaView.as_view(), name="campaign-pca"),
    path("campaigns/mail-volume/", CampaignMailVolumeView.as_view(), name="campaign-mail-volume"),

    path("profile/",              ProfileView.as_view(),             name="profile"),
    path("profile/appearance/",   AppearanceView.as_view(),          name="profile-appearance"),
    path("profile/avatar/upload/",AvatarUploadView.as_view(),        name="profile-avatar-upload"),
    path("profile/preferences/",  PreferencesView.as_view(),         name="profile-preferences"),
    path("profile/colors/",       SemanticColorsView.as_view(),      name="profile-colors"),
    path("profile/colors/reset/", ResetSemanticColorsView.as_view(), name="profile-colors-reset"),

    path("submissions/", SubmissionListView.as_view(), name="submissions-list"),
    path("submissions/<int:submission_id>/", SubmissionDetailsView.as_view(), name="submission-details"),
    path("submissions/<int:submission_id>/challenge/", SubmissionChallengeView.as_view(), name="submission-challenge"),
    path("submissions/<int:submission_id>/urls/<int:url_id>/analyze/",
         SubmissionUrlAnalyzeView.as_view(), name="submission-url-analyze"),

    path("settings/list/<str:section>/", SettingsListView.as_view(), name="settings-list"),
    path("settings/list/<str:section>/<int:item_id>/", SettingsListItemDeleteView.as_view(), name="settings-list-delete"),
    path("settings/email-feeder/", EmailFeederSettingsView.as_view(), name="settings-email-feeder"),
    path("feeder/health/", FeederHealthView.as_view(), name="feeder-health"),
    path("health/", HealthView.as_view(), name="suspicious-health"),
    path("settings/analyzers/", AnalyzerSettingsListView.as_view(), name="settings-analyzers"),
    path("settings/analyzers/<int:analyzer_id>/", AnalyzerSettingsDetailView.as_view(), name="settings-analyzer-detail"),

    path("investigations/", InvestigationListView.as_view(), name="investigation-list"),
    path("investigations/<int:case_id>/", InvestigationDetailsView.as_view(), name="investigation-details"),
    path("investigations/<int:case_id>/edit-global/", InvestigationGlobalEditView.as_view(), name="investigation-edit-global"),

    path("submit/config/", SubmitConfigView.as_view(), name="submit-config"),
    path("submit/url/", SubmitUrlView.as_view(), name="submit-url"),
    path("submit/other/", SubmitOtherView.as_view(), name="submit-other"),
    path("submit/file/", SubmitFileView.as_view(), name="submit-file"),

    path("home/summary/", HomeSummaryView.as_view(), name="home-summary"),

    path("cortex/webhook/", CortexWebhookView.as_view(), name="cortex-webhook"),

    path("config/<str:scope>/", ServiceConfigView.as_view(), name="service-config"),

    path("connectors/", ConnectorListView.as_view(), name="connectors-list"),
    path("connectors/<str:name>/", ConnectorStateView.as_view(), name="connector-state"),
    path("connectors/<str:name>/config/", ConnectorConfigView.as_view(), name="connector-config"),
    path("connectors/<str:name>/test/", ConnectorTestView.as_view(), name="connector-test"),
    path("connectors/<str:name>/deliveries/", ConnectorDeliveriesView.as_view(), name="connector-deliveries"),
]
