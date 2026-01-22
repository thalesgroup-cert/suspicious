from django.urls import include, path
from tasp import views

app_name = "tasp"

urlpatterns = [
    # Home
    path("", views.home, name="home"),

    # Auth
    path("logout/", views.logout_view, name="logout"),
    path("accounts/", include("django.contrib.auth.urls")),

    # OIDC SSO
    path("oidc/login/", views.oidc_login, name="oidc_login"),
    path("oidc/callback/", views.oidc_callback, name="oidc_callback"),

    # Main pages / flows
    path("submit/", views.submit, name="submit"),
    path("submissions/", views.submissions, name="submissions"),
    path("about/", views.about, name="about"),

    # Admin / investigation
    path("tasp-admin/", views.tasp, name="tasp"),

    # Actions / API-like endpoints
    path(
        "update-ciso-profile-scope/<str:scope>/",
        views.update_ciso_profile_scope,
        name="update_ciso_profile_scope",
    ),
    path(
        "set-ioc-level/<id>/<type>/<level>/<case_id>",
        views.set_ioc_level,
        name="set_ioc_level",
    ),
    path(
        "create-case-popup/<case_id>/<user>",
        views.create_case_popup,
        name="create_case_popup",
    ),
    path(
        "edit-global/<case_id>/<score>/<confidence>/<classification>",
        views.edit_global,
        name="edit_global",
    ),
    path(
        "get-link-analyzer/<value>/<ioc_type>",
        views.get_link_analyzer,
        name="get_link_analyzer",
    ),
    path(
        "challenge/<case_id>",
        views.challenge,
        name="challenge",
    ),
    path(
        "compute/<id>/<user>",
        views.compute,
        name="compute",
    ),
]
