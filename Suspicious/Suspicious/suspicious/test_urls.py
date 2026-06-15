# test_urls.py — minimal URL configuration for use during unit tests.
#
# The test runner uses --settings=suspicious.test_settings which points
# ROOT_URLCONF here.  This avoids importing the full api/ view tree,
# which depends on system libraries (libmagic, libldap) that are not
# present outside Docker.
#
# Individual lightweight routes whose views have no heavy system-lib
# dependencies may be registered here so their endpoint tests can run
# outside the container. The production URLConf (suspicious.urls →
# api.urls) remains the source of truth for the real deployment.

from django.urls import path

from api.views.config import ServiceConfigView
from api.views.connectors import (
    ConnectorConfigView,
    ConnectorDeliveriesView,
    ConnectorListView,
    ConnectorStateView,
    ConnectorTestView,
)

urlpatterns: list = [
    path("api/config/<str:scope>/", ServiceConfigView.as_view(), name="service-config"),
    path("api/connectors/", ConnectorListView.as_view(), name="connectors-list"),
    path("api/connectors/<str:name>/", ConnectorStateView.as_view(), name="connector-state"),
    path(
        "api/connectors/<str:name>/config/",
        ConnectorConfigView.as_view(),
        name="connector-config",
    ),
    path(
        "api/connectors/<str:name>/test/",
        ConnectorTestView.as_view(),
        name="connector-test",
    ),
    path(
        "api/connectors/<str:name>/deliveries/",
        ConnectorDeliveriesView.as_view(),
        name="connector-deliveries",
    ),
]
