
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
