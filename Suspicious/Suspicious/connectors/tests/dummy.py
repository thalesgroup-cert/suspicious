"""In-repo dummy connector used by framework tests."""
from connectors.base import (
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
    Schedule,
    EVENT_CASE_FINALISED,
)


class DummyConnector(Connector):
    manifest = ConnectorManifest(
        name="dummy",
        version="0.0.1",
        description="Test fixture connector.",
        config_schema=(
            ConfigField("url", "url", required=True),
            ConfigField("api_key", "secret"),
            ConfigField("nested.deep.token", "secret"),
        ),
        events=(EVENT_CASE_FINALISED,),
        schedules=(Schedule("sync", 120),),
    )

    calls: list = []  # class-level call recorder for assertions

    def health_check(self) -> HealthStatus:
        return HealthStatus(ok=True, detail="dummy ok")

    def on_case_finalised(self, event) -> None:
        type(self).calls.append(event)

    def sync(self) -> None:
        type(self).calls.append("sync")
