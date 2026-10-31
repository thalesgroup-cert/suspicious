"""In-repo dummy connector used by framework tests."""
from connectors.base import (
    ConfigField,
    Connector,
    ConnectorManifest,
    HealthStatus,
    PROVIDER_KIND_MAIL_AI,
    ProviderResult,
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
            ConfigField("ui_url", "url"),
            ConfigField("api_key", "secret"),
            ConfigField("nested.deep.token", "secret"),
        ),
        events=(EVENT_CASE_FINALISED,),
        schedules=(Schedule("sync", 120),),
    )

    calls: list = []

    def health_check(self) -> HealthStatus:
        return HealthStatus(ok=True, detail="dummy ok")

    def on_case_finalised(self, event) -> None:
        type(self).calls.append(event)

    def sync(self) -> None:
        type(self).calls.append("sync")


class DummyProviderConnector(Connector):
    """Test fixture for the mail_ai provider slot. ``result`` / ``error`` are
    class attributes so a test sets what ``analyze`` yields."""

    manifest = ConnectorManifest(
        name="dummy_provider",
        version="0.0.1",
        description="Test fixture analysis provider.",
        provides=PROVIDER_KIND_MAIL_AI,
    )

    result: ProviderResult | None = None
    error: Exception | None = None

    def health_check(self) -> HealthStatus:
        return HealthStatus(ok=True, detail="dummy provider ok")

    def analyze(self, kind: str, case_id: int) -> ProviderResult:
        if type(self).error is not None:
            raise type(self).error
        return type(self).result
