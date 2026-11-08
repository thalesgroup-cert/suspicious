"""Keep the inference server's loaded models equal to the registry (Ruling F2). The registry is the
truth: the server holds models in memory only, so a restarted server is brought back by `sync`."""
import logging

from connectors.contrib.ai_model.client import ServerBusy
from connectors.providers import ProviderUnavailable

from . import registry
from .models import ModelVersion

logger = logging.getLogger(__name__)
LEGACY_ID = "v0"  # what a server without a loaded bundle reports as active


class ReloadRefused(Exception):
    """The server answered a reload with a 4xx. The message carries no URL and no body."""


class ShadowRefused(ReloadRefused):
    """The server refused the reload with the shadow and took the active part without it."""


def _rows():
    S = ModelVersion.Status
    return (ModelVersion.objects.filter(status=S.ACTIVE).first(),
            ModelVersion.objects.filter(status=S.SHADOW).first())


def wanted_state() -> dict:
    return registry.reload_payload(*_rows())


def _wanted_ids():
    active, shadow = _rows()
    return (active.version_id if active and active.bundle_prefix else LEGACY_ID,
            shadow.version_id if shadow else None)


def server_matches(client) -> bool:
    versions = client.metadata().get("versions") or {}
    return (versions.get("active", {}).get("id"), versions.get("shadow", {}).get("id")) == _wanted_ids()


def _reload(client, active, shadow):
    try:
        client.reload(registry.reload_payload(active, shadow))
    except ValueError:
        raise ReloadRefused("the inference server refused the reload") from None


def sync(client=None, *, shadow_must_load=False) -> bool:
    """Reload the server when it differs from the registry; True when it matches afterwards.
    A reload refused (4xx) while a shadow is wanted is retried once without the shadow, so the
    active pointer never depends on the shadow bundle: the shadow gets a `shadow_refused` event
    and sync returns False (ShadowRefused with shadow_must_load). ReloadRefused when the reload
    without a shadow is refused; a transient failure, or no usable connector, returns False and
    the beat retries."""
    try:
        if client is None:
            from connectors.registry import registry as connectors
            client = connectors.instantiate("ai_model")._client()
        if server_matches(client):
            return True
        active, shadow = _rows()
        try:
            _reload(client, active, shadow)
        except ReloadRefused:
            if shadow is None:
                raise
            _reload(client, active, None)
            logger.warning("ai_model server refused the shadow %s, loaded without it", shadow.version_id)
            registry.shadow_refused(shadow)
            if shadow_must_load:
                raise ShadowRefused("the inference server refused the shadow") from None
            return False
        return server_matches(client)
    except (ProviderUnavailable, ServerBusy, ValueError, KeyError) as exc:  # not ReloadRefused
        logger.warning("ai_model server sync failed: %s", type(exc).__name__)
        return False
