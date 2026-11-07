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


def sync(client=None) -> bool:
    """Reload the server when it differs from the registry; True when it matches afterwards.
    ReloadRefused on a 4xx; a transient failure returns False and the beat retries."""
    if client is None:
        from connectors.registry import registry as connectors
        client = connectors.instantiate("ai_model")._client()
    try:
        if server_matches(client):
            return True
        client.reload(wanted_state())
        return server_matches(client)
    except ValueError:
        raise ReloadRefused("the inference server refused the reload") from None
    except (ProviderUnavailable, ServerBusy) as exc:
        logger.warning("ai_model server sync failed: %s", type(exc).__name__)
        return False
