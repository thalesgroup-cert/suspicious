"""Connector management endpoints (Admin/CERT only).

Secret config fields are masked on read; on write they are routed to Vault
via set_secret and are NEVER persisted to the RuntimeConfig DB row.
Non-secret fields are written to RuntimeConfig as before."""
import copy
import logging
from dataclasses import asdict

from django.utils import timezone
from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions.settings import IsAdminOrCERT
from api.serializers.connectors import (
    ConnectorDeliverySerializer,
    ConnectorSerializer,
)
from connectors.delivery import get_state
from connectors.models import ConnectorDelivery
from connectors.registry import registry
from settings.config import SECRET_FIELDS, get_section, invalidate_cache
from suspicious.secrets import SecretStoreUnavailable, set_secret

logger = logging.getLogger("api.connectors")

SECRET_MASK = "********"


def _connector_or_none(name: str):
    try:
        return registry.get(name)
    except KeyError:
        return None


def _compute_status(config_schema, enabled: bool, section: dict) -> str:
    """Disabled/partial/connected — mirrors Watcher's own connector status
    logic. No 'disconnected' state: Watcher's badge config defines one but
    its _compute_status never returns it."""
    if not enabled:
        return "disabled"
    required = [f for f in config_schema if f.required]
    if not required:
        return "connected"
    filled = [f for f in required if _dotted_get(section, f.key)]
    return "connected" if len(filled) == len(required) else "partial"


def _serialize_connector(name: str) -> dict:
    cls = registry.get(name)
    manifest = cls.manifest
    state = get_state(name)
    section = get_section(f"integrations.{name}")
    return {
        "name": manifest.name,
        "version": manifest.version,
        "description": manifest.description,
        "author": manifest.author,
        "docs_url": manifest.docs_url,
        "category": manifest.category,
        "events": list(manifest.events),
        "schedules": [asdict(s) for s in manifest.schedules],
        "config_schema": [asdict(f) for f in manifest.config_schema],
        "enabled": state.enabled,
        "enabled_by_default": manifest.enabled_by_default,
        "status": _compute_status(manifest.config_schema, state.enabled, section),
        "last_health_ok": state.last_health_ok,
        "last_health_detail": state.last_health_detail,
        "last_health_at": state.last_health_at,
    }


class ConnectorListView(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrCERT]

    def get(self, request):
        data = [_serialize_connector(name) for name in registry.names()]
        return Response({
            "connectors": ConnectorSerializer(data, many=True).data,
            "load_errors": registry.errors,
        })


class ConnectorStateView(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrCERT]

    def patch(self, request, name: str):
        if _connector_or_none(name) is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        enabled = request.data.get("enabled")
        if not isinstance(enabled, bool):
            return Response({"detail": "'enabled' must be a boolean."},
                            status=status.HTTP_400_BAD_REQUEST)
        state = get_state(name)
        state.enabled = enabled
        state.save(update_fields=["enabled", "updated_at"])
        return Response(ConnectorSerializer(_serialize_connector(name)).data)


def _dotted_get(data: dict, dotted: str):
    node = data
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _mask_secrets(section: dict, section_name: str) -> dict:
    """Replace every Vault-overlaid secret leaf with the mask (handles
    sub-section SECRET_FIELDS entries like integrations.misp.instances.primary)."""
    masked = dict(section)
    for sec, leaves in SECRET_FIELDS.items():
        if sec == section_name:
            for leaf in leaves:
                if masked.get(leaf):
                    masked[leaf] = SECRET_MASK
        elif sec.startswith(section_name + "."):
            sub_path = sec[len(section_name) + 1:].split(".")
            node = masked
            for part in sub_path:
                node = node.get(part) if isinstance(node, dict) else None
                if node is None:
                    break
            if isinstance(node, dict):
                for leaf in leaves:
                    if node.get(leaf):
                        node[leaf] = SECRET_MASK
    return masked


def _apply_to_secret_leaves(payload: dict, schema, action) -> dict:
    """Deep-copy ``payload`` and call ``action(parent_dict, leaf_key)`` on every
    secret-typed leaf present in it. The schema is the authoritative source of
    which fields are secret — never SECRET_FIELDS, so connector-defined secrets
    are handled even if they are absent from that static map."""
    cleaned = copy.deepcopy(payload)
    for field in schema:
        if field.type != "secret":
            continue
        parts = field.key.split(".")
        node = cleaned
        for part in parts[:-1]:
            node = node.get(part) if isinstance(node, dict) else None
            if node is None:
                break
        if isinstance(node, dict):
            action(node, parts[-1])
    return cleaned


def _strip_secret_leaves(payload: dict, schema) -> dict:
    """Copy of payload with every secret-typed leaf removed, so secrets are
    never persisted to the RuntimeConfig DB row."""
    return _apply_to_secret_leaves(
        payload, schema, lambda node, leaf: node.pop(leaf, None)
    )


def _mask_secret_leaves(payload: dict, schema) -> dict:
    """Copy of payload with every secret-typed leaf that is present replaced by
    the mask — used for the response body so cleartext secrets are never echoed."""
    def mask(node, leaf):
        if leaf in node:
            node[leaf] = SECRET_MASK

    return _apply_to_secret_leaves(payload, schema, mask)


class ConnectorConfigView(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrCERT]

    def get(self, request, name: str):
        if _connector_or_none(name) is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        section_name = f"integrations.{name}"
        return Response({
            "config": _mask_secrets(get_section(section_name), section_name)
        })

    def put(self, request, name: str):
        cls = _connector_or_none(name)
        if cls is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        schema = cls.manifest.config_schema
        payload = request.data if isinstance(request.data, dict) else {}

        errors = {}
        # (vault_key, value, field_key) — applied only after validation passes.
        secret_writes = []
        for field in schema:
            value = _dotted_get(payload, field.key)
            if field.type == "secret":
                # None = field absent; SECRET_MASK = UI echoed the mask back —
                # both mean "leave the stored secret unchanged".
                if value not in (None, SECRET_MASK):
                    secret_writes.append(
                        (f"integrations.{name}.{field.key}", value, field.key)
                    )
            elif field.required and value in (None, ""):
                errors[field.key] = "this field is required"
            elif value is not None and field.type == "int" and not isinstance(value, int):
                errors[field.key] = "must be an integer"
            elif value is not None and field.type == "bool" and not isinstance(value, bool):
                errors[field.key] = "must be a boolean"
        if errors:
            return Response({"errors": errors}, status=status.HTTP_400_BAD_REQUEST)

        # Secrets are written before the DB row. With multiple secrets, a failure
        # on a later write leaves earlier ones in Vault while the DB is not
        # updated; a retry re-writes them idempotently (KV v2), so this is
        # eventually consistent and intentionally not rolled back.
        for vault_key, value, field_key in secret_writes:
            try:
                set_secret(vault_key, value)
            except SecretStoreUnavailable:
                return Response(
                    {"errors": {field_key: "secret store not configured"}},
                    status=status.HTTP_409_CONFLICT,
                )
            except Exception:  # noqa: BLE001 — surface any Vault write failure as 502
                # Log full detail server-side (never the value); return a generic
                # message so internal error text is not echoed to the client.
                logger.exception("Vault write failed for secret '%s'", vault_key)
                return Response(
                    {"errors": {field_key: "secret store write failed"}},
                    status=status.HTTP_502_BAD_GATEWAY,
                )

        from settings.models import RuntimeConfig
        key = f"integrations.{name}"
        non_secret = _strip_secret_leaves(payload, schema)
        RuntimeConfig.objects.update_or_create(
            scope="backend", key=key, defaults={"value": non_secret}
        )
        invalidate_cache(key)
        # Mask from the schema, not SECRET_FIELDS, so no cleartext secret is
        # ever echoed in the response body.
        return Response({"config": _mask_secret_leaves(payload, schema)})


class ConnectorTestView(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrCERT]

    def post(self, request, name: str):
        if _connector_or_none(name) is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        try:
            health = registry.instantiate(name).health_check()
        except Exception as exc:  # noqa: BLE001 — surface as failed health
            from connectors.base import HealthStatus
            health = HealthStatus(ok=False, detail=str(exc))
        state = get_state(name)
        state.last_health_ok = health.ok
        state.last_health_detail = health.detail
        state.last_health_at = timezone.now()
        state.save(update_fields=[
            "last_health_ok", "last_health_detail", "last_health_at", "updated_at",
        ])
        return Response({"ok": health.ok, "detail": health.detail})


class ConnectorDeliveriesView(ListAPIView):
    permission_classes = [IsAuthenticated, IsAdminOrCERT]
    serializer_class = ConnectorDeliverySerializer
    pagination_class = LimitOffsetPagination

    def get_queryset(self):
        return ConnectorDelivery.objects.filter(
            connector=self.kwargs["name"]
        ).order_by("-created_at")
