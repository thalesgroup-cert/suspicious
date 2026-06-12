"""Harmonized client factories for tier-1 infrastructure services.

One construction path per backend service; config always comes from the
runtime-config accessors so Vault-overlaid secrets and DB overrides apply
uniformly. Factories raise on misconfiguration — call sites keep their own
try/except policy, as before."""
from __future__ import annotations

import os

from minio import Minio

from settings.config import get_section

# chromadb is imported lazily inside get_chroma_client() so that importing
# this module never triggers the heavy chromadb package load.  The module-level
# name is exposed so tests can patch "common.clients.chromadb" cleanly.
try:
    import chromadb  # type: ignore
except ImportError:  # pragma: no cover
    chromadb = None  # type: ignore[assignment]

_DEFAULT_CHROMA_HOST = "chromadb"
_DEFAULT_CHROMA_PORT = 8000


def get_s3_client() -> Minio:
    """MinIO/rustfs client from the shared ``storage.s3`` section."""
    cfg = get_section("storage.s3")
    return Minio(
        endpoint=cfg["endpoint"],
        access_key=cfg["access_key"],
        secret_key=cfg["secret_key"],
        secure=cfg.get("secure", False),
    )


def _disable_chromadb_telemetry() -> None:
    """Suppress ChromaDB telemetry via env vars and best-effort monkey-patching."""
    try:
        os.environ.setdefault("CHROMADB_TELEMETRY_ENABLED", "false")
        os.environ.setdefault("ANONYMIZED_TELEMETRY", "false")
        os.environ.setdefault("CHROMADB_DISABLE_TELEMETRY", "true")
        os.environ.setdefault("CHROMADB_TELEMETRY", "false")
    except Exception:
        pass

    try:
        from chromadb.telemetry import telemetry as _telemetry  # type: ignore

        if hasattr(_telemetry, "TELEMETRY_ENABLED"):
            try:
                _telemetry.TELEMETRY_ENABLED = False  # type: ignore[attr-defined]
            except Exception:
                pass

        inst = getattr(_telemetry, "telemetry_instance", None)
        if inst is not None:
            for attr in ("capture", "capture_event", "capture_span", "flush"):
                if hasattr(inst, attr):
                    setattr(inst, attr, lambda *a, **k: None)
    except Exception:
        pass

    try:
        from chromadb.telemetry import product as _product  # type: ignore

        posthog_mod = getattr(_product, "posthog", None)
        if posthog_mod is not None:
            def _noop_capture(*args, **kwargs):
                return None

            if hasattr(posthog_mod, "capture"):
                posthog_mod.capture = _noop_capture  # type: ignore[assignment]
            client_cls = getattr(posthog_mod, "Posthog", None)
            if client_cls is not None and hasattr(client_cls, "capture"):
                client_cls.capture = _noop_capture  # type: ignore[assignment]
    except Exception:
        pass


def get_chroma_client():
    """ChromaDB HTTP client from ``integrations.chromadb`` (telemetry off).

    Uses ``host`` and ``port`` from the ``integrations.chromadb`` config
    section, falling back to ``"chromadb"`` / ``8000``.  Telemetry is
    suppressed via environment variables and best-effort monkey-patching
    before the client is constructed.
    """
    cfg = get_section("integrations.chromadb")
    host = str(cfg.get("host", _DEFAULT_CHROMA_HOST))
    port = int(cfg.get("port", _DEFAULT_CHROMA_PORT))

    _disable_chromadb_telemetry()

    return chromadb.HttpClient(host=host, port=port)
