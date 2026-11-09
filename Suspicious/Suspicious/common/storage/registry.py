import os
import threading
from typing import Callable

from .base import ObjectStore
from .s3 import S3Store

DEFAULT_PROVIDER = "s3"

Factory = Callable[[dict, bool], ObjectStore]


class StorageConfigError(Exception):
    pass


_providers: dict[str, Factory] = {}
_stores: dict[bool, ObjectStore] = {}
_lock = threading.Lock()


def register_provider(name: str, factory: Factory) -> None:
    _providers[name] = factory


def known_providers() -> list[str]:
    return sorted(_providers)


def check_provider_name(name: str) -> None:
    if name not in _providers:
        raise StorageConfigError(
            f"Unknown storage provider {name!r}; registered providers: {', '.join(known_providers())}"
        )


def configured_provider_name() -> str:
    from settings.config import get_config

    try:
        name = get_config("storage.provider", None)
    except Exception:
        name = None
    return str(name or os.environ.get("STORAGE_PROVIDER") or DEFAULT_PROVIDER).strip().lower()


def _build(presign: bool) -> ObjectStore:
    from settings.config import get_section

    name = configured_provider_name()
    check_provider_name(name)
    return _providers[name](get_section(f"storage.{name}"), presign)


def _get(presign: bool) -> ObjectStore:
    store = _stores.get(presign)
    if store is None:
        with _lock:
            store = _stores.get(presign)
            if store is None:
                store = _stores[presign] = _build(presign)
    return store


def get_store() -> ObjectStore:
    return _get(False)


def get_presign_store() -> ObjectStore:
    return _get(True)


def reset_store_cache() -> None:
    with _lock:
        _stores.clear()


register_provider("s3", lambda cfg, presign: S3Store.from_config(cfg, presign=presign))


def _gcs(cfg: dict, presign: bool) -> ObjectStore:
    from .gcs import GcsStore

    return GcsStore.from_config(cfg, presign=presign)


register_provider("gcs", _gcs)
