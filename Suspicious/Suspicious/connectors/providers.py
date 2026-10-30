"""Analysis-provider slot: resolve which connector supplies a kind of analysis."""
from __future__ import annotations

from connectors.registry import registry


def enabled_provider(kind: str) -> str | None:
    """Name of the enabled connector providing ``kind``, or None. At most one
    can be enabled (the connector state API refuses a second)."""
    from connectors.delivery import get_state  # lazy: delivery imports the registry too

    return next(
        (name for name in registry.providers(kind) if get_state(name).enabled), None
    )
