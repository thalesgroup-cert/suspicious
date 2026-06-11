# misp/events.py
"""
MISP event manager — get-or-create logic for case and monthly events.
"""
from __future__ import annotations
import logging
from datetime import datetime
from typing import Optional

from pymisp import MISPEvent

from case_handler.models import Case
from .client import MISPClient
from .config_loader import load_misp_settings
from .utils import (
    add_case_number_attribute,
    current_month_event_name,
    first_day_of_month,
    get_detection_level_tag,
    parse_tags,
)

logger = logging.getLogger(__name__)


class MISPEventManager:
    """
    Encapsulates get-or-create logic for MISP events.

    Receives a MISPClient so it does not reconnect on every call.
    """

    def __init__(self, client: MISPClient) -> None:
        self.client = client          # MISPClient wrapper
        self._misp  = client.misp     # ExpandedPyMISP instance — direct access

    # ── Internal helpers ──────────────────────────────────────────────────

    def _find_event_by_name(self, event_name: str) -> Optional[str]:
        """Return the MISP event ID whose info field equals event_name, or None."""
        try:
            results = self._misp.search(
                controller="events",
                value=event_name,
                metadata=True,
            )
            if not results:
                return None
            for event in results:
                if event.get("Event", {}).get("info") == event_name:
                    return event["Event"]["id"]
            return None
        except Exception as exc:
            logger.error("Error searching for MISP event %r: %s", event_name, exc, exc_info=True)
            return None

    # ── Public API ────────────────────────────────────────────────────────

    def get_or_create_event(self, case: Case) -> Optional[MISPEvent]:
        event_name = "Email Analysis - Case %s" % str(case.id)
        try:
            event_id = self._find_event_by_name(event_name)

            if event_id:
                logger.info("Found existing MISP event %s for %r.", event_id, event_name)
                event_data = self._misp.get_event(event_id)
                # add_case_number_attribute is a module-level function
                add_case_number_attribute(self._misp, event_data["Event"]["id"], case.id)
                event_obj = MISPEvent().load(event_data["Event"])
                # get_detection_level_tag is a module-level function
                tag = get_detection_level_tag(case.results or "")
                if tag:
                    event_obj.add_tag(tag)
                self._misp.update_event(event_obj)
                return event_obj

            # Create a new event
            event                 = MISPEvent()
            event.info            = event_name
            event.date            = datetime.now().strftime("%Y-%m-%d")
            event.distribution    = 0
            event.threat_level_id = 3
            event.analysis        = 1

            created = self._misp.add_event(event)
            if "Event" in created and "id" in created["Event"]:
                add_case_number_attribute(self._misp, created["Event"]["id"], case.id)
                event_obj = MISPEvent().load(created["Event"])
                tag = get_detection_level_tag(case.results or "")
                if tag:
                    event_obj.add_tag(tag)
                self._misp.update_event(event_obj)
                return event_obj

            logger.warning("add_event returned unexpected structure for %r.", event_name)
            return None

        except Exception as exc:
            logger.error("Error processing MISP event for %r: %s", event_name, exc, exc_info=True)
            return None

    def get_or_create_monthly_event(self) -> Optional[MISPEvent]:
        event_name  = current_month_event_name()
        event_date  = first_day_of_month()
        # Load lazily — not from a module-level global
        tags_config = load_misp_settings().tags or {}

        try:
            event_id = self._find_event_by_name(event_name)

            if event_id:
                logger.info("Found existing monthly MISP event %s for %r.", event_id, event_name)
                # pythonify=True returns a MISPEvent object
                event = self._misp.get_event(event_id, pythonify=True)
                if event:
                    # parse_tags is a module-level function, not self.parse_tags
                    for tag in parse_tags(tags_config):
                        event.add_tag(tag["name"])
                    return self._misp.update_event(event, pythonify=True)
                return None

            # Create a new monthly event
            event                 = MISPEvent()
            event.info            = event_name
            event.date            = event_date
            event.distribution    = 3
            event.threat_level_id = 3
            event.analysis        = 1

            for tag in parse_tags(tags_config):
                event.add_tag(tag["name"])

            return self._misp.add_event(event, pythonify=True)

        except Exception as exc:
            logger.error("Error in get_or_create_monthly_event for %r: %s", event_name, exc, exc_info=True)
            return None