from pymisp import MISPEvent
from typing import Optional
from case_handler.models import Case
from datetime import datetime
import logging
import json
from .utils import parse_tags, current_month_event_name, first_day_of_month
CONFIG_PATH = "/app/settings.json"
with open(CONFIG_PATH) as config_file:
    config = json.load(config_file)

misp_config = config.get('misp', {})
logger = logging.getLogger(__name__)

class MISPEventManager:
    def __init__(self, misp):
        self.misp = misp

    def _find_event_by_name(self, event_name: str) -> Optional[str]:
        """
        Find a MISP event ID by its info field (event name).
        """
        try:
            results = self.misp.search(
                controller="events",
                value=event_name,
                metadata=True,
            )

            if not results:
                return None

            for event in results:
                info = event.get("Event", {}).get("info")
                if info == event_name:
                    return event["Event"]["id"]

            return None
        except Exception as e:
            logger.error(f"Error searching for event '{event_name}': {e}", exc_info=True)
            return None

    def get_or_create_event(self, case: Case) -> Optional[MISPEvent]:
        event_name = f"Email Analysis - Case {case.id}"
        try:
            event_id = self._find_event_by_name(event_name)
            if event_id:
                logger.info(f"Found existing event {event_id} for {event_name}")
                event_data = self.client.misp.get_event(event_id)
                self.add_case_number_attribute(event_data['Event'], case.id)
                event_obj = MISPEvent().load(event_data['Event'])
                detection_tag = self.get_detection_level_tag(case.results)
                if detection_tag:
                    event_obj.add_tag(detection_tag)
                self.client.misp.update_event(event_obj)
                return event_obj

            # Create new event
            event = MISPEvent()
            event.info = event_name
            event.date = datetime.now().strftime("%Y-%m-%d")
            event.distribution = 0
            event.threat_level_id = 3
            event.analysis = 1
            created_event = self.client.misp.add_event(event)
            if 'Event' in created_event and 'id' in created_event['Event']:
                self.add_case_number_attribute(created_event['Event'], case.id)
                event_obj = MISPEvent().load(created_event['Event'])
                detection_tag = self.get_detection_level_tag(case.results)
                if detection_tag:
                    event_obj.add_tag(detection_tag)
                self.client.misp.update_event(event_obj)
                return event_obj
            return None
        except Exception as e:
            logger.error(f"Error processing event for {event_name}: {e}", exc_info=True)
            return None

    def get_or_create_monthly_event(self) -> Optional[MISPEvent]:
        event_name = current_month_event_name()
        event_date = first_day_of_month()
        tags_config = misp_config.get('tags', {})

        try:
            event_id = self._find_event_by_name(event_name)
            if event_id:
                logger.info(f"Found existing monthly event {event_id} for {event_name}")
                event = self.client.misp.get_event(event_id, pythonify=True)
                if event:
                    tags = self.parse_tags(tags_config)
                    for tag in tags:
                        event.add_tag(tag["name"])
                    return self.client.misp.update_event(event, pythonify=True)
                return None

            # Create new monthly event
            event = MISPEvent()
            event.info = event_name
            event.date = event_date
            event.distribution = 3
            event.threat_level_id = 3
            event.analysis = 1

            tags = parse_tags(tags_config)
            for tag in tags:
                event.add_tag(tag["name"])

            created = self.client.misp.add_event(event, pythonify=True)
            return created
        except Exception as e:
            logger.error(f"Error creating or retrieving monthly event: {e}", exc_info=True)
            return None