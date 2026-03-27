import json
from pathlib import Path
from .models import MISPConfig, MISPSettings

CONFIG_PATH = Path("/app/settings.json")

def load_misp_settings() -> MISPSettings:
    with open(CONFIG_PATH) as f:
        config = json.load(f).get('integrations', {}).get('misp', {})
    return MISPSettings(
        suspicious=MISPConfig(
            url=config.get('instances', {}).get('primary', {}).get('url', 'http://localhost:8880'),
            key=config.get('instances', {}).get('primary', {}).get('api_key', '')
        ),
        security=MISPConfig(
            url=config.get('instances', {}).get('secondary', {}).get('url', 'https://secondary-misp.example.com'),
            key=config.get('instances', {}).get('secondary', {}).get('api_key', '')
        ),
        tags=config.get('default_tags', {})
    )
