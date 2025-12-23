import json
from pathlib import Path
from .models import MISPConfig, MISPSettings

CONFIG_PATH = Path("/app/settings.json")

def load_misp_settings() -> MISPSettings:
    with open(CONFIG_PATH) as f:
        config = json.load(f).get('misp', {})
    return MISPSettings(
        suspicious=MISPConfig(
            url=config['suspicious'].get('url', 'http://localhost:8880'),
            key=config['suspicious'].get('key', '')
        ),
        security=MISPConfig(
            url=config['security'].get('url', 'https://secondary-misp.example.com'),
            key=config['security'].get('key', '')
        ),
        tags=config.get('tags', {})
    )
