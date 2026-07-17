import logging
from models import CortexJobConfig

fetch_mail_logger = logging.getLogger("tasp.cron.fetch_and_process_emails")

def load_config(config_path: str = None) -> CortexJobConfig:
    """Cortex config via the runtime accessor (url/analyzers from DB,
    api_key from Vault). config_path retained for signature compatibility."""
    from settings.config import get_section
    try:
        cortex = get_section("integrations.cortex")
        return CortexJobConfig(
            url=cortex.get("url", ""),
            api_key=cortex.get("api_key", ""),
            proxies=cortex.get("proxies", {}),
        )
    except Exception as e:
        fetch_mail_logger.error(f"Could not load cortex config: {e}")
        return CortexJobConfig(url="", api_key="", proxies={})
