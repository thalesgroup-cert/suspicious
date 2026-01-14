import logging
from django.db import transaction
from cortex4py.api import Api
from cortex4py.exceptions import CortexException
from .utils import load_config
from .models import CronConfig
from cortex_job.models import Analyzer

logger = logging.getLogger("cron.sync_cortex")
log_analyzers = logging.getLogger("tasp.cron.fetch_analyzer")
CONFIG_PATH = "/app/settings.json"


def sync_cortex_analyzers(config_path: str = CONFIG_PATH) -> None:
    cfg: CronConfig = load_config(config_path)
    if not cfg.cortex:
        log_analyzers.error("Missing Cortex config")
        return

    api = Api(str(cfg.cortex.url), cfg.cortex.api_key)
    try:
        remote_analyzers = api.analyzers.find_all({}, range="all")
    except CortexException as exc:
        log_analyzers.error("Cortex fetch failed: %s", exc)
        return

    if not remote_analyzers:
        return

    remote_names = []
    with transaction.atomic():
        for analyzer in remote_analyzers:
            Analyzer.objects.update_or_create(
                name=analyzer.name,
                defaults={"analyzer_cortex_id": analyzer.id, "is_active": True},
            )
            remote_names.append(analyzer.name)
        Analyzer.objects.exclude(name__in=remote_names).update(is_active=False)
