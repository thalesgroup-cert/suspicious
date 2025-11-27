from pydantic import BaseModel, conint
import logging

logger = logging.getLogger("kpi_updating")

class Period(BaseModel):
    month: conint(ge=1, le=12)
    year: conint(ge=2000, le=2100)


def safe_get_or_create(model, defaults=None, **lookup):
    """
    Wrapper around Django's get_or_create with error handling.
    """
    try:
        instance, created = model.objects.get_or_create(defaults=defaults or {}, **lookup)
        return instance, created
    except Exception as e:
        logger.error(f"Error in safe_get_or_create for {model.__name__}: {e}")
        raise
