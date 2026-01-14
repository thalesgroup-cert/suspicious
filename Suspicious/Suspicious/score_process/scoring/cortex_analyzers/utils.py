import re
from urllib.parse import urlparse
from domain_process.domain_utils.domain_handler import DomainHandler


def normalize_analyzer_name(name: str) -> str:
    return re.sub(r"_\d_\d", "", name).split("_")[0].lower()


def extract_domain(value: str) -> str | None:
    domain_type = DomainHandler().validate_domain(value)
    if domain_type == "Domain":
        return value
    if domain_type == "Url":
        return urlparse(value).netloc
    return None

def dump_model(model):
    if hasattr(model, "model_dump"):
        return model.model_dump(exclude_none=True)
    return model.dict()
