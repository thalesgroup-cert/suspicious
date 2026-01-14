from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, List, Union
from datetime import datetime


class MailBody(BaseModel):
    fuzzy_hash: str
    body_value: str


class MailHeader(BaseModel):
    header_value: str


class Analyzer(BaseModel):
    id: str
    name: str
    weight: float


class AnalyzerReport(BaseModel):
    cortex_job_id: str
    type: str
    analyzer: Analyzer
    level: str
    confidence: int
    score: int
    report_summary: dict
    report_full: dict
    report_taxonomy: dict


class CortexJobData(BaseModel):
    data_type: str
    value: Union[str, dict, None]  # Could be file, URL, etc.
    data_value: str


class CortexJobConfig(BaseModel):
    url: str
    api_key: str
    proxies: dict


class CortexJobRequest(BaseModel):
    api_url: Optional[str] = None
    api_key: Optional[str] = None
    proxies: Optional[dict] = None
