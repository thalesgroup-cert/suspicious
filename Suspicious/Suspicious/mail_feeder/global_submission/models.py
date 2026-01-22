from pydantic import BaseModel, Field
from typing import List, Optional, Union


class ArtifactResult(BaseModel):
    ids: List[str] = Field(default_factory=list)
    ai_ids: List[str] = Field(default_factory=list)


class MailSubmissionData(BaseModel):
    workdir: str
    filename: str
    email_id: str
    bucket_name: Optional[str]
    user: Optional[str]
    is_submitted: bool
