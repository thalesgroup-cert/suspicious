from pydantic import BaseModel, Field
from typing import Optional


class ArtifactModel(BaseModel):
    """
    Pydantic model for validating artifact input.
    """
    artifact_type: str = Field(..., description="Type of the artifact (IP, Hash, URL, Domain, MailAddress)")
    id: Optional[int] = Field(None, description="Optional artifact database ID")
