from pydantic import BaseModel, Field
from typing import Dict, Any


class AttachmentFileModel(BaseModel):
    """Represents a single attachment file with minimal required attributes."""
    name: str = Field(..., min_length=1)

    class Config:
        arbitrary_types_allowed = True  # for Django file objects


class AttachmentBatchModel(BaseModel):
    """Represents a batch of attachments to be processed."""
    files: Dict[str, Any]
