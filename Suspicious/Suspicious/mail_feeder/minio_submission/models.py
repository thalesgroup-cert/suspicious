from pydantic import BaseModel, Field
from typing import Optional


class MinioEmailData(BaseModel):
    """
    Represents metadata required to process a MinIO email.
    """
    workdir: str = Field(..., description="Path to the email directory in MinIO")
    email_id: str = Field(..., description="Unique identifier for the email session")
