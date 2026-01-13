from pydantic import BaseModel, EmailStr, Field, PositiveInt, ConfigDict
from typing import Optional, Any
from django.contrib.auth.models import User

class CaseInputData(BaseModel):
    """
    Pydantic model for validating case creation input data.
    """
    model_config = ConfigDict(arbitrary_types_allowed=True)
    instance: Optional[Any] = Field(
        None,
        description="The mail instance associated with the case."
    )
    user: User = Field(
        ...,
        description="Email of the user creating the case."
    )
    artifact_ids: list[str] = Field(
        default_factory=list,
        description="List of artifact IDs to be associated with the case."
    )
    attachment_ids: list[str] = Field(
        default_factory=list,
        description="List of attachment IDs to be associated with the case."
    )
    attachment_ids_ai: list[str] = Field(
        default_factory=list,
        description="List of AI-generated attachment IDs to be associated with the case."
    )
    list_ids: list[str] = Field(
        default_factory=list,
        description="Flattened list of all IDs (artifacts and attachments) for the case."
    )