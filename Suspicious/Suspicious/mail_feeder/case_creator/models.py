from pydantic import BaseModel, EmailStr, Field, PositiveInt
from typing import Optional, Any


class CaseInputData(BaseModel):
    """
    Pydantic model for validating case creation input data.
    """

    instance: Optional[Any] = Field(
        None,
        description="The mail instance associated with the case."
    )
    user: EmailStr = Field(
        ...,
        description="Email of the user creating the case."
    )
    artifact_ids: list[PositiveInt] = Field(
        default_factory=list,
        description="List of artifact IDs to be associated with the case."
    )
    attachment_ids: list[list[PositiveInt]] = Field(
        default_factory=list,
        description="List of lists of attachment IDs to be associated with the case."
    )
    attachment_ids_ai: list[PositiveInt] = Field(
        default_factory=list,
        description="List of AI-generated attachment IDs to be associated with the case."
    )
    list_ids: list[PositiveInt] = Field(
        default_factory=list,
        description="Flattened list of all IDs (artifacts and attachments) for the case."
    )