from pydantic import BaseModel, Field

class TextInputModel(BaseModel):
    """
    Pydantic model for validating input text to hash or compare.
    """
    text: str = Field(..., min_length=1, description="Text input to be hashed or processed")
