from pydantic import BaseModel, Field, constr


class WebSubmissionConfig(BaseModel):
    """
    Configuration for web-submitted email processing.
    """
    workdir: constr(min_length=1) = Field(..., description="Directory containing submitted email files")
    user_email: constr(min_length=5) = Field(..., description="Email address of the user submitting the emails")
