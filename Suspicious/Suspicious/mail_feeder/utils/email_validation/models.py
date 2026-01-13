from pydantic import BaseModel, EmailStr
from typing import List, Optional, Tuple, Union

class ConfigModel(BaseModel):
    company_domains: List[str]

class EmailValidationResult(BaseModel):
    is_valid: bool
    normalized: Optional[EmailStr] = None
    error: Optional[str] = None
