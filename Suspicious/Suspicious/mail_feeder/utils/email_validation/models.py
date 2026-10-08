from pydantic import BaseModel, EmailStr
from typing import List, Optional

class ConfigModel(BaseModel):
    company_domains: List[str]
    # The organisation's own domains: these and all their subdomains count as
    # company. The Watcher list stays exact-match (it holds third-party domains too).
    own_domains: List[str] = []

class EmailValidationResult(BaseModel):
    is_valid: bool
    normalized: Optional[EmailStr] = None
    error: Optional[str] = None
