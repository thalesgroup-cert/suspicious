from pydantic import BaseModel, Field
from typing import Optional


class FileModel(BaseModel):
    """
    Represents a file to be processed.
    """
    file_path: str
    tmp_path: str
    linked_hash_id: Optional[int] = None
    file_score: Optional[int] = 0
    file_confidence: Optional[int] = 0
    file_level: Optional[str] = None


class HashModel(BaseModel):
    """
    Represents a file hash.
    """
    value: str
    ioc_score: Optional[int] = 0
    ioc_confidence: Optional[int] = 0
    ioc_level: Optional[str] = None
