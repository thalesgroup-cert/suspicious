"""
This module provides different interfaces allowing the parsing of Minio configs
from a JSON object.
"""

import pydantic


class MinioConfig(pydantic.BaseModel):
    endpoint: str
    """Minio's server endpoint. (format: host:port)"""

    access_key: str
    """The access key for Minio authentication. It can also be the username."""

    secret_key: str
    """The secret key for Minio authentication. It can also be the password."""

    secure: bool = pydantic.Field(default=False)
    """Whether to secure the communication."""

    feeder_bucket: str = pydantic.Field(default="")
    """Single bucket for the portable prefix contract. Empty => legacy
    bucket-per-submission mode."""
