# email_processing/utils.py
import uuid
import hashlib
import re
import logging
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import Optional, Union

logger = logging.getLogger(__name__)

def get_sha256(file_path: Union[str, Path]) -> Optional[str]:
    """
    Compute SHA‑256 checksum in 8 KiB reading blocks.
    Returns hex digest or None if file is missing.
    """
    try:
        hasher = hashlib.sha256()
        with Path(file_path).open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        logger.error("File not found: %s", file_path)
        return None

def sanitize_filename(filename: str, id_num: int, default_base: str = "attachment") -> str:
    """
    Sanitize a filename for safe filesystem usage:
    - Replace non-alphanumeric/included punctuation with "_"
    - Collapse spaces and underscores into single underscore
    - Limit name length (~200 chars total including extension)
    """
    filename = filename.strip() or f"{default_base}_{id_num}"
    sanitized = re.sub(r"[^\w\s\.-]", "_", filename)
    sanitized = re.sub(r"[\s_]+", "_", sanitized).strip("_")

    if not sanitized:
        sanitized = f"{default_base}_{id_num}"

    name, ext = Path(sanitized).stem, Path(sanitized).suffix
    max_name_len = 200 - len(ext)
    return name[:max_name_len] + ext

def header_dict_list(msg_part) -> dict:
    """
    Return a mapping of header keys to list of values for a message part.
    """
    d = defaultdict(list)
    for k, v in msg_part.items():
        d[k].append(v)
    return d

def generate_object_reference() -> str:
    """
    Generate unique reference like 'YYMMDDHHMMSS-xxxxxxxxxxxx':
    timestamp + 12‑hex UUID.
    """
    timestamp = datetime.now().strftime("%y%m%d%H%M%S")
    uuid_part = uuid.uuid4().hex[:12]
    return f"{timestamp}-{uuid_part}"

def cleanup_directory(dir_path: Union[str, Path], remove_parent_if_empty: bool = False):
    """
    Recursively delete a directory. Optionally delete its parent if it becomes empty.
    """
    p = Path(dir_path)
    if not p.exists():
        logger.warning("Directory not found for cleanup: %s", p)
        return

    try:
        for child in p.iterdir():
            if child.is_dir():
                cleanup_directory(child, remove_parent_if_empty=False)
            else:
                child.unlink()
        p.rmdir()
        logger.info("Removed directory: %s", p)
        if remove_parent_if_empty and p.parent.exists() and not any(p.parent.iterdir()):
            p.parent.rmdir()
            logger.info("Removed empty parent directory: %s", p.parent)
    except Exception as e:
        logger.error("Error during cleanup of '%s': %s", p, e)

def decode_header_str(header_value: Optional[str]) -> str:
    """
    Decode MIME encoded-word header values (RFC2047), preserving unicode.
    """
    if not header_value:
        return ""
    parts = []
    for decoded, charset in __import__('email').header.decode_header(header_value):
        if isinstance(decoded, bytes):
            try:
                parts.append(decoded.decode(charset or "utf-8", errors="replace"))
            except LookupError:
                parts.append(decoded.decode("latin-1", errors="replace"))
        else:
            parts.append(decoded)
    return "".join(parts)
