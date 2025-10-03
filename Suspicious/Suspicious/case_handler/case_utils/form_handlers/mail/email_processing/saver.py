import logging
from pathlib import Path
from typing import Optional, Union
from email.message import EmailMessage

logger = logging.getLogger(__name__)


class EmailSaver:
    """
    Responsible for saving parsed email components to disk:
    - original EML content
    - plain text body
    - HTML body
    - headers snapshot
    """

    def __init__(self, dest_dir: Union[str, Path]):
        """
        Initialize the saver for a specific directory.
        Ensures the directory exists.

        Args:
            dest_dir (str | Path): Target directory to save files.
        """
        self.dest_dir = Path(dest_dir)
        try:
            self.dest_dir.mkdir(parents=True, exist_ok=True)
            logger.debug("EmailSaver directory created: %s", self.dest_dir)
        except Exception as e:
            logger.error("Cannot create directory %s: %s", self.dest_dir, e)
            raise

    def save(self,
        ref: str,
        *,
        body_text: Optional[str] = None,
        body_html: Optional[str] = None,
        headers: Optional[Union[str, EmailMessage]] = None,
        eml_bytes: Optional[bytes] = None) -> None:
        """
        Save the various pieces of an email:

        - {ref}.eml  : raw email bytes
        - {ref}.html : HTML body (if provided)
        - {ref}.txt  : plain-text body
        - {ref}.headers: headers snapshot (string form)

        Args:
            ref (str): Identifier for file naming.
            body_text (str, optional): Plain text content.
            body_html (str, optional): HTML content.
            headers (str | EmailMessage, optional): Email headers.
            eml_bytes (bytes, optional): Raw .eml bytes.
        """
        try:
            if eml_bytes:
                self._save_bytes(f"{ref}.eml", eml_bytes)

            if body_html is not None:
                self._save_text(f"{ref}.html", body_html)

            if body_text is not None:
                self._save_text(f"{ref}.txt", body_text)

            if headers is not None:
                headers_str = headers.as_string() if hasattr(headers, "as_string") else str(headers)
                self._save_text(f"{ref}.headers", headers_str)

        except Exception as e:
            logger.error("Failed to save email parts for '%s': %s", ref, e, exc_info=True)

    def _save_text(self, filename: str, content: str) -> None:
        path = self.dest_dir / filename
        try:
            path.write_text(content, encoding="utf-8", errors="replace")
            logger.debug("Saved text file: %s", path)
        except Exception as e:
            logger.error("Error writing text file %s: %s", path, e)

    def _save_bytes(self, filename: str, content: bytes) -> None:
        path = self.dest_dir / filename
        try:
            path.write_bytes(content)
            logger.debug("Saved binary file: %s", path)
        except Exception as e:
            logger.error("Error writing binary file %s: %s", path, e)
