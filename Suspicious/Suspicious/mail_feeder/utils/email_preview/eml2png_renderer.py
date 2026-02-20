from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Optional

from django.core.files.base import ContentFile

logger = logging.getLogger(__name__)


class Eml2PngRenderer:
    """
    Renders an .eml file to a PNG using the `eml2png` CLI.
    Requires: eml2png + wkhtmltopdf installed in the runtime image.
    """

    def __init__(self, cli: str = "eml2png"):
        self.cli = cli

    def render_eml_path_to_png_bytes(self, eml_path: Path) -> Optional[bytes]:
        if not eml_path.exists():
            logger.warning("EML file not found: %s", eml_path)
            return None

        # eml2png works via output file
        out_path = eml_path.with_suffix(".preview.png")

        try:
            subprocess.run(
                [self.cli, str(eml_path), "-o", str(out_path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError:
            logger.error("eml2png CLI not found (is it installed in the container?)")
            return None
        except subprocess.CalledProcessError as e:
            logger.error("eml2png failed: %s", e.stderr.decode(errors="replace"))
            return None

        try:
            data = out_path.read_bytes()
        except OSError as e:
            logger.error("Cannot read rendered PNG: %s", e)
            return None
        finally:
            # best-effort cleanup
            try:
                out_path.unlink(missing_ok=True)  # Python 3.8+: missing_ok exists
            except Exception:
                pass

        return data

    def save_preview_to_mail(self, mail, png_bytes: bytes) -> None:
        # Storage-aware: uses DEFAULT_FILE_STORAGE (local/MinIO/dual)
        mail.preview_png.save("preview.png", ContentFile(png_bytes), save=False)
        mail.save(update_fields=["preview_png"])
