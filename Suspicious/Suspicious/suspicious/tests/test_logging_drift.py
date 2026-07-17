import re
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

# Suspicious/Suspicious/ — the manage.py directory; app packages
# (case_handler, cortex_job, ...) are its direct children.
APPS_ROOT = Path(__file__).resolve().parent.parent.parent

_NAME_CALL = re.compile(r"getLogger\(__name__\)")
_LITERAL_CALL = re.compile(r'getLogger\(\s*["\']([^"\']+)["\']\s*\)')

_EXCLUDED_DIR_PARTS = {"tests", "migrations", "__pycache__", "node_modules"}
# manage_cron.py is a standalone ops script (calls logging.basicConfig
# itself) that is never imported as part of the running Django app — it's
# not wired into the Makefile, docker-compose, or any app package, so it
# manages its own logging independently of this LOGGING dict.
_EXCLUDED_FILENAMES = {"manage_cron.py"}


def _module_name_for(path: Path) -> str:
    rel = path.relative_to(APPS_ROOT).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _collect_logger_names() -> set[str]:
    names: set[str] = set()
    for path in APPS_ROOT.rglob("*.py"):
        rel_parts = path.relative_to(APPS_ROOT).parts
        if any(part in _EXCLUDED_DIR_PARTS for part in rel_parts[:-1]):
            continue
        filename = rel_parts[-1]
        if (
            filename in _EXCLUDED_FILENAMES
            or filename.startswith("test_")
            or filename == "tests.py"
        ):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if _NAME_CALL.search(text):
            names.add(_module_name_for(path))
        for match in _LITERAL_CALL.finditer(text):
            names.add(match.group(1))
    return names


def _has_configured_ancestor(name: str, configured: set[str]) -> bool:
    parts = name.split(".")
    for i in range(len(parts), 0, -1):
        if ".".join(parts[:i]) in configured:
            return True
    return False


class TestLoggerNamesResolveToConfiguredHandlers(SimpleTestCase):
    def test_every_logger_call_site_has_a_configured_ancestor(self):
        configured = set(settings.LOGGING["loggers"].keys())
        used_names = _collect_logger_names()
        orphaned = sorted(
            name
            for name in used_names
            if not _has_configured_ancestor(name, configured)
        )
        self.assertEqual(
            orphaned,
            [],
            "These logger names have no configured ancestor and would only "
            "ever reach the root safety net — add a dedicated entry in "
            f"settings.py's LOGGING dict: {orphaned}",
        )
