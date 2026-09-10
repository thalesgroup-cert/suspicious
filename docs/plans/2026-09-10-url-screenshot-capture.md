# URL Screenshot Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist the page screenshot produced by a Cortex screenshot analyzer (`Lookyloo_Screenshot`, `Urlscan.io_Scan`) and show it on the IOC-road and mail-road investigation views and in the downloadable HTML report.

**Architecture:** A new `score_process/scoring/screenshots/` package mirrors the existing `enrichment/` one — a registry dispatches an `AnalyzerReport` to a per-analyzer extractor that returns PNG bytes (base64-decoded from `report_full`, or fetched once from `urlscan.io`). `_save_report` calls it right after `enrich()`, stores the bytes in a MinIO bucket, and stamps `(bucket, key)` on the report — exactly the shape of the eml→png mail-preview path. A dedicated view streams the image; serializers expose a URL; the HTML report inlines it as a data URI. No app-side capture, no scoring change.

**Tech Stack:** Django 6.1, Python 3.12, DRF, `minio` client, `requests`. Frontend: React 19 + TypeScript + Vite + MUI v9 + TanStack Query v5 + Zod. Vitest.

**Spec:** `docs/specs/2026-09-10-url-screenshot-capture-design.md`

## Global Constraints

- **No new runtime dependency.** `minio` and `requests` are already in `Suspicious/requirements*.txt`; add nothing.
- **No app-side / headless capture.** Screenshots come only from Cortex analyzer reports.
- **Do not change** scoring, the categorical verdict engine, `mail_band_escalation`, the Cortex webhook, `dispatch_pending`, `CaseAnalyzerJob`, or `finalise_case`.
- **Additive migration only.** New blank fields on `AnalyzerReport`; no data migration. Next `cortex_job` migration number is **`0015`** (head: `0014_derivedobservable`).
- Screenshot capture/store failures must never break report scoring — isolate in their own `try/except`.
- 8 MB per-image cap on capture; 6 MB total-embedded cap in the HTML report.
- Conventional Commits. Commit after every task with explicit `git add <paths>` — never `git add -A`.
- Tests run through **`ww test`** (`~/.local/bin/ww-test`), never an ad-hoc `docker compose run` string. Backend tasks end with the `cortex_job` / `score_process` / `api` suites green; frontend tasks end with `pnpm test` green and `pnpm lint` clean.
- After a containerised backend test run, remove the stray root-owned `Suspicious/Suspicious/gunicorn.conf.py` before committing.
- Django project lives at `Suspicious/Suspicious/` (nested); all `manage.py` paths in this plan are relative to there.
- `python manage.py backtest_scoring` must show zero verdict drift (regression guard — this feature touches no scoring path).
- Frontend: follow `suspicious-ui/src` patterns — TanStack Query for server state, Zod schemas in `features/*/`, MUI components, no new state libraries.

---

## File Structure

### Backend

| File | Responsibility |
|---|---|
| `cortex_job/models.py` | `AnalyzerReport.screenshot_bucket`, `.screenshot_key` |
| `cortex_job/migrations/00NN_analyzerreport_screenshot.py` | schema |
| `common/clients.py` | `ensure_bucket(client, name)` helper (shared with eml2png) |
| `score_process/scoring/screenshots/__init__.py` | package marker |
| `score_process/scoring/screenshots/registry.py` | `capture(report)`, `store(report, png)` |
| `score_process/scoring/screenshots/lookyloo.py` | `extract(report_full, data_type, value) -> bytes \| None` |
| `score_process/scoring/screenshots/urlscan.py` | `extract(report_full, data_type, value) -> bytes \| None` |
| `score_process/scoring/cortex_analyzers/reports.py` | call `capture` + `store` in `_save_report` |
| `api/views/case_screenshot.py` | **new** — `GET /api/cases/<id>/screenshot.png` |
| `api/urls.py` | route `cases/<int:case_id>/screenshot.png` |
| `api/serializers/investigations.py` | `screenshot_url` on `CaseInvestigationSerializer` |
| `api/utils/observable_report.py` | per-observable `screenshot_url` in `assemble_observables` |
| `api/views/case_report.py` | inline screenshots as data URIs |
| `templates/case_report/report.html` | `<img>` per observable |
| `score_process/management/commands/backfill_screenshots.py` | **new** — backfill historical reports |
| `deployment/scripts/enable-dev-analyzers.sh` | enable `Lookyloo_Screenshot` |
| `docs/specs/2026-09-02-analyzer-classification.md` | add both analyzers to bucket ② |

### Frontend

| File | Responsibility |
|---|---|
| `suspicious-ui/src/shared/components/ScreenshotPanel.tsx` | **new** — lazy `<img>` + skeleton + fallback |
| `suspicious-ui/src/features/investigation/*` (schema file) | `screenshot_url` in the Zod schemas |
| `suspicious-ui/src/pages/InvestigationPage.tsx` (or the IOC/mail layout components) | render `ScreenshotPanel` on both roads |

---

## Task 1: `AnalyzerReport` screenshot fields + migration

**Files:**
- Modify: `cortex_job/models.py` (class `AnalyzerReport`, after the `enrichment` field ~line 60)
- Create: `cortex_job/migrations/00NN_analyzerreport_screenshot.py` (via `makemigrations`)
- Test: `cortex_job/tests/test_analyzerreport_screenshot_fields.py`

**Interfaces:**
- Produces: `AnalyzerReport.screenshot_bucket: str` (blank default `""`), `AnalyzerReport.screenshot_key: str` (blank default `""`, `db_index=True`)

- [ ] **Step 1: Write the failing test**

```python
# cortex_job/tests/test_analyzerreport_screenshot_fields.py
from django.test import TestCase
from cortex_job.models import Analyzer, AnalyzerReport


class ScreenshotFieldsTest(TestCase):
    def test_fields_default_blank(self):
        a = Analyzer.objects.create(name="Lookyloo_Screenshot", version="1.0")
        r = AnalyzerReport.objects.create(
            cortex_job_id="j1", type="url", status="Success", analyzer=a,
            level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={},
        )
        r.refresh_from_db()
        self.assertEqual(r.screenshot_bucket, "")
        self.assertEqual(r.screenshot_key, "")

    def test_screenshot_key_indexed(self):
        field = AnalyzerReport._meta.get_field("screenshot_key")
        self.assertTrue(field.db_index)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test cortex_job.tests.test_analyzerreport_screenshot_fields -v 2`
Expected: FAIL — `FieldDoesNotExist: AnalyzerReport has no field named 'screenshot_bucket'`

- [ ] **Step 3: Add the fields**

```python
# cortex_job/models.py — in AnalyzerReport, right after the `enrichment` field
    # (bucket, key) of the page screenshot captured by a screenshot analyzer
    # (Lookyloo_Screenshot / Urlscan.io_Scan) and stored in MinIO by
    # score_process.scoring.screenshots. Blank = none captured. Mirrors
    # Mail.preview_bucket / Mail.preview_object_key.
    screenshot_bucket = models.CharField(max_length=255, blank=True, default="")
    screenshot_key = models.CharField(max_length=512, blank=True, default="", db_index=True)
```

- [ ] **Step 4: Make the migration and run tests**

Run: `python manage.py makemigrations cortex_job` then `python manage.py test cortex_job.tests.test_analyzerreport_screenshot_fields -v 2`
Expected: migration `00NN_analyzerreport_screenshot.py` created; tests PASS

- [ ] **Step 5: Commit**

```bash
git add cortex_job/models.py cortex_job/migrations/ cortex_job/tests/test_analyzerreport_screenshot_fields.py
git commit -m "feat(cortex_job): AnalyzerReport screenshot bucket/key fields"
```

---

## Task 2: `ensure_bucket` helper in `common/clients.py`

**Files:**
- Modify: `common/clients.py` (add `ensure_bucket`)
- Modify: `mail_feeder/utils/email_preview/eml2png_renderer.py` (`_ensure_bucket` delegates to the new helper)
- Test: `common/tests/test_ensure_bucket.py` (create `common/tests/__init__.py` if absent)

**Interfaces:**
- Produces: `common.clients.ensure_bucket(client, name: str) -> None` — creates the bucket if `client.bucket_exists(name)` is false; no-op otherwise.

- [ ] **Step 1: Write the failing test**

```python
# common/tests/test_ensure_bucket.py
from unittest.mock import MagicMock
from django.test import SimpleTestCase
from common.clients import ensure_bucket


class EnsureBucketTest(SimpleTestCase):
    def test_creates_when_missing(self):
        client = MagicMock()
        client.bucket_exists.return_value = False
        ensure_bucket(client, "shots")
        client.make_bucket.assert_called_once_with("shots")

    def test_noop_when_present(self):
        client = MagicMock()
        client.bucket_exists.return_value = True
        ensure_bucket(client, "shots")
        client.make_bucket.assert_not_called()
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test common.tests.test_ensure_bucket -v 2`
Expected: FAIL — `ImportError: cannot import name 'ensure_bucket'`

- [ ] **Step 3: Implement**

```python
# common/clients.py — module level
def ensure_bucket(client, name: str) -> None:
    """Create the MinIO bucket if it does not exist yet. Idempotent."""
    if not client.bucket_exists(name):
        client.make_bucket(name)
```

Then in `mail_feeder/utils/email_preview/eml2png_renderer.py`, replace the body of the existing `_ensure_bucket` with a call to `from common.clients import ensure_bucket; ensure_bucket(client, bucket)` (keep the existing function name/signature so its callers are untouched).

- [ ] **Step 4: Run tests**

Run: `python manage.py test common.tests.test_ensure_bucket mail_feeder -v 2`
Expected: PASS (mail_feeder preview tests still green)

- [ ] **Step 5: Commit**

```bash
git add common/clients.py common/tests/ mail_feeder/utils/email_preview/eml2png_renderer.py
git commit -m "refactor(common): shared ensure_bucket helper"
```

---

## Task 3: `screenshots/lookyloo.py` extractor

**Files:**
- Create: `score_process/scoring/screenshots/__init__.py` (empty)
- Create: `score_process/scoring/screenshots/lookyloo.py`
- Test: `score_process/tests/test_screenshots_lookyloo.py`

**Interfaces:**
- Produces: `score_process.scoring.screenshots.lookyloo.extract(report_full: Any, data_type: str, value: str | None) -> bytes | None`
- Consumes: `score_process.scoring.screenshots._MAX_BYTES` — no; keep the cap local as `_MAX_BYTES = 8 * 1024 * 1024` in this module and re-use via import in Task 4.

**Notes:** the Cortex `Lookyloo_Screenshot` analyzer base64-encodes the PNG into its `full` report. Suspicious may wrap `full` under a `results` key (see `enrichment/virustotal.py::_attributes`). Check both `report_full["screenshot"]` and `report_full["results"]["screenshot"]`, plus the fallback key `"raw"`. Validate the PNG magic bytes (`\x89PNG\r\n\x1a\n`). A real capture should be diffed against this once Lookyloo is enabled in dev (Task 11 backfill is the opportunity).

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_screenshots_lookyloo.py
import base64
from django.test import SimpleTestCase
from score_process.scoring.screenshots import lookyloo

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
B64 = base64.b64encode(PNG).decode()


class LookylooExtractTest(SimpleTestCase):
    def test_top_level_key(self):
        self.assertEqual(lookyloo.extract({"screenshot": B64}, "url", "http://x"), PNG)

    def test_wrapped_in_results(self):
        self.assertEqual(lookyloo.extract({"results": {"screenshot": B64}}, "url", "http://x"), PNG)

    def test_missing_key_returns_none(self):
        self.assertIsNone(lookyloo.extract({"lookyloo_url": "http://l/tree/1"}, "url", "http://x"))

    def test_not_a_png_returns_none(self):
        bad = base64.b64encode(b"<html>nope").decode()
        self.assertIsNone(lookyloo.extract({"screenshot": bad}, "url", "http://x"))

    def test_oversized_returns_none(self):
        big = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * (9 * 1024 * 1024)).decode()
        self.assertIsNone(lookyloo.extract({"screenshot": big}, "url", "http://x"))

    def test_non_dict_returns_none(self):
        self.assertIsNone(lookyloo.extract("boom", "url", "http://x"))
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test score_process.tests.test_screenshots_lookyloo -v 2`
Expected: FAIL — `ModuleNotFoundError: score_process.scoring.screenshots`

- [ ] **Step 3: Implement**

```python
# score_process/scoring/screenshots/lookyloo.py
"""Extract the page screenshot from a Lookyloo_Screenshot report_full.
Pure dict -> bytes; no ORM, no network. None when there is no usable PNG."""
from __future__ import annotations

import base64
import binascii
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

_MAX_BYTES = 8 * 1024 * 1024
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_KEYS = ("screenshot", "raw")


def _b64_field(report_full: Any) -> Optional[str]:
    if not isinstance(report_full, dict):
        return None
    for container in (report_full, report_full.get("results")):
        if isinstance(container, dict):
            for k in _KEYS:
                v = container.get(k)
                if isinstance(v, str) and v:
                    return v
    return None


def extract(report_full: Any, data_type: str, value: Optional[str]) -> Optional[bytes]:
    b64 = _b64_field(report_full)
    if not b64:
        return None
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        logger.warning("lookyloo screenshot: bad base64")
        return None
    if len(raw) > _MAX_BYTES or not raw.startswith(_PNG_MAGIC):
        logger.warning("lookyloo screenshot: oversized or not a PNG (%d bytes)", len(raw))
        return None
    return raw
```

- [ ] **Step 4: Run tests**

Run: `python manage.py test score_process.tests.test_screenshots_lookyloo -v 2`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add score_process/scoring/screenshots/ score_process/tests/test_screenshots_lookyloo.py
git commit -m "feat(screenshots): Lookyloo_Screenshot PNG extractor"
```

---

## Task 4: `screenshots/urlscan.py` extractor

**Files:**
- Create: `score_process/scoring/screenshots/urlscan.py`
- Test: `score_process/tests/test_screenshots_urlscan.py`

**Interfaces:**
- Produces: `score_process.scoring.screenshots.urlscan.extract(report_full: Any, data_type: str, value: str | None) -> bytes | None`
- Consumes: `score_process.scoring.screenshots.lookyloo._MAX_BYTES`, `_PNG_MAGIC`

**Notes:** `Urlscan.io_Scan` puts the screenshot URL in `report_full` — check `report_full["task"]["screenshotURL"]`, `report_full["screenshot"]`, and `report_full["results"]["task"]["screenshotURL"]`. Fetch it once with `requests.get(url, timeout=10, stream=True)`, cap the read at `_MAX_BYTES`, only accept an `https://urlscan.io/` (or `https://*.urlscan.io/`) host.

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_screenshots_urlscan.py
from unittest.mock import patch, MagicMock
from django.test import SimpleTestCase
from score_process.scoring.screenshots import urlscan

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


def _resp(content=PNG, status=200):
    m = MagicMock(status_code=status)
    m.iter_content.return_value = [content]
    m.raise_for_status.side_effect = None if status == 200 else Exception("http %d" % status)
    return m


class UrlscanExtractTest(SimpleTestCase):
    @patch("score_process.scoring.screenshots.urlscan.requests.get")
    def test_task_screenshot_url(self, get):
        get.return_value = _resp()
        full = {"task": {"screenshotURL": "https://urlscan.io/screenshots/abc.png"}}
        self.assertEqual(urlscan.extract(full, "url", "http://x"), PNG)

    @patch("score_process.scoring.screenshots.urlscan.requests.get")
    def test_wrapped_in_results(self, get):
        get.return_value = _resp()
        full = {"results": {"task": {"screenshotURL": "https://urlscan.io/screenshots/abc.png"}}}
        self.assertEqual(urlscan.extract(full, "url", "http://x"), PNG)

    def test_no_url_returns_none(self):
        self.assertIsNone(urlscan.extract({"task": {}}, "url", "http://x"))

    def test_non_urlscan_host_rejected(self):
        full = {"task": {"screenshotURL": "https://evil.example/x.png"}}
        self.assertIsNone(urlscan.extract(full, "url", "http://x"))

    @patch("score_process.scoring.screenshots.urlscan.requests.get")
    def test_http_error_returns_none(self, get):
        get.return_value = _resp(status=404)
        full = {"task": {"screenshotURL": "https://urlscan.io/screenshots/abc.png"}}
        self.assertIsNone(urlscan.extract(full, "url", "http://x"))

    @patch("score_process.scoring.screenshots.urlscan.requests.get", side_effect=Exception("timeout"))
    def test_timeout_returns_none(self, get):
        full = {"task": {"screenshotURL": "https://urlscan.io/screenshots/abc.png"}}
        self.assertIsNone(urlscan.extract(full, "url", "http://x"))

    @patch("score_process.scoring.screenshots.urlscan.requests.get")
    def test_not_a_png_returns_none(self, get):
        get.return_value = _resp(content=b"<html>")
        full = {"task": {"screenshotURL": "https://urlscan.io/screenshots/abc.png"}}
        self.assertIsNone(urlscan.extract(full, "url", "http://x"))
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test score_process.tests.test_screenshots_urlscan -v 2`
Expected: FAIL — `ModuleNotFoundError: ...screenshots.urlscan`

- [ ] **Step 3: Implement**

```python
# score_process/scoring/screenshots/urlscan.py
"""Fetch the urlscan.io scan screenshot referenced by an Urlscan.io_Scan
report_full. One GET to urlscan.io (never the target URL). None on any failure."""
from __future__ import annotations

import logging
from typing import Any, Optional
from urllib.parse import urlparse

import requests

from .lookyloo import _MAX_BYTES, _PNG_MAGIC

logger = logging.getLogger(__name__)

_TIMEOUT = 10


def _screenshot_url(report_full: Any) -> Optional[str]:
    if not isinstance(report_full, dict):
        return None
    for container in (report_full, report_full.get("results")):
        if not isinstance(container, dict):
            continue
        task = container.get("task")
        if isinstance(task, dict) and isinstance(task.get("screenshotURL"), str):
            return task["screenshotURL"]
        if isinstance(container.get("screenshot"), str):
            return container["screenshot"]
    return None


def _is_urlscan(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host == "urlscan.io" or host.endswith(".urlscan.io")


def extract(report_full: Any, data_type: str, value: Optional[str]) -> Optional[bytes]:
    url = _screenshot_url(report_full)
    if not url or not url.startswith("https://") or not _is_urlscan(url):
        return None
    try:
        resp = requests.get(url, timeout=_TIMEOUT, stream=True)
        resp.raise_for_status()
        buf = b""
        for chunk in resp.iter_content(64 * 1024):
            buf += chunk
            if len(buf) > _MAX_BYTES:
                logger.warning("urlscan screenshot: oversized")
                return None
    except Exception as exc:  # noqa: BLE001 - network is best-effort
        logger.warning("urlscan screenshot fetch failed: %s", exc)
        return None
    return buf if buf.startswith(_PNG_MAGIC) else None
```

- [ ] **Step 4: Run tests**

Run: `python manage.py test score_process.tests.test_screenshots_urlscan -v 2`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add score_process/scoring/screenshots/urlscan.py score_process/tests/test_screenshots_urlscan.py
git commit -m "feat(screenshots): Urlscan.io_Scan screenshot fetch"
```

---

## Task 5: `screenshots/registry.py` — `capture` + `store`

**Files:**
- Create: `score_process/scoring/screenshots/registry.py`
- Test: `score_process/tests/test_screenshots_registry.py`

**Interfaces:**
- Consumes: `lookyloo.extract`, `urlscan.extract`; `cortex_job.cortex_utils.report_target.analyzer_report_target_value`; `common.clients.get_s3_client`, `common.clients.ensure_bucket`
- Produces:
  - `score_process.scoring.screenshots.registry.capture(report) -> bytes | None`
  - `score_process.scoring.screenshots.registry.store(report, png: bytes) -> None` — puts `report-<report.id>.png` into `settings.SCREENSHOT_BUCKET` (default `"analyzer-screenshots"`), then `report.save(update_fields=["screenshot_bucket", "screenshot_key"])`

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_screenshots_registry.py
from unittest.mock import patch, MagicMock
from django.test import TestCase
from cortex_job.models import Analyzer, AnalyzerReport
from cortex_job.models import URL
from score_process.scoring.screenshots import registry

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


def _report(analyzer_name):
    a = Analyzer.objects.create(name=analyzer_name, version="1.0")
    u = URL.objects.create(address="http://x.test")
    return AnalyzerReport.objects.create(
        cortex_job_id="j", type="url", status="Success", analyzer=a, url=u,
        level="info", confidence=0, score=0,
        report_summary={}, report_taxonomy={}, report_full={"screenshot": ""},
    )


class CaptureDispatchTest(TestCase):
    @patch("score_process.scoring.screenshots.registry.lookyloo.extract", return_value=PNG)
    def test_dispatches_lookyloo(self, ex):
        self.assertEqual(registry.capture(_report("Lookyloo_Screenshot")), PNG)
        ex.assert_called_once()

    @patch("score_process.scoring.screenshots.registry.urlscan.extract", return_value=PNG)
    def test_dispatches_urlscan(self, ex):
        self.assertEqual(registry.capture(_report("Urlscan.io_Scan")), PNG)

    def test_unknown_analyzer_returns_none(self):
        self.assertIsNone(registry.capture(_report("VirusTotal_GetReport_3_1")))

    @patch("score_process.scoring.screenshots.registry.lookyloo.extract", side_effect=ValueError("boom"))
    def test_extractor_raising_returns_none(self, ex):
        self.assertIsNone(registry.capture(_report("Lookyloo_Screenshot")))


class StoreTest(TestCase):
    @patch("score_process.scoring.screenshots.registry.ensure_bucket")
    @patch("score_process.scoring.screenshots.registry.get_s3_client")
    def test_store_puts_and_stamps(self, get_client, ensure):
        client = MagicMock()
        get_client.return_value = client
        r = _report("Lookyloo_Screenshot")
        registry.store(r, PNG)
        ensure.assert_called_once()
        args, kwargs = client.put_object.call_args
        self.assertEqual(args[0], "analyzer-screenshots")
        self.assertEqual(args[1], f"report-{r.id}.png")
        r.refresh_from_db()
        self.assertEqual(r.screenshot_bucket, "analyzer-screenshots")
        self.assertEqual(r.screenshot_key, f"report-{r.id}.png")
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test score_process.tests.test_screenshots_registry -v 2`
Expected: FAIL — `ModuleNotFoundError: ...screenshots.registry`

- [ ] **Step 3: Implement**

```python
# score_process/scoring/screenshots/registry.py
"""Dispatch an AnalyzerReport to its screenshot extractor and persist the PNG."""
from __future__ import annotations

import io
import logging
from typing import Optional

from django.conf import settings

from cortex_job.cortex_utils.report_target import analyzer_report_target_value
from common.clients import ensure_bucket, get_s3_client
from score_process.scoring.screenshots import lookyloo, urlscan

logger = logging.getLogger(__name__)

# analyzer.name (lowercased) substring -> extractor(report_full, data_type, value)
_EXTRACTORS = (
    ("lookyloo", lookyloo.extract),
    ("urlscan", urlscan.extract),
)

_DEFAULT_BUCKET = "analyzer-screenshots"


def capture(report) -> Optional[bytes]:
    name = (getattr(getattr(report, "analyzer", None), "name", "") or "").lower()
    for key, fn in _EXTRACTORS:
        if key in name:
            try:
                value = analyzer_report_target_value(report)
                return fn(report.report_full, report.type, value)
            except Exception as exc:  # noqa: BLE001
                logger.warning("screenshot extract for %s failed: %s", name, exc, exc_info=True)
                return None
    return None


def store(report, png: bytes) -> None:
    client = get_s3_client()
    bucket = getattr(settings, "SCREENSHOT_BUCKET", _DEFAULT_BUCKET)
    ensure_bucket(client, bucket)
    key = f"report-{report.id}.png"
    client.put_object(bucket, key, io.BytesIO(png), length=len(png), content_type="image/png")
    report.screenshot_bucket = bucket
    report.screenshot_key = key
    report.save(update_fields=["screenshot_bucket", "screenshot_key"])
```

- [ ] **Step 4: Run tests**

Run: `python manage.py test score_process.tests.test_screenshots_registry -v 2`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add score_process/scoring/screenshots/registry.py score_process/tests/test_screenshots_registry.py
git commit -m "feat(screenshots): capture + MinIO store registry"
```

---

## Task 6: Wire capture into `_save_report`

**Files:**
- Modify: `score_process/scoring/cortex_analyzers/reports.py` (`_save_report`, right after `report.enrichment = enrich(report)` ~line 281)
- Test: `score_process/tests/test_screenshots_save_report.py`

**Interfaces:**
- Consumes: `score_process.scoring.screenshots.registry.capture`, `.store`

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_screenshots_save_report.py
from unittest.mock import patch
from django.test import TestCase
from cortex_job.models import Analyzer, AnalyzerReport, URL
from score_process.scoring.cortex_analyzers.reports import ReportHandler  # adjust to the real class/func

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


class SaveReportScreenshotTest(TestCase):
    def _report(self, name="Lookyloo_Screenshot"):
        a = Analyzer.objects.create(name=name, version="1.0")
        u = URL.objects.create(address="http://x.test")
        return AnalyzerReport.objects.create(
            cortex_job_id="j", type="url", status="Success", analyzer=a, url=u,
            level="info", confidence=0, score=0,
            report_summary={"taxonomies": []}, report_taxonomy={}, report_full={"screenshot": ""},
        )

    @patch("score_process.scoring.screenshots.registry.store")
    @patch("score_process.scoring.screenshots.registry.capture", return_value=PNG)
    def test_capture_and_store_called(self, cap, store):
        report = self._report()
        ReportHandler._save_report(report, case_id=None, artifact_value="http://x.test")
        cap.assert_called_once_with(report)
        store.assert_called_once_with(report, PNG)

    @patch("score_process.scoring.screenshots.registry.capture", side_effect=RuntimeError("boom"))
    def test_capture_failure_does_not_break_scoring(self, cap):
        report = self._report()
        # must not raise; report still persisted with its score fields
        ReportHandler._save_report(report, case_id=None, artifact_value="http://x.test")
        report.refresh_from_db()
        self.assertEqual(report.screenshot_key, "")
```

> Adjust the import and the `_save_report` call signature to match `reports.py` (it is a `@staticmethod` on the report-handling class). If `_save_report` needs a scored `result`, stub the parser via `patch` the same way the existing `reports.py` tests do — mirror `score_process/tests/test_*reports*.py`.

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test score_process.tests.test_screenshots_save_report -v 2`
Expected: FAIL — `capture` never called

- [ ] **Step 3: Implement**

```python
# score_process/scoring/cortex_analyzers/reports.py — in _save_report, immediately after:
#     report.enrichment = enrich(report)
#     report.save(update_fields=["score", "confidence", "category", "level", "enrichment"])

            try:
                from score_process.scoring.screenshots import registry as _shots
                png = _shots.capture(report)
                if png:
                    _shots.store(report, png)   # ponytail: inline; move to a Celery task if it slows the reconcile tick
            except Exception:
                update_cases_logger.exception(
                    "screenshot capture failed for report id=%s", getattr(report, "id", "?"))
```

- [ ] **Step 4: Run tests**

Run: `python manage.py test score_process -v 2`
Expected: PASS (full `score_process` suite green)

- [ ] **Step 5: Commit**

```bash
git add score_process/scoring/cortex_analyzers/reports.py score_process/tests/test_screenshots_save_report.py
git commit -m "feat(screenshots): capture screenshot when saving an analyzer report"
```

---

## Task 7: `CaseScreenshotView` + route

**Files:**
- Create: `api/views/case_screenshot.py`
- Modify: `api/urls.py` (import + one `path(...)` near the `mail-preview.png` route ~line 99)
- Test: `api/tests/test_case_screenshot_view.py`

**Interfaces:**
- Consumes: `AnalyzerReport.screenshot_bucket/screenshot_key`; `common.clients.get_s3_client`
- Produces: `GET /api/cases/<int:case_id>/screenshot.png` (name `case-screenshot`), optional `?report=<id>`

**Permissions:** use `[IsAuthenticated, CanAccessSubmission]` + `self.check_object_permissions(request, case)` — identical to `MailPreviewView` (`api/views/mail_preview.py`).

**Best-pick order:** reports with a non-empty `screenshot_key` linked to the case, ordered `Lookyloo_Screenshot` before `Urlscan.io_Scan`, then `-last_update`.

**Case → reports queryset:** the investigation serializer already has
`InvestigationCaseSerializer.get_analyzer_reports_queryset(obj)` in
`api/views/investigations.py:158`, which resolves the case's targets and calls
`build_analyzer_report_filter(targets)` → `AnalyzerReport.objects.filter(query)`.
Extract the case→queryset logic into `api/utils/analyzer_reports.py` as
`reports_for_case(case) -> QuerySet[AnalyzerReport]` and call it from both the
serializer method and this view. (Locate `build_analyzer_report_filter` — grep
`api/` and `cortex_job/` — and keep it where it is; only the *case→targets→filter*
wrapper moves.)

- [ ] **Step 1: Write the failing test**

```python
# api/tests/test_case_screenshot_view.py
from unittest.mock import patch, MagicMock
from django.urls import reverse
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
# ... imports for Case / ObservableGroup / Analyzer / AnalyzerReport / URL per existing api tests

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


class CaseScreenshotViewTest(APITestCase):
    def setUp(self):
        # build an investigator user + a URL IOC case with an ObservableGroup,
        # following api/tests/test_case_report_view.py or test_investigation*.py
        ...

    def _obj(self):
        return MagicMock(stream=lambda n: [PNG], close=lambda: None, release_conn=lambda: None)

    @patch("api.views.case_screenshot.get_s3_client")
    def test_streams_png(self, client):
        client.return_value.get_object.return_value = self._obj()
        # attach a Success Lookyloo report with screenshot_key set to the case's URL
        ...
        resp = self.client.get(reverse("case-screenshot", args=[self.case.id]))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "image/png")

    def test_404_when_no_screenshot(self):
        resp = self.client.get(reverse("case-screenshot", args=[self.case.id]))
        self.assertEqual(resp.status_code, 404)

    def test_403_for_non_investigator(self):
        self.client.force_authenticate(self.plain_user)
        resp = self.client.get(reverse("case-screenshot", args=[self.case.id]))
        self.assertEqual(resp.status_code, 403)

    @patch("api.views.case_screenshot.get_s3_client")
    def test_report_query_param_selects(self, client):
        client.return_value.get_object.return_value = self._obj()
        # two reports with screenshots; ?report=<id2> should fetch key of report 2
        ...
        resp = self.client.get(
            reverse("case-screenshot", args=[self.case.id]) + f"?report={self.r2.id}")
        self.assertEqual(resp.status_code, 200)
        client.return_value.get_object.assert_called_with(self.r2.screenshot_bucket, self.r2.screenshot_key)

    def test_404_for_foreign_report_id(self):
        resp = self.client.get(
            reverse("case-screenshot", args=[self.case.id]) + "?report=999999")
        self.assertEqual(resp.status_code, 404)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test api.tests.test_case_screenshot_view -v 2`
Expected: FAIL — `NoReverseMatch: 'case-screenshot'`

- [ ] **Step 3: Implement the view**

```python
# api/views/case_screenshot.py
"""GET /api/cases/<case_id>/screenshot.png

Streams the page screenshot captured by a screenshot analyzer
(Lookyloo_Screenshot / Urlscan.io_Scan) for a case, from MinIO, addressed by
AnalyzerReport.screenshot_bucket / screenshot_key. 404 when the case has none.
?report=<id> selects a specific report's screenshot (IOC groups with many URLs).
"""
from __future__ import annotations

import logging

from django.db.models import Case as DjCase, IntegerField, Value, When
from django.http import StreamingHttpResponse
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from api.permissions.submissions import CanAccessSubmission
from common.clients import get_s3_client
from case_handler.models import Case
from cortex_job.models import AnalyzerReport

logger = logging.getLogger(__name__)
_CHUNK = 32 * 1024


def _case_report_qs(case):
    # Reuse the investigation-detail report queryset. If investigations.py keeps
    # this inline, extract it to api/utils/analyzer_reports.py in this task and
    # import from both places.
    from api.utils.analyzer_reports import reports_for_case
    return reports_for_case(case)


class CaseScreenshotView(APIView):
    permission_classes = [IsAuthenticated, CanAccessSubmission]

    def get(self, request, case_id: int):
        try:
            case = Case.objects.get(pk=case_id)
        except Case.DoesNotExist as exc:
            raise NotFound("Case not found") from exc
        self.check_object_permissions(request, case)

        qs = (_case_report_qs(case)
              .exclude(screenshot_key="")
              .select_related("analyzer"))

        report_id = request.query_params.get("report")
        if report_id:
            report = qs.filter(pk=report_id).first()
        else:
            report = (qs.annotate(_pref=DjCase(
                        When(analyzer__name__icontains="lookyloo", then=Value(0)),
                        default=Value(1), output_field=IntegerField()))
                      .order_by("_pref", "-last_update")
                      .first())
        if report is None:
            raise NotFound("No screenshot available")

        try:
            obj = get_s3_client().get_object(report.screenshot_bucket, report.screenshot_key)
        except Exception as exc:
            logger.warning("MinIO get_object failed case=%s key=%s err=%s",
                           case.pk, report.screenshot_key, exc)
            raise NotFound("Screenshot unavailable") from exc

        resp = StreamingHttpResponse(_stream(obj), content_type="image/png")
        resp["Cache-Control"] = "private, max-age=300"
        resp["Content-Disposition"] = f'inline; filename="case_{case.pk}_screenshot.png"'
        return resp


def _stream(obj):
    try:
        for chunk in obj.stream(_CHUNK):
            yield chunk
    finally:
        try:
            obj.close(); obj.release_conn()
        except Exception:
            pass
```

- [ ] **Step 4: Add the route and (if needed) `reports_for_case`**

```python
# api/urls.py
from api.views.case_screenshot import CaseScreenshotView
# ... in urlpatterns, next to the mail-preview route:
    path("cases/<int:case_id>/screenshot.png", CaseScreenshotView.as_view(), name="case-screenshot"),
```

If `api/views/investigations.py` builds its report queryset inline, create `api/utils/analyzer_reports.py` with `reports_for_case(case) -> QuerySet[AnalyzerReport]` holding exactly that logic and call it from both `investigations.py` and here.

- [ ] **Step 5: Run tests**

Run: `python manage.py test api.tests.test_case_screenshot_view api.tests -v 2`
Expected: PASS (full `api` suite green)

- [ ] **Step 6: Commit**

```bash
git add api/views/case_screenshot.py api/urls.py api/utils/analyzer_reports.py api/tests/test_case_screenshot_view.py api/views/investigations.py
git commit -m "feat(api): GET /api/cases/<id>/screenshot.png"
```

---

## Task 8: `screenshot_url` in the investigation serializers

**Files:**
- Modify: `api/serializers/investigations.py` (`CaseInvestigationSerializer` — add `screenshot_url` method field + `Meta.fields`)
- Modify: `api/utils/observable_report.py` (`assemble_observables` — per-observable `screenshot_url`)
- Test: `api/tests/test_investigation_screenshot_url.py`

**Interfaces:**
- Consumes: `AnalyzerReport.screenshot_key`, the `reports_for_case` helper (or the same queryset in context)
- Produces: JSON `screenshot_url: str | null` on the case detail; `observables[].screenshot_url: str | null` in the group payload

- [ ] **Step 1: Write the failing test**

```python
# api/tests/test_investigation_screenshot_url.py
# Build an IOC-group case with 2 URL observables; attach a Lookyloo Success
# report WITH screenshot_key to observable #1 only.
class InvestigationScreenshotUrlTest(APITestCase):
    def test_case_level_url_present_when_any_report_has_screenshot(self):
        resp = self.client.get(reverse("investigation-detail", args=[self.case.id]))
        self.assertEqual(resp.data["screenshot_url"], f"/api/cases/{self.case.id}/screenshot.png")

    def test_case_level_url_null_without_screenshots(self):
        resp = self.client.get(reverse("investigation-detail", args=[self.other_case.id]))
        self.assertIsNone(resp.data["screenshot_url"])

    def test_per_observable_url(self):
        resp = self.client.get(reverse("investigation-detail", args=[self.case.id]))
        obs = {o["value"]: o for o in resp.data["observable_group"]["observables"]}
        self.assertEqual(
            obs["http://one.test"]["screenshot_url"],
            f"/api/cases/{self.case.id}/screenshot.png?report={self.r1.id}")
        self.assertIsNone(obs["http://two.test"]["screenshot_url"])
```

> Use the real detail route name / response shape from `api/tests/test_investigation*.py`.

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test api.tests.test_investigation_screenshot_url -v 2`
Expected: FAIL — `KeyError: 'screenshot_url'`

- [ ] **Step 3: Implement — case level**

```python
# api/serializers/investigations.py — CaseInvestigationSerializer
    screenshot_url = serializers.SerializerMethodField()

    class Meta:
        model = Case
        fields = [
            "id", "reporter_email", "status", "info", "created_at",
            "tests_done", "type", "result", "is_challengeable", "is_challenged",
            "mail_preview_url", "screenshot_url",
        ]

    def get_screenshot_url(self, obj: Case):
        qs = self.context.get("analyzer_reports_qs")
        if qs is not None and qs.exclude(screenshot_key="").exists():
            return f"/api/cases/{obj.pk}/screenshot.png"
        return None
```

(If this serializer does not already receive `analyzer_reports_qs` in context, pass it from the view the same way `InvestigationCaseSerializer` gets it — see `get_analyzer_reports`.)

- [ ] **Step 4: Implement — per observable**

```python
# api/utils/observable_report.py — inside assemble_observables, in the per-report loop,
# track the first report that carries a screenshot:
        shot_report_id = next(
            (rep.id for rep in reports if getattr(rep, "screenshot_key", "")), None)
# ... then in the appended dict:
            "screenshot_url": (
                f"/api/cases/{case.pk}/screenshot.png?report={shot_report_id}"
                if shot_report_id else None),
```

Ensure `observable_reports(case)` selects/defers `screenshot_key` (it selects full `AnalyzerReport` rows already — no change expected; confirm).

- [ ] **Step 5: Run tests**

Run: `python manage.py test api -v 2`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add api/serializers/investigations.py api/utils/observable_report.py api/tests/test_investigation_screenshot_url.py api/views/investigations.py
git commit -m "feat(api): expose screenshot_url on the investigation detail"
```

---

## Task 9: Inline screenshots in the downloadable HTML report

**Files:**
- Modify: `api/views/case_report.py` (`CaseReportView.get` — inline data URIs; add `_inline_screenshots(observables, request)` helper)
- Modify: `templates/case_report/report.html` (per-observable `<img>`)
- Test: `api/tests/test_case_report_screenshot.py`

**Interfaces:**
- Consumes: `AnalyzerReport.screenshot_bucket/key`, `get_s3_client`
- Produces: `observables[].screenshot_data_uri: str | None` on the template context; total embedded bytes capped at `_REPORT_IMG_CAP = 6 * 1024 * 1024`

- [ ] **Step 1: Write the failing test**

```python
# api/tests/test_case_report_screenshot.py
class CaseReportScreenshotTest(APITestCase):
    @patch("api.views.case_report.get_s3_client")
    def test_screenshot_inlined_as_data_uri(self, client):
        client.return_value.get_object.return_value = MagicMock(
            read=lambda: b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
        resp = self.client.get(reverse("case-report", args=[self.case.id]))
        self.assertIn("data:image/png;base64,", resp.content.decode())

    @patch("api.views.case_report.get_s3_client")
    def test_cap_stops_further_images(self, client):
        # 3 observables each with a ~3MB screenshot; only the first ~2 fit under 6MB
        big = b"\x89PNG\r\n\x1a\n" + b"\x00" * (3 * 1024 * 1024)
        client.return_value.get_object.return_value = MagicMock(read=lambda: big)
        resp = self.client.get(reverse("case-report", args=[self.case.id]))
        body = resp.content.decode()
        self.assertLessEqual(body.count("data:image/png;base64,"), 2)
        self.assertIn("screenshot omitted", body)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test api.tests.test_case_report_screenshot -v 2`
Expected: FAIL — no data URI in the output

- [ ] **Step 3: Implement the helper + wire it in**

```python
# api/views/case_report.py
import base64
from common.clients import get_s3_client

_REPORT_IMG_CAP = 6 * 1024 * 1024


def _inline_screenshots(observables):
    """Replace each observable's screenshot_url with an inline data URI,
    fetched from MinIO, until the running total exceeds _REPORT_IMG_CAP."""
    used = 0
    client = None
    for obs in observables:
        url = obs.get("screenshot_url")
        obs["screenshot_data_uri"] = None
        obs["screenshot_omitted"] = bool(url)
        if not url:
            obs["screenshot_omitted"] = False
            continue
        report_id = url.split("report=")[-1]
        try:
            from cortex_job.models import AnalyzerReport
            rep = AnalyzerReport.objects.filter(pk=report_id).exclude(screenshot_key="").first()
            if rep is None:
                continue
            client = client or get_s3_client()
            data = client.get_object(rep.screenshot_bucket, rep.screenshot_key).read()
        except Exception:
            continue
        if used + len(data) > _REPORT_IMG_CAP:
            continue
        used += len(data)
        obs["screenshot_data_uri"] = "data:image/png;base64," + base64.b64encode(data).decode()
        obs["screenshot_omitted"] = False
    return observables
```

In `CaseReportView.get`, after `observables = assemble_observables(case, full=True) ...`:

```python
        observables = _inline_screenshots(observables)
```

- [ ] **Step 4: Template**

```django
{# templates/case_report/report.html — inside the per-observable block #}
{% if obs.screenshot_data_uri %}
  <img class="observable-screenshot" alt="Screenshot of {{ obs.value }}"
       src="{{ obs.screenshot_data_uri }}"
       style="max-width:100%;border:1px solid #ccc;margin-top:.5rem;">
{% elif obs.screenshot_omitted %}
  <p class="muted">Screenshot omitted from the report (size cap) — open the investigation view.</p>
{% endif %}
```

- [ ] **Step 5: Run tests**

Run: `python manage.py test api -v 2`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add api/views/case_report.py templates/case_report/report.html api/tests/test_case_report_screenshot.py
git commit -m "feat(api): inline analyzer screenshots in the downloadable report"
```

---

## Task 10: Frontend — `ScreenshotPanel` on both roads

**Files:**
- Create: `suspicious-ui/src/shared/components/ScreenshotPanel.tsx`
- Create: `suspicious-ui/src/shared/components/__tests__/ScreenshotPanel.test.tsx`
- Modify: the investigation Zod schema file(s) under `suspicious-ui/src/features/investigation/` — add `screenshot_url`
- Modify: the IOC-group layout + mail-road layout components to render `<ScreenshotPanel>`

**Interfaces:**
- Consumes: `screenshot_url: string | null` from the case detail and each observable
- Produces: `<ScreenshotPanel src={string | null} label={string} />`

- [ ] **Step 1: Write the failing test**

```tsx
// suspicious-ui/src/shared/components/__tests__/ScreenshotPanel.test.tsx
import { render, screen, fireEvent } from "@testing-library/react";
import { ScreenshotPanel } from "../ScreenshotPanel";

test("renders an img with the given src", () => {
  render(<ScreenshotPanel src="/api/cases/1/screenshot.png" label="Page screenshot" />);
  expect(screen.getByRole("img", { name: /page screenshot/i })).toHaveAttribute(
    "src", "/api/cases/1/screenshot.png");
});

test("shows fallback when src is null", () => {
  render(<ScreenshotPanel src={null} label="Page screenshot" />);
  expect(screen.getByText(/no screenshot available/i)).toBeInTheDocument();
});

test("shows fallback after the image errors", () => {
  render(<ScreenshotPanel src="/bad.png" label="Page screenshot" />);
  fireEvent.error(screen.getByRole("img"));
  expect(screen.getByText(/no screenshot available/i)).toBeInTheDocument();
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `pnpm --dir suspicious-ui test ScreenshotPanel`
Expected: FAIL — module not found

- [ ] **Step 3: Implement the component**

```tsx
// suspicious-ui/src/shared/components/ScreenshotPanel.tsx
import { useState } from "react";
import { Box, Skeleton, Typography } from "@mui/material";

export function ScreenshotPanel({ src, label }: { src: string | null; label: string }) {
  const [state, setState] = useState<"loading" | "ok" | "error">(src ? "loading" : "error");

  if (!src || state === "error") {
    return (
      <Box sx={{ p: 2, bgcolor: "action.hover", borderRadius: 1 }}>
        <Typography variant="body2" color="text.secondary">No screenshot available</Typography>
      </Box>
    );
  }
  return (
    <Box>
      <Typography variant="caption" color="text.secondary">{label}</Typography>
      {state === "loading" && <Skeleton variant="rectangular" height={240} />}
      <Box
        component="img"
        src={src}
        alt={label}
        onLoad={() => setState("ok")}
        onError={() => setState("error")}
        sx={{ display: state === "ok" ? "block" : "none", maxWidth: "100%", border: "1px solid", borderColor: "divider" }}
      />
    </Box>
  );
}
```

- [ ] **Step 4: Wire into the layouts + schema**

- Add `screenshot_url: z.string().nullable().optional()` to the case detail schema and the observable schema.
- IOC-group layout: for each URL/domain/IP observable, render `<ScreenshotPanel src={obs.screenshot_url ?? null} label={`Screenshot — ${obs.value}`} />`.
- Mail-road layout: render `<ScreenshotPanel src={data.screenshot_url ?? null} label="Page screenshot" />` near the `MailPreview`, and per embedded URL observable if that view lists them.

- [ ] **Step 5: Run tests + lint**

Run: `pnpm --dir suspicious-ui test && pnpm --dir suspicious-ui lint`
Expected: PASS / clean

- [ ] **Step 6: Commit**

```bash
git add suspicious-ui/src/shared/components/ScreenshotPanel.tsx suspicious-ui/src/shared/components/__tests__/ScreenshotPanel.test.tsx suspicious-ui/src/features/investigation/ suspicious-ui/src/pages/
git commit -m "feat(ui): show the analyzer page screenshot on both investigation roads"
```

---

## Task 11: `backfill_screenshots` management command

**Files:**
- Create: `score_process/management/commands/backfill_screenshots.py`
- Test: `score_process/tests/test_backfill_screenshots.py`

**Interfaces:**
- Consumes: `screenshots.registry.capture`, `.store`
- Produces: `python manage.py backfill_screenshots [--dry-run] [--limit N]`

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_backfill_screenshots.py
from io import StringIO
from unittest.mock import patch
from django.core.management import call_command
from django.test import TestCase
from cortex_job.models import Analyzer, AnalyzerReport, URL

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16


class BackfillScreenshotsTest(TestCase):
    def _report(self):
        a = Analyzer.objects.create(name="Lookyloo_Screenshot", version="1.0")
        u = URL.objects.create(address="http://x.test")
        return AnalyzerReport.objects.create(
            cortex_job_id="j", type="url", status="Success", analyzer=a, url=u,
            level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={"screenshot": ""},
        )

    @patch("score_process.scoring.screenshots.registry.store")
    @patch("score_process.scoring.screenshots.registry.capture", return_value=PNG)
    def test_dry_run_writes_nothing(self, cap, store):
        self._report()
        call_command("backfill_screenshots", "--dry-run", stdout=StringIO())
        store.assert_not_called()

    @patch("score_process.scoring.screenshots.registry.store")
    @patch("score_process.scoring.screenshots.registry.capture", return_value=PNG)
    def test_stores_for_missing(self, cap, store):
        r = self._report()
        call_command("backfill_screenshots", stdout=StringIO())
        store.assert_called_once_with(r, PNG)

    @patch("score_process.scoring.screenshots.registry.capture", return_value=None)
    def test_skips_when_no_png(self, cap):
        self._report()
        call_command("backfill_screenshots", stdout=StringIO())  # no error
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test score_process.tests.test_backfill_screenshots -v 2`
Expected: FAIL — `CommandError: Unknown command: 'backfill_screenshots'`

- [ ] **Step 3: Implement**

```python
# score_process/management/commands/backfill_screenshots.py
"""Backfill AnalyzerReport screenshots for historical Success reports from
screenshot analyzers. Idempotent; does not re-score."""
from django.core.management.base import BaseCommand
from django.db.models import Q

from cortex_job.models import AnalyzerReport
from score_process.scoring.screenshots import registry


class Command(BaseCommand):
    help = "Capture + store screenshots for existing analyzer reports that have none."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--limit", type=int, default=None)

    def handle(self, *args, **opts):
        qs = (AnalyzerReport.objects
              .filter(status="Success", screenshot_key="")
              .filter(Q(analyzer__name__icontains="lookyloo") | Q(analyzer__name__icontains="urlscan"))
              .select_related("analyzer", "url", "domain", "ip")
              .order_by("id"))
        if opts["limit"]:
            qs = qs[:opts["limit"]]

        scanned = stored = 0
        for report in qs.iterator(chunk_size=200):
            scanned += 1
            png = registry.capture(report)
            if not png:
                continue
            if opts["dry_run"]:
                stored += 1
                continue
            try:
                registry.store(report, png)
                stored += 1
            except Exception as exc:  # noqa: BLE001
                self.stderr.write(f"report {report.id}: store failed: {exc}")

        verb = "would store" if opts["dry_run"] else "stored"
        self.stdout.write(f"scanned {scanned}, {verb} {stored} screenshots")
```

- [ ] **Step 4: Run tests**

Run: `python manage.py test score_process.tests.test_backfill_screenshots -v 2`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add score_process/management/commands/backfill_screenshots.py score_process/tests/test_backfill_screenshots.py
git commit -m "feat(screenshots): backfill_screenshots management command"
```

---

## Task 12: Enable `Lookyloo_Screenshot` in dev + classification doc

**Files:**
- Modify: `deployment/scripts/enable-dev-analyzers.sh` (add `Lookyloo_Screenshot` with the public CIRCL instance)
- Modify: `docs/specs/2026-09-02-analyzer-classification.md` (add both analyzers to bucket ②)
- Test: none automated — deployment script; verified manually against the dev stack

- [ ] **Step 1: Add Lookyloo to the dev analyzer set**

In `deployment/scripts/enable-dev-analyzers.sh`, add `Lookyloo_Screenshot` to the `ANALYZERS` array. If the script only enables keyless analyzers by name, extend it to also POST the analyzer config `{"instance_url": "https://lookyloo.circl.lu"}` for Lookyloo (follow the existing `cortex4py` / `SessionCortexApi` enable call in the script). Do **not** add `Urlscan.io_Scan` (needs an API key).

- [ ] **Step 2: Update the classification doc**

In `docs/specs/2026-09-02-analyzer-classification.md`, under **Bucket ② (egress-allowlist, no sandbox)** add:

```
- Lookyloo_Screenshot — submits the URL to a Lookyloo instance, returns the
  rendered PNG. No attacker code in-process. Egress: the Lookyloo instance host
  (dev: lookyloo.circl.lu; prod: the private instance).
- Urlscan.io_Scan — submits the URL to urlscan.io, returns scan JSON + a
  screenshot URL. No attacker code in-process. Egress: urlscan.io. API key.
```

- [ ] **Step 3: Manual verification (document the result in the commit body)**

```
# with the dev stack up and Cortex reachable:
bash deployment/scripts/enable-dev-analyzers.sh
# submit a URL IOC, wait for reconcile, then:
python manage.py backfill_screenshots        # or let the reconcile tick capture it
curl -s -o /tmp/shot.png -H "Authorization: Token <t>" \
  http://localhost/api/cases/<id>/screenshot.png && file /tmp/shot.png   # -> PNG image data
```

- [ ] **Step 4: Commit**

```bash
git add deployment/scripts/enable-dev-analyzers.sh docs/specs/2026-09-02-analyzer-classification.md
git commit -m "feat(deployment): enable Lookyloo_Screenshot in the dev analyzer set"
```

---

## Task 13: Whole-feature verification

- [ ] **Step 1: Full backend suite**

Run: `python manage.py test cortex_job score_process api -v 2`
Expected: all green

- [ ] **Step 2: Scoring regression guard**

Run: `python manage.py backtest_scoring`
Expected: zero verdict drift (this feature touches no scoring path)

- [ ] **Step 3: Frontend suite + lint + build**

Run: `pnpm --dir suspicious-ui test && pnpm --dir suspicious-ui lint && pnpm --dir suspicious-ui build`
Expected: green / clean / builds

- [ ] **Step 4: Update the SOC roadmap tracking**

Mark *"Afficher un screenshot de la page analysée"* (Lot 1, P1 Analyse) as done in the roadmap artifact / notes; note the residuals (on-demand capture button, urlscan in dev, screenshot in the TheHive ticket).

- [ ] **Step 5: Commit any doc updates**

```bash
git add docs/
git commit -m "docs: URL screenshot capture — mark roadmap item done, note residuals"
```

---

## Self-Review

**Spec coverage:**
- §1 screenshots package → Tasks 3, 4, 5
- §2 storage / `ensure_bucket` → Tasks 2, 5
- §3 model → Task 1
- §4 wire into `_save_report` → Task 6
- §5 API endpoint → Task 7
- §6 serializers → Task 8
- §7 HTML report data URIs → Task 9
- §8 frontend → Task 10
- §9 deployment / classification doc → Task 12
- §10 backfill → Task 11
- Error-handling + testing tables → covered across each task's tests; whole-feature guard → Task 13

**Placeholder scan:** the test bodies in Tasks 7 and 8 carry `...` for fixture setup that must mirror existing `api/tests/` helpers — this is deliberate (the exact `Case`/`ObservableGroup` factory calls live in those files and differ by app version). Every implementation step has concrete code. No "TBD"/"handle edge cases"/"add validation".

**Type consistency:** `capture(report) -> bytes | None` and `store(report, png)` are used identically in Tasks 5, 6, 11. `extract(report_full, data_type, value)` matches across Tasks 3, 4 and the `_EXTRACTORS` table in Task 5. `screenshot_bucket` / `screenshot_key` names match across Tasks 1, 5, 7, 8, 9, 11. `_MAX_BYTES` / `_PNG_MAGIC` defined in Task 3, imported in Task 4. `reports_for_case` introduced in Task 7, reused in Task 8.

**Open confirmations for the implementer (not blockers):**
- The exact `report_full` key holding the Lookyloo base64 PNG — Task 3 checks `screenshot`/`raw` at top level and under `results`; diff against a real capture during Task 12.
- Whether `api/views/investigations.py` already factors its report queryset — Task 7 extracts `reports_for_case` if not.
- `_save_report`'s real name/signature in `reports.py` — Task 6 note.
