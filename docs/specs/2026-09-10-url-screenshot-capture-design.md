# URL screenshot capture — reuse the analyzer's screenshot

**Date:** 2026-09-10
**Status:** design, approved for planning
**Context:** SOC roadmap Lot 1, P1 "Analyse" — *"Afficher un screenshot de la page
analysée"*. It is the only P1 "Analyse" item still unbuilt: Suspicious captures no
page screenshot today (the sole image path is the eml→png mail preview in
`mail_feeder/utils/email_preview/`). Cortex already ships two analyzers that
produce one — `Lookyloo_Screenshot` (`url/domain/fqdn/ip`) and `Urlscan.io_Scan`
(`url`) — but neither is wired into Suspicious and no `lookyloo` reference exists
in the repo.

## Goal

When a screenshot-capable analyzer runs on a URL/domain/IP observable, persist
the screenshot it produced and surface it on the IOC-road and mail-road
investigation views and in the downloadable HTML report.

The screenshot comes **only** from the isolated analyzer tier — no app-side
capture — which keeps rendering of attacker-controlled URLs off the Suspicious
host, consistent with the analyzer-isolation direction (the 2-bucket isolation
classification is tracked in the team's engineering memory, not in-repo).

Net effect: an analyst opening a URL case sees the rendered page next to the
verdict and per-source table; the extracted report carries the same image inline.

## Non-goals

- **No in-process / headless-browser capture.** No new runtime dependency
  (no Playwright, no wkhtmltoimage-on-URLs). If no screenshot analyzer ran or
  succeeded, the UI simply shows nothing.
- No on-demand "capture now" button — a later iteration.
- No screenshots for file/hash/mail-address observables — URL/domain/IP only.
- No change to scoring, the categorical verdict engine, `mail_band_escalation`,
  the Cortex webhook, dispatch, or `CaseAnalyzerJob`.
- No screenshot in the TheHive ticket payload yet.
- `Urlscan.io_Scan` stays **disabled in dev** (needs an API key); `Lookyloo_Screenshot`
  runs against the public CIRCL instance in dev.

## Design

### Data flow

```
Cortex analyzer (Lookyloo_Screenshot / Urlscan.io_Scan)
  → AnalyzerReport.report_full
  → reports.py:_save_report → screenshots.capture(report) → PNG bytes
  → screenshots.store(report, png) → MinIO  analyzer-screenshots/report-<id>.png
  → AnalyzerReport.screenshot_bucket / screenshot_key
  → serializer  screenshot_url
  → GET /api/cases/<id>/screenshot.png[?report=<id>]   (stream from MinIO)
  → UI <ScreenshotPanel>   /   HTML report <img src="data:image/png;base64,…">
```

This composes the two patterns already in the tree: the `enrichment/` extractor
+ registry (pure `report_full` → data, dispatched by analyzer-name substring,
called from `_save_report`) and the mail-preview MinIO-backed image endpoint
(bytes in a bucket, `(bucket, key)` on the row, streamed by a dedicated view).

### 1. `score_process/scoring/screenshots/` package

Mirrors `score_process/scoring/enrichment/`.

| File | Responsibility |
|---|---|
| `registry.py` | `capture(report) -> bytes \| None` — substring dispatch on `report.analyzer.name.lower()`: `"lookyloo"` → `lookyloo.extract`, `"urlscan"` → `urlscan.extract`. Wraps the call in try/except → `None` + `logger.warning` (identical shape to `enrichment/registry.py`). Also holds `store(report, png)` (§2). |
| `lookyloo.py` | `extract(report_full, data_type, value) -> bytes \| None` — base64-decode the screenshot payload out of `report_full`. **The exact key is pinned against a captured fixture in Task 1** (candidates: `full["screenshot"]`, `full["raw"]`). Reject empty / non-PNG (magic-byte check). |
| `urlscan.py` | `extract(...) -> bytes \| None` — read the screenshot URL (`task.screenshotURL`, or `result`-level equivalent) from `report_full`; one `requests.get` to **`urlscan.io`** (never the target) with a 10 s timeout and a size cap; return PNG bytes. |

Shared: an 8 MB size cap (drop + log oversized), PNG magic-byte validation.

`Urlscan_io_Search` (already enabled) also carries per-result `screenshot` URLs in
`report_full["indicator"]["results"][].screenshot`, but those are *historical*
captures of prior scans, not of the observable as submitted — out of scope here;
note it as a possible later source.

### 2. Storage — `screenshots/registry.py::store`

```python
def store(report, png: bytes) -> None:
    client = get_s3_client()
    bucket = getattr(settings, "SCREENSHOT_BUCKET", "analyzer-screenshots")
    ensure_bucket(client, bucket)
    key = f"report-{report.id}.png"
    client.put_object(bucket, key, io.BytesIO(png), length=len(png),
                      content_type="image/png")
    report.screenshot_bucket, report.screenshot_key = bucket, key
    report.save(update_fields=["screenshot_bucket", "screenshot_key"])
```

Directly parallels `Eml2PngRenderer.save_preview_to_mail`. `ensure_bucket` is
lifted into `common/clients.py` (both this and `eml2png_renderer._ensure_bucket`
then call the one helper). Re-scores overwrite `report-<id>.png` in place.

### 3. Model — `cortex_job/models.py`

```python
screenshot_bucket = models.CharField(max_length=255, blank=True)
screenshot_key    = models.CharField(max_length=512, blank=True, db_index=True)
```

One additive migration (`cortex_job/migrations/00NN_analyzerreport_screenshot.py`).
Mirrors `Mail.preview_bucket` / `Mail.preview_object_key`.

### 4. Wire into scoring — `score_process/scoring/cortex_analyzers/reports.py`

In `_save_report`, immediately after `report.enrichment = enrich(report)`:

```python
try:
    png = capture(report)
    if png:
        store(report, png)
except Exception:
    update_cases_logger.exception("screenshot capture failed for report id=%s", report.id)
```

Its own try/except — a screenshot failure must never take scoring down (same
discipline the branch already applies around `manage_ai_jobs`).
`# ponytail:` inline in `_save_report`; promote to a Celery task only if it
measurably slows the reconcile tick.

### 5. API endpoint — `api/views/case_screenshot.py`

`GET /api/cases/<int:case_id>/screenshot.png`, `permission_classes =
[IsAuthenticated, IsInvestigator]`. Copies `api/views/mail_preview.py`:

- Collect the case's `AnalyzerReport`s with a non-empty `screenshot_key`
  (via the same report queryset the investigation detail already builds).
- No `?report=` → **best pick**: `Lookyloo_Screenshot` before `Urlscan.io_Scan`,
  then most recent `last_update`.
- `?report=<id>` → that report (404 if it is not in this case or has no
  screenshot) — used by IOC-group cases with several URLs.
- Stream `client.get_object(bucket, key)` as `image/png`, `Cache-Control:
  private, max-age=300`, `Content-Disposition: inline; filename="case_<id>_screenshot.png"`.
- No screenshot → **404** (no lazy re-enqueue: there is no fallback renderer).
- MinIO error → 502, short message (MailPreviewView already models this).

Route in `api/urls.py`:
`path("cases/<int:case_id>/screenshot.png", CaseScreenshotView.as_view(), name="case-screenshot")`.

### 6. Serializers — `api/serializers/investigations.py`

- **`CaseInvestigationSerializer`** — add `screenshot_url` (SerializerMethodField),
  beside `mail_preview_url`: relative `/api/cases/<pk>/screenshot.png` when any of
  the case's analyzer reports has `screenshot_key`, else `None`. Add to `Meta.fields`.
- **`assemble_observables()`** (`api/utils/observable_report.py`) — per observable,
  when one of its `sources` reports has `screenshot_key`, add
  `"screenshot_url": "/api/cases/<pk>/screenshot.png?report=<report_id>"`, else `None`.
  Emitted for `full=False` (API detail). For `full=True` (report) the field is
  replaced by an inline data-URI in §7.
- **Frontend Zod** — `screenshot_url: z.string().nullable().optional()` on the case
  schema and the observable schema in `features/investigation/`.

### 7. HTML report — `api/views/case_report.py` + `templates/case_report/report.html`

A downloaded HTML file carries no session, so `/api/…/screenshot.png` would 401
for the reader. Instead inline the image:

- New helper `inline_screenshot(report) -> str | None` — fetch the bytes from
  MinIO, return `data:image/png;base64,<…>`.
- In `CaseReportView.get`, after `assemble_observables(full=True)`, walk the rows;
  for each with a screenshot set `row["screenshot_data_uri"]` from the helper.
- **Total embedded-image cap** (e.g. 6 MB across the report). Past it, skip the
  remaining images and render a "screenshot omitted — open the investigation
  view" note.
- Template: `<img class="observable-screenshot" src="{{ row.screenshot_data_uri }}">`
  in the per-observable block, behind an `{% if %}`.

### 8. Frontend — `suspicious-ui`

- **`src/shared/components/ScreenshotPanel.tsx`** — lazy `<img>`, MUI `<Skeleton>`
  while loading, a muted "No screenshot available" box on error/404. Modelled on
  `MailPreview.tsx`; if the two converge, extract a shared `<RemoteImagePanel src label />`
  and back both with it.
- **IOC-road investigation** — a `ScreenshotPanel` per URL/domain/IP observable
  whose row has `screenshot_url` (in or beside `SourceTable`).
- **Mail-road investigation** — a `ScreenshotPanel` for each embedded URL
  observable with a screenshot, near the existing mail preview.
- Tests (Vitest): panel renders `<img>` with the expected `src`; shows the
  fallback on error.

### 9. Deployment / enablement

- **`deployment/scripts/enable-dev-analyzers.sh`** — add `Lookyloo_Screenshot`
  with config `{"instance_url": "https://lookyloo.circl.lu"}` (public, keyless).
  Do **not** add `Urlscan.io_Scan` (API key).
- `Lookyloo_Screenshot` and `Urlscan.io_Scan` are `url`/`domain` **type-dispatch**
  analyzers → `CortexJob.get_analyzers_by_type` runs them automatically once
  enabled in Cortex; **no `settings.json` change**.
- **Analyzer isolation classification** — the 2-bucket split (code-execution
  sandbox tier vs. egress-allowlist tier) is tracked in the team's engineering
  memory, not in-repo. Both screenshot analyzers are egress-only: neither runs
  attacker code in-process, each just needs outbound (Lookyloo → its instance
  host; urlscan → `urlscan.io`), so both sit in the egress-allowlist tier. See
  also §Non-goals.
- **Prod runbook note** — set a private Lookyloo instance URL and the urlscan
  API key; both hosts on the analyzer-tier egress allowlist.

### 10. Backfill — `score_process/management/commands/backfill_screenshots.py`

Mirrors `backfill_enrichment`: iterate `AnalyzerReport`s from the screenshot
analyzers with an empty `screenshot_key`, run `capture` + `store`. `--dry-run`,
`--limit`.

## Error handling

| Failure | Behaviour |
|---|---|
| `capture` / `store` raises | logged, swallowed in `_save_report`; the report still scores and saves |
| Lookyloo payload missing / not PNG | `extract` returns `None`; no screenshot for that report |
| urlscan fetch times out / 4xx | `extract` returns `None`; other analyzers unaffected |
| image > 8 MB | dropped, one log line |
| MinIO down at serve time | endpoint 502; investigation JSON still loads (screenshot is a separate request) |
| No screenshot analyzer ran | `screenshot_url` is `null`; UI renders nothing extra |

## Testing

| Area | Tests |
|---|---|
| `lookyloo.extract` | base64 PNG fixture → bytes; missing key → `None`; non-PNG blob → `None`; oversized → `None` |
| `urlscan.extract` | fixture with `screenshotURL` + mocked `requests.get` → bytes; missing URL → `None`; GET timeout → `None`; GET 404 → `None` |
| `registry.capture` | dispatches by name; unknown analyzer → `None`; extractor raising → `None` (logged) |
| `registry.store` | mocked `Minio` — bucket ensured, `put_object` args, `(bucket, key)` saved with `update_fields` |
| `_save_report` | report from `Lookyloo_Screenshot` → fields populated; `capture` raising → report still saved with score/enrichment |
| endpoint | 200 streams PNG; best-pick order (Lookyloo before urlscan, then newest); `?report=<id>` selects; 404 when none; 404 for a foreign `report` id; 403 non-investigator; 502 on MinIO error |
| serializer | `screenshot_url` present when a report has a key, `null` otherwise; per-observable url in `assemble_observables` |
| HTML report | data-URI inlined into the row; total cap respected → later images skipped with the note |
| frontend | `ScreenshotPanel` renders `<img src>`; fallback on error |
| `backfill_screenshots` | `--dry-run` writes nothing; `--limit` honoured; re-run is idempotent |

Every backend task ends with `python manage.py test cortex_job score_process api`
green; frontend tasks end with `pnpm test` green and `pnpm lint` clean.
`python manage.py backtest_scoring` must show **zero** verdict drift — this
feature touches no scoring path, so that is a regression guard, not an expectation.

## Rollout

Additive migration, no data migration. Screenshots appear only for cases analysed
after `Lookyloo_Screenshot` / `Urlscan.io_Scan` are enabled in the deployment's
Cortex, or after `backfill_screenshots` is run against historical reports. The
feature is self-gating: without a screenshot analyzer, `screenshot_url` stays
`null` and no UI changes are visible.

## What remains after this

- On-demand "capture now" button (dispatch a one-off Lookyloo/urlscan job).
- `Urlscan.io_Scan` enabled in dev.
- Screenshot in the TheHive ticket payload and any PDF export.
- `Urlscan_io_Search` historical screenshots as a secondary source.

### Roadmap status

SOC roadmap Lot 1 / P1 "Analyse" item *"Afficher un screenshot de la page
analysée"* is delivered by this branch for any URL processed by an enabled
screenshot analyzer. Residuals unchanged: the on-demand capture button,
`Urlscan.io_Scan` enabled in dev, the screenshot in the TheHive ticket, and the
unverified Lookyloo config key.
