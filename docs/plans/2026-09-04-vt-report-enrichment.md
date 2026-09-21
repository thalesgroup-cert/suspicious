# VT Report Enrichment — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Parse the structured fields already stored in `AnalyzerReport.report_full` (per-vendor results, ISP/geo/ASN, first/last-seen dates, threat classification, hash↔filename) into a new `enrichment` column, surface it on both investigation roads and the downloadable report, and refine the VirusTotal parser's `level`/`confidence` so a lone low-quality engine detection no longer bands `malicious`.

**Architecture:** A pure `dict → dict` extraction package (`score_process/scoring/enrichment/`) with a per-analyzer registry (VT first, Shodan/AbuseIPDB slot in later). `create_and_save_report` calls it once per finished report and persists the result. The VT parser reads the same extraction to refine its verdict — VT-only, tightening (fewer `malicious`), gated on new fixtures + `backtest_scoring`. Frontend gets a shared `<AnalyzerEnrichment>` component rendered on both roads.

**Tech Stack:** Django 6.1 + DRF, Pydantic parsers, React 19 + TS + Vite + MUI + Zod + Vitest. No new dependencies.

**Spec:** `docs/specs/2026-09-04-vt-report-enrichment-design.md`

## Global Constraints

- **No new pip / npm dependencies.**
- **Additive DB change only** — `AnalyzerReport.enrichment` is nullable, default `None`. No backfill required for correctness; historical rows read as "no enrichment".
- **The verdict change is VT-only.** No edits to `scoring/engine.py`, `scoring/sources.py`, `scoring/observable_engine.py`, `scoring/collect.py`, `scoring/processing.py`, or any non-VT parser. When VT extraction returns `None`, the VT parser falls back to its **current** `level`/`confidence` logic verbatim.
- **Enrichment must never break scoring.** Every extraction entry point is wrapped so any exception → `None` + a log line.
- **Backend test harness** (no local Python env — Docker, SQLite in-memory, full no-label discovery):
  ```
  docker run --rm \
    -v "$PWD/Suspicious/Suspicious":/app/Suspicious \
    -v "$PWD/Suspicious/settings.ci.json":/app/settings.json:ro \
    -e SUSPICIOUS_CONFIG_PATH=/app/settings.json -w /app/Suspicious \
    suspicious:django61 \
    python manage.py test <named.modules OR nothing> --settings=suspicious.test_settings
  ```
  `makemigrations --check` runs the same way. **Baseline: 858 tests OK** at branch tip `c1dda957`.
- **Frontend test harness:**
  ```
  docker run --rm -v "$PWD/suspicious-ui":/app \
    -v "$HOME/.cache/ms-playwright":/root/.cache/ms-playwright \
    -w /app --entrypoint pnpm suspicious-ui-test-runner:latest <cmd>
  ```
  `<cmd>` = `exec vitest --run` | `exec tsc -b` | `run lint`. **Baseline: vitest 302 passed / 49 files; tsc clean; lint 4 pre-existing warnings, 0 errors.**
- Commit messages: Conventional Commits. End every commit body with:
  ```
  Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01WYQN5r7nrXfKCoVpHWA3SL
  ```
- **This session cannot run compound git commands.** Use plain separate `git` commands from the worktree root.

---

## File Structure

| File | Responsibility |
|---|---|
| `cortex_job/models.py` | `+ enrichment` JSONField on `AnalyzerReport` |
| `cortex_job/migrations/0013_analyzerreport_enrichment.py` | additive migration |
| `cortex_job/cortex_utils/report_target.py` | **new** — `analyzer_report_target_value(report) -> str \| None` (the observable string), hoisted from the serializer's `get_target` |
| `score_process/scoring/enrichment/__init__.py` | **new** — empty package marker |
| `score_process/scoring/enrichment/virustotal.py` | **new** — `extract(report_full, data_type, value=None) -> dict \| None` |
| `score_process/scoring/enrichment/registry.py` | **new** — `enrich(report) -> dict \| None` (dispatch on analyzer name) |
| `score_process/scoring/cortex_analyzers/reports.py` | `create_and_save_report` persists `enrichment` |
| `score_process/scoring/cortex_analyzers/contrib/virustotal.py` | refined `level` / `confidence` from the extraction; current behaviour when extraction is `None` |
| `score_process/tests/fixtures/virustotal/*.json` | **new** — verdict + extraction fixtures |
| `score_process/tests/test_enrichment_virustotal.py` | **new** — extraction unit tests (SimpleTestCase) |
| `score_process/tests/test_virustotal_verdict.py` | **new** — refined-verdict fixture tests |
| `score_process/management/commands/backfill_enrichment.py` | **new** — backfill historical reports |
| `api/serializers/investigations.py` | `+ "enrichment"` in `InvestigationAnalyzerReportSerializer.Meta.fields`; `get_target` calls the shared helper |
| `api/utils/observable_report.py` | `sources[]` dict `+ "enrichment"` |
| `api/tests/test_investigation_group.py`, `api/tests/test_case_report.py` | enrichment assertions |
| `templates/case_report/report.html` | per-source enrichment block |
| `suspicious-ui/src/features/investigation/enrichment.ts` | **new** — Zod schema + `parseEnrichment` |
| `suspicious-ui/src/features/investigation/AnalyzerEnrichment.tsx` | **new** — `<AnalyzerEnrichment>` + `<FactGrid>` + `<VendorTable>` |
| `suspicious-ui/src/features/investigation/SourceTable.tsx` | render `<AnalyzerEnrichment>` (IOC road) |
| `suspicious-ui/src/features/investigation/components/InvestigationAnalyzerReportCard.tsx` | render `<AnalyzerEnrichment>` (mail road) |
| `suspicious-ui/src/features/investigation/api.ts` | `enrichment?` on `InvestigationAnalyzerReport` type + `normalizeAnalyzerReport` |
| `suspicious-ui/src/features/investigation/observableGroup.ts` | `enrichment?` on `sourceSchema` |
| `suspicious-ui/src/features/investigation/__tests__/enrichment.test.ts` | **new** |
| `suspicious-ui/src/features/investigation/__tests__/AnalyzerEnrichment.test.tsx` | **new** |

**Deviation from spec §4.3:** the spec threads the enrichment dict into the parser via a new `AnalyzerParser.run(..., enrichment=)` kwarg. This plan instead has the VT parser call `extract()` directly and `create_and_save_report` call `registry.enrich()` directly — two calls of a pure µs-scale function over an already-loaded dict, versus changing the abstract `run()`/`parse()` contract that all six parsers implement. Same behaviour, smaller blast radius.

**Deviation from spec §5.4:** fixtures live at `score_process/tests/fixtures/virustotal/` (next to the existing `fixtures/cortex/`), not under `scoring/cortex_analyzers/fixtures/`.

---

## Task 1: `AnalyzerReport.enrichment` field + migration

**Files:**
- Modify: `Suspicious/Suspicious/cortex_job/models.py` (class `AnalyzerReport`, after `report_full` ~line 56)
- Create: `Suspicious/Suspicious/cortex_job/migrations/0013_analyzerreport_enrichment.py`
- Test: `Suspicious/Suspicious/cortex_job/tests/test_models.py` (append)

**Interfaces:**
- Produces: `AnalyzerReport.enrichment` — `JSONField(null=True, blank=True, default=None)`. Consumed by Tasks 3, 4, 6, 5.

- [ ] **Step 1: Add the field**

`cortex_job/models.py`, in `class AnalyzerReport`, immediately after `report_full = models.JSONField()`:

```python
    # Structured, display-ready fields extracted from report_full by
    # score_process.scoring.enrichment (VT vendor list, geo/ASN, dates,
    # threat class, filenames). None = not extracted / no extractor / failed.
    enrichment = models.JSONField(null=True, blank=True, default=None)
```

- [ ] **Step 2: Generate the migration**

Run: `docker run ... suspicious:django61 python manage.py makemigrations cortex_job --settings=suspicious.test_settings`
Expected: creates `0013_analyzerreport_enrichment.py` with one `AddField`. Verify the file name and that `dependencies` is `[("cortex_job", "0012_seed_analyzer_tiers")]`.

- [ ] **Step 3: Verify no other migration drift**

Run: `docker run ... python manage.py makemigrations --check --dry-run --settings=suspicious.test_settings`
Expected: "No changes detected".

- [ ] **Step 4: Test — field round-trips**

Append to `cortex_job/tests/test_models.py` (a new test method in an existing `AnalyzerReport` test class, or a new `class AnalyzerReportEnrichmentTest(TestCase)`):

```python
    def test_enrichment_defaults_none_and_round_trips(self):
        from cortex_job.models import Analyzer, AnalyzerReport
        a = Analyzer.objects.create(name="X", analyzer_cortex_id="x1")
        r = AnalyzerReport.objects.create(
            cortex_job_id="j", type="ip", status="Success", analyzer=a,
            level="safe", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={},
        )
        self.assertIsNone(r.enrichment)
        r.enrichment = {"source": "virustotal", "malicious_count": 3}
        r.save(update_fields=["enrichment"])
        r.refresh_from_db()
        self.assertEqual(r.enrichment["malicious_count"], 3)
```

- [ ] **Step 5: Run + commit**

Run the named test module, then the full no-label suite (expect **859**, +1).
```
git add Suspicious/Suspicious/cortex_job/models.py Suspicious/Suspicious/cortex_job/migrations/0013_analyzerreport_enrichment.py Suspicious/Suspicious/cortex_job/tests/test_models.py
git commit -m "feat(cortex_job): AnalyzerReport.enrichment JSONField (additive)"
```

---

## Task 2: `report_target` helper + extraction module + registry

**Files:**
- Create: `Suspicious/Suspicious/cortex_job/cortex_utils/report_target.py`
- Create: `Suspicious/Suspicious/score_process/scoring/enrichment/__init__.py` (empty)
- Create: `Suspicious/Suspicious/score_process/scoring/enrichment/virustotal.py`
- Create: `Suspicious/Suspicious/score_process/scoring/enrichment/registry.py`
- Test: `Suspicious/Suspicious/score_process/tests/test_enrichment_virustotal.py`
- Test fixtures: `Suspicious/Suspicious/score_process/tests/fixtures/virustotal/` (created here, filled in Task 4 for verdict cases; add 2 here for extraction)

**Interfaces:**
- Consumes: `AnalyzerReport` FK attrs (`report.ip`/`url`/`hash`/`domain`/`file`), `report.report_full`, `report.type`, `report.analyzer.name`.
- Produces:
  - `analyzer_report_target_value(report) -> str | None` — the observable string.
  - `score_process.scoring.enrichment.virustotal.extract(report_full, data_type, value=None) -> dict | None`
  - `score_process.scoring.enrichment.registry.enrich(report) -> dict | None`

- [ ] **Step 1: `report_target.py`**

```python
"""The observable string an AnalyzerReport is about, resolved from its
non-null FK. Shared by the enrichment registry and the investigation
serializer (get_target)."""
from __future__ import annotations

from typing import Optional


def analyzer_report_target_value(report) -> Optional[str]:
    if report.url_id:
        return getattr(report.url, "address", None)
    if report.domain_id:
        return getattr(report.domain, "value", None)
    if report.hash_id:
        return getattr(report.hash, "value", None)
    if report.ip_id:
        return getattr(report.ip, "address", None)
    if report.file_id:
        f = getattr(report.file, "file_path", None)
        return getattr(f, "name", None)
    if report.mail_id:
        return getattr(report.mail, "address", None)
    return None
```

- [ ] **Step 2: Write the failing extraction tests**

`score_process/tests/test_enrichment_virustotal.py` (SimpleTestCase — no DB):

```python
import json
from pathlib import Path

from django.test import SimpleTestCase

from score_process.scoring.enrichment.virustotal import extract

FIX = Path(__file__).parent / "fixtures" / "virustotal"


def _full(name):
    return json.loads((FIX / f"{name}.json").read_text())["report_full"]


class VirustotalExtractTests(SimpleTestCase):
    def test_none_when_no_vt_attributes(self):
        self.assertIsNone(extract({"results": {"foo": 1}}, "ip"))
        self.assertIsNone(extract(None, "ip"))
        self.assertIsNone(extract("garbage", "hash"))

    def test_ip_extraction(self):
        e = extract(_full("ip_lone_fp"), "ip", value="8.8.8.8")
        self.assertEqual(e["source"], "virustotal")
        self.assertEqual(e["malicious_count"], 1)
        self.assertGreaterEqual(e["total"], 80)
        self.assertEqual(e["as_owner"], "Google LLC")
        self.assertEqual(e["country"], "US")
        self.assertTrue(e["vt_link"].endswith("/ip-address/8.8.8.8"))
        # vendors sorted flagging-first
        self.assertEqual(e["vendors"][0]["category"], "malicious")

    def test_hash_threat_classification(self):
        e = extract(_full("hash_emotet"), "hash", value="a" * 64)
        self.assertEqual(e["threat_category"], "trojan")
        self.assertIn("emotet", e["threat_label"])
        self.assertIn("invoice", e["meaningful_name"].lower())
        self.assertLessEqual(len(e["names"]), 10)

    def test_dates_are_iso_utc(self):
        e = extract(_full("hash_emotet"), "hash", value="a" * 64)
        self.assertRegex(e["first_seen"], r"^\d{4}-\d\d-\d\dT.*Z$")

    def test_legacy_positives_shape(self):
        e = extract(_full("legacy_positives"), "url", value="http://x.test")
        self.assertEqual(e["malicious_count"], 3)
        self.assertEqual(e["total"], 70)
        self.assertTrue(all("category" in v for v in e["vendors"]))
```

- [ ] **Step 3: Create the 3 extraction fixtures**

Pull a **real** `VirusTotal_GetReport_3_1` `report_full` from the running instance if available:
```
docker compose --env-file deployment/.env exec -T suspicious python manage.py shell -c \
"from cortex_job.models import AnalyzerReport; import json; r=AnalyzerReport.objects.filter(analyzer__name__icontains='virustotal', status='Success').exclude(report_full={}).first(); print(json.dumps(r.report_full)[:200] if r else 'NONE')"
```
If none exists, synthesise realistic v3 payloads. Each fixture file:
`score_process/tests/fixtures/virustotal/<name>.json`:
```json
{
  "data_type": "ip",
  "report_full": { "results": { "data": { "attributes": {
    "last_analysis_stats": {"malicious": 1, "suspicious": 0, "harmless": 60, "undetected": 25, "timeout": 0},
    "last_analysis_results": {
      "SomeVendor": {"category": "malicious", "result": "Malware", "engine_name": "SomeVendor"},
      "Kaspersky": {"category": "harmless", "result": null, "engine_name": "Kaspersky"}
    },
    "as_owner": "Google LLC", "asn": 15169, "country": "US", "continent": "NA",
    "network": "8.8.8.0/24", "reputation": 0,
    "first_submission_date": 1546502400, "last_analysis_date": 1725000000, "tags": []
  }}}},
  "expect": {"level": "suspicious", "confidence_min": 55, "confidence_max": 65}
}
```
- `ip_lone_fp.json` — 1/88 malicious, `as_owner: "Google LLC"`, `country: "US"`, reputation 0 → `expect: {level: "suspicious", ...}`
- `hash_emotet.json` — 55/70 malicious, `popular_threat_classification: {"suggested_threat_label": "trojan.emotet/heur", "popular_threat_category": [{"value": "trojan", "count": 30}]}`, `meaningful_name: "invoice_2026.exe"`, `names: [...12 entries...]`, `first_submission_date`, `type_description: "Win32 EXE"`, `size: 245760` → `expect: {level: "malicious", confidence_min: 90}`
- `legacy_positives.json` — `{"results": {"positives": 3, "total": 70, "scans": {"A": {"detected": true, "result": "X"}, "B": {"detected": false, "result": null}, "C": {"detected": true, "result": "Y"}, "D": {"detected": true, "result": "Z"}}}}` → `expect: {level: "malicious", ...}` (3 ≥ 2)

- [ ] **Step 4: Implement `virustotal.py`**

```python
"""Extract display-ready fields from a VirusTotal v3 report_full.
Pure dict -> dict; no ORM, no network. Returns None when the payload
carries no usable VT attributes."""
from __future__ import annotations

import base64
import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

_CAT_ORDER = {"malicious": 0, "suspicious": 1, "type-unsupported": 2,
              "harmless": 3, "undetected": 3, "timeout": 4}
_NAMES_CAP = 10


def _attributes(report_full: Any) -> Optional[dict]:
    if not isinstance(report_full, dict):
        return None
    res = report_full.get("results")
    if not isinstance(res, dict):
        return None
    data = res.get("data")
    if isinstance(data, dict) and isinstance(data.get("attributes"), dict):
        return data["attributes"]
    if isinstance(res.get("attributes"), dict):
        return res["attributes"]
    if "last_analysis_results" in res or "last_analysis_stats" in res:
        return res
    return None


def _iso(ts: Any) -> Optional[str]:
    try:
        ts = int(ts)
    except (TypeError, ValueError):
        return None
    if ts <= 0:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _vendors_from_results(results: dict) -> list[dict]:
    out = []
    for engine, r in results.items():
        if not isinstance(r, dict):
            continue
        out.append({
            "name": engine,
            "category": str(r.get("category") or "undetected"),
            "result": r.get("result") or None,
        })
    out.sort(key=lambda v: (_CAT_ORDER.get(v["category"], 3), v["name"].lower()))
    return out


def _vendors_from_scans(scans: dict) -> list[dict]:
    out = []
    for engine, r in scans.items():
        if not isinstance(r, dict):
            continue
        detected = bool(r.get("detected"))
        out.append({
            "name": engine,
            "category": "malicious" if detected else "undetected",
            "result": r.get("result") or None,
        })
    out.sort(key=lambda v: (_CAT_ORDER.get(v["category"], 3), v["name"].lower()))
    return out


def _vt_link(data_type: str, value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    base = "https://www.virustotal.com/gui"
    dt = (data_type or "").lower()
    if dt in ("hash", "file"):
        return f"{base}/file/{value}"
    if dt == "ip":
        return f"{base}/ip-address/{value}"
    if dt == "domain":
        return f"{base}/domain/{value}"
    if dt == "url":
        uid = base64.urlsafe_b64encode(value.encode()).rstrip(b"=").decode()
        return f"{base}/url/{uid}"
    return None


def extract(report_full: Any, data_type: str, value: Optional[str] = None) -> Optional[dict]:
    try:
        return _extract(report_full, data_type, value)
    except Exception as exc:   # never break scoring
        logger.warning("VT enrichment extraction failed: %s", exc, exc_info=True)
        return None


def _extract(report_full: Any, data_type: str, value: Optional[str]) -> Optional[dict]:
    attrs = _attributes(report_full)
    legacy = None
    if attrs is None and isinstance(report_full, dict):
        res = report_full.get("results")
        if isinstance(res, dict) and "positives" in res:
            legacy = res
    if attrs is None and legacy is None:
        return None

    out: dict[str, Any] = {"source": "virustotal"}
    dt = (data_type or "").lower()

    if legacy is not None:
        scans = legacy.get("scans") if isinstance(legacy.get("scans"), dict) else {}
        out["vendors"] = _vendors_from_scans(scans)
        out["malicious_count"] = int(legacy.get("positives") or 0)
        out["suspicious_count"] = 0
        out["total"] = int(legacy.get("total") or len(scans) or 0)
        out["vt_link"] = _vt_link(dt, value)
        return out

    results = attrs.get("last_analysis_results")
    if isinstance(results, dict):
        out["vendors"] = _vendors_from_results(results)
    stats = attrs.get("last_analysis_stats")
    if isinstance(stats, dict):
        out["malicious_count"] = int(stats.get("malicious") or 0)
        out["suspicious_count"] = int(stats.get("suspicious") or 0)
        out["total"] = sum(int(v or 0) for v in stats.values())
    elif "vendors" in out:
        cats = [v["category"] for v in out["vendors"]]
        out["malicious_count"] = cats.count("malicious")
        out["suspicious_count"] = cats.count("suspicious")
        out["total"] = len(cats)

    rep = attrs.get("reputation")
    if isinstance(rep, (int, float)):
        out["reputation"] = int(rep)
    fs = _iso(attrs.get("first_submission_date"))
    if fs:
        out["first_seen"] = fs
    ls = _iso(attrs.get("last_analysis_date")) or _iso(attrs.get("last_submission_date"))
    if ls:
        out["last_seen"] = ls
    tags = attrs.get("tags")
    if isinstance(tags, list) and tags:
        out["tags"] = [str(t) for t in tags][:20]
    link = _vt_link(dt, value)
    if link:
        out["vt_link"] = link

    if dt == "ip":
        for k_src, k_dst in (("as_owner", "as_owner"), ("asn", "asn"),
                             ("country", "country"), ("continent", "continent"),
                             ("network", "network")):
            v = attrs.get(k_src)
            if v not in (None, ""):
                out[k_dst] = v
    elif dt in ("domain", "url"):
        for k_src, k_dst in (("registrar", "registrar"),):
            v = attrs.get(k_src)
            if v not in (None, ""):
                out[k_dst] = v
        cd = _iso(attrs.get("creation_date"))
        if cd:
            out["creation_date"] = cd
        cats = attrs.get("categories")
        if isinstance(cats, dict) and cats:
            out["categories"] = {str(k): str(v) for k, v in list(cats.items())[:10]}
        if dt == "url":
            for k_src, k_dst in (("last_final_url", "final_url"), ("title", "page_title")):
                v = attrs.get(k_src)
                if v not in (None, ""):
                    out[k_dst] = v
    elif dt in ("hash", "file"):
        for k_src, k_dst in (("meaningful_name", "meaningful_name"),
                             ("size", "size"),
                             ("type_description", "type_description")):
            v = attrs.get(k_src)
            if v not in (None, ""):
                out[k_dst] = v
        names = attrs.get("names")
        if isinstance(names, list) and names:
            out["names"] = [str(n) for n in names][:_NAMES_CAP]
        ptc = attrs.get("popular_threat_classification")
        if isinstance(ptc, dict):
            label = ptc.get("suggested_threat_label")
            if label:
                out["threat_label"] = str(label)
            cats = ptc.get("popular_threat_category")
            if isinstance(cats, list) and cats and isinstance(cats[0], dict):
                out["threat_category"] = str(cats[0].get("value") or "")

    return out
```

- [ ] **Step 5: Implement `registry.py`**

```python
"""Dispatch an AnalyzerReport to its enrichment extractor, or None."""
from __future__ import annotations

import logging
from typing import Optional

from cortex_job.cortex_utils.report_target import analyzer_report_target_value
from score_process.scoring.enrichment import virustotal

logger = logging.getLogger(__name__)

# analyzer.name (lowercased) substring -> extractor callable(report_full, data_type, value)
_EXTRACTORS = (
    ("virustotal", virustotal.extract),
)


def enrich(report) -> Optional[dict]:
    name = (getattr(getattr(report, "analyzer", None), "name", "") or "").lower()
    for key, fn in _EXTRACTORS:
        if key in name:
            try:
                value = analyzer_report_target_value(report)
                return fn(report.report_full, report.type, value)
            except Exception as exc:
                logger.warning("enrichment for %s failed: %s", name, exc, exc_info=True)
                return None
    return None
```

- [ ] **Step 6: Run + commit**

Named modules: `score_process.tests.test_enrichment_virustotal`. Then full suite (expect **864**, +5).
```
git add Suspicious/Suspicious/cortex_job/cortex_utils/report_target.py Suspicious/Suspicious/score_process/scoring/enrichment/ Suspicious/Suspicious/score_process/tests/test_enrichment_virustotal.py Suspicious/Suspicious/score_process/tests/fixtures/virustotal/
git commit -m "feat(score): VT report_full enrichment extractor + registry"
```

---

## Task 3: Persist `enrichment` in `create_and_save_report`

**Files:**
- Modify: `Suspicious/Suspicious/score_process/scoring/cortex_analyzers/reports.py` (`create_and_save_report`, ~line 96-135)
- Test: `Suspicious/Suspicious/score_process/tests/test_get_report.py` (append) or a new `test_enrichment_persist.py`

**Interfaces:**
- Consumes: `registry.enrich` (Task 2), `AnalyzerReport.enrichment` (Task 1).
- Produces: a finished VT `AnalyzerReport` has `.enrichment` populated after scoring.

- [ ] **Step 1: Write the failing test**

`score_process/tests/test_enrichment_persist.py`:

```python
import json
from pathlib import Path

from django.test import TestCase

from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports

FIX = Path(__file__).parent / "fixtures" / "virustotal"


class EnrichmentPersistTests(TestCase):
    def test_vt_report_gets_enrichment_on_score(self):
        full = json.loads((FIX / "ip_lone_fp.json").read_text())["report_full"]
        ip = IP.objects.create(address="8.8.8.8")
        a = Analyzer.objects.create(name="VirusTotal_GetReport_3_1", analyzer_cortex_id="VirusTotal_GetReport_3_1", tier=1)
        r = AnalyzerReport.objects.create(
            cortex_job_id="j", type="ip", status="Success", analyzer=a, ip=ip,
            level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full=full,
        )
        CortexAnalyzerReports.create_and_save_report(r, "8.8.8.8", None)
        r.refresh_from_db()
        self.assertIsNotNone(r.enrichment)
        self.assertEqual(r.enrichment["source"], "virustotal")
        self.assertEqual(r.enrichment["as_owner"], "Google LLC")

    def test_non_vt_report_enrichment_stays_none(self):
        a = Analyzer.objects.create(name="FileInfo_8_0", analyzer_cortex_id="FileInfo_8_0")
        ip = IP.objects.create(address="1.1.1.1")
        r = AnalyzerReport.objects.create(
            cortex_job_id="j2", type="ip", status="Success", analyzer=a, ip=ip,
            level="info", confidence=0, score=0,
            report_summary={"taxonomies": []}, report_taxonomy={}, report_full={},
        )
        CortexAnalyzerReports.create_and_save_report(r, "1.1.1.1", None)
        r.refresh_from_db()
        self.assertIsNone(r.enrichment)
```

- [ ] **Step 2: Run — verify it fails**

Expected: `test_vt_report_gets_enrichment_on_score` fails (`r.enrichment is None`).

- [ ] **Step 3: Wire it in**

In `reports.py::create_and_save_report`, the block that ends with:
```python
            report.score      = result_dict.get("score",      0)
            report.confidence = result_dict.get("confidence", 0)
            report.category   = category
            report.level      = result_dict.get("level",    "info")
            report.save(update_fields=["score", "confidence", "category", "level"])
```
becomes:
```python
            from score_process.scoring.enrichment.registry import enrich
            report.score      = result_dict.get("score",      0)
            report.confidence = result_dict.get("confidence", 0)
            report.category   = category
            report.level      = result_dict.get("level",    "info")
            report.enrichment = enrich(report)
            report.save(update_fields=["score", "confidence", "category", "level", "enrichment"])
```

- [ ] **Step 4: Run + commit**

Named: `score_process.tests.test_enrichment_persist`. Full suite (**866**, +2).
```
git add Suspicious/Suspicious/score_process/scoring/cortex_analyzers/reports.py Suspicious/Suspicious/score_process/tests/test_enrichment_persist.py
git commit -m "feat(score): persist analyzer enrichment when a report is scored"
```

---

## Task 4: Refined VT verdict

**Files:**
- Modify: `Suspicious/Suspicious/score_process/scoring/cortex_analyzers/contrib/virustotal.py` (`VirusTotalGetReportParser.parse`)
- Create: `Suspicious/Suspicious/score_process/tests/test_virustotal_verdict.py`
- Add fixtures: `score_process/tests/fixtures/virustotal/{ip_8888_clean,url_two_engines,domain_neg_reputation}.json` (the `hash_emotet`, `ip_lone_fp`, `legacy_positives` from Task 2 are reused)

**Interfaces:**
- Consumes: `enrichment.virustotal.extract` (Task 2).
- Produces: unchanged `AnalyzerResult` shape; `level` / `confidence` values differ per §5.2 of the spec.

- [ ] **Step 1: Write the failing fixture-driven test**

`score_process/tests/test_virustotal_verdict.py`:

```python
import json
from pathlib import Path

from django.test import SimpleTestCase

from score_process.scoring.cortex_analyzers.contrib.virustotal import VirusTotalGetReportParser

FIX = Path(__file__).parent / "fixtures" / "virustotal"
CASES = sorted(p.stem for p in FIX.glob("*.json"))


class VirustotalVerdictTests(SimpleTestCase):
    def _run(self, name):
        spec = json.loads((FIX / f"{name}.json").read_text())
        p = VirusTotalGetReportParser(
            analyzer_name="VirusTotal_GetReport_3_1", data=name,
            data_type=spec["data_type"], case_id=None,
        )
        return p.parse({}, spec["report_full"]), spec["expect"]

    def test_all_fixtures_hit_expected_band(self):
        for name in CASES:
            with self.subTest(fixture=name):
                result, expect = self._run(name)
                self.assertEqual(result.level, expect["level"])
                if "confidence_min" in expect:
                    self.assertGreaterEqual(result.confidence, expect["confidence_min"])
                if "confidence_max" in expect:
                    self.assertLessEqual(result.confidence, expect["confidence_max"])

    def test_lone_fp_is_suspicious_not_malicious(self):
        result, _ = self._run("ip_lone_fp")
        self.assertEqual(result.level, "suspicious")   # was "malicious" before this change

    def test_extraction_none_falls_back_to_current_behaviour(self):
        # report_full with NO parseable VT attributes at all -> extract() -> None
        # -> the parser must use its pre-change logic. Here the stats-only path
        # (the `_stats()` helper reads results.data.attributes.last_analysis_stats)
        # still yields malicious=2, so old logic bands "malicious".
        p = VirusTotalGetReportParser(
            analyzer_name="VirusTotal_GetReport_3_1", data="x", data_type="ip", case_id=None,
        )
        full = {"results": {"data": {"attributes": {"last_analysis_stats":
                {"malicious": 2, "harmless": 5, "undetected": 1}}}}}
        # extract() returns a dict here (it can read last_analysis_stats), so the
        # refined path runs: m=2 -> malicious. Both paths agree -> assert malicious.
        r = p.parse({}, full)
        self.assertEqual(r.level, "malicious")

    def test_truly_unparseable_full_uses_legacy_flat_confidence(self):
        # results present but neither attributes nor positives -> _stats() None
        # AND extract() None -> parser hits its `stats is None and positives is None`
        # DefaultTaxonomyParser fallback (unchanged behaviour).
        p = VirusTotalGetReportParser(
            analyzer_name="VirusTotal_GetReport_3_1", data="x", data_type="ip", case_id=None,
        )
        r = p.parse({}, {"results": {"unexpected": "shape"}})
        self.assertEqual(r.level, "info")  # DefaultTaxonomyParser with empty summary
```

Additional fixtures:
- `ip_8888_clean.json` — `data_type: ip`, 0 malicious / 90 harmless, reputation 0 → `expect: {level: "safe", confidence_min: 85}`
- `url_two_engines.json` — `data_type: url`, 2 malicious / 78, no threat class → `expect: {level: "malicious", confidence_min: 55, confidence_max: 62}`
- `domain_neg_reputation.json` — `data_type: domain`, 0 malicious, `reputation: -40` → `expect: {level: "suspicious", confidence_min: 55, confidence_max: 65}`

- [ ] **Step 2: Run — verify `ip_lone_fp` / `domain_neg_reputation` fail**

- [ ] **Step 3: Implement the refined verdict**

`contrib/virustotal.py`, replace the block from `if malicious > 0:` through the `AnalyzerResult(...)` return with:

```python
        from score_process.scoring.enrichment.virustotal import extract as _vt_extract

        enr = _vt_extract(full, self.type)
        if enr is not None:
            m = int(enr.get("malicious_count", malicious) or 0)
            s = int(enr.get("suspicious_count", suspicious) or 0)
            total_e = int(enr.get("total", total) or 0)
            reputation = enr.get("reputation")
            has_class = bool(enr.get("threat_label") or enr.get("threat_category"))

            if m >= 2 or (m >= 1 and has_class):
                level = "malicious"
                confidence = max(55, min(95, round(50 + 45 * m / max(total_e, 1))))
            elif m == 1 or s >= 2 or (isinstance(reputation, (int, float)) and reputation <= -25 and m == 0):
                level = "suspicious"
                confidence = 60
            else:
                level = "safe"
                confidence = 90 if total_e >= 10 else 60
            score, _ = get_level_score_confidence(level)   # keep the level->score column
            malicious, total = m, total_e                  # for the category string below
        else:
            # extraction unavailable — current behaviour verbatim
            if malicious > 0:
                level = "malicious"
            elif suspicious > 0:
                level = "suspicious"
            else:
                level = "safe"
            score, confidence = get_level_score_confidence(level)

        return AnalyzerResult(
            analyzer_name=self.analyzer_name, data=self.data_name,
            score=score, confidence=confidence, level=level,
            category=[f"{malicious}/{total} engines"], details=details,
        )
```

(Note: `details` and the `stats`/`positives` extraction above this block are unchanged. The `enr is not None` branch supersedes only the `level`/`score`/`confidence` decision.)

- [ ] **Step 4: Run tests + backtest**

- Named: `score_process.tests.test_virustotal_verdict`, `score_process.tests.test_analyzer_parsers` (must stay green).
- Full suite (expect **~869**, +3).
- `docker run ... python manage.py backtest_scoring --road all --settings=suspicious.test_settings` — capture the transition matrix. In the test DB there are no cases, so this just confirms it runs; **record in the task report that a real-instance backtest is a pre-merge manual step** (run against the live DB, review that every `X -> Y` transition is a VT lone-FP being corrected, not a regression).
- `docker run ... python manage.py score_accuracy --settings=suspicious.test_settings` — the 5 labelled cases stay green (they carry pre-computed SourceVerdicts, unaffected).

- [ ] **Step 5: Commit**
```
git add Suspicious/Suspicious/score_process/scoring/cortex_analyzers/contrib/virustotal.py Suspicious/Suspicious/score_process/tests/test_virustotal_verdict.py Suspicious/Suspicious/score_process/tests/fixtures/virustotal/
git commit -m "feat(score): refine VT verdict from vendor ratio + threat class

A lone low-quality engine detection (1/N, no threat classification) now
bands suspicious instead of malicious; confidence scales with vendor
agreement. Falls back to the previous flat logic when extraction is
unavailable. VT parser only."
```

---

## Task 5: `backfill_enrichment` management command

**Files:**
- Create: `Suspicious/Suspicious/score_process/management/commands/backfill_enrichment.py`
- Test: `Suspicious/Suspicious/score_process/tests/test_backfill_enrichment.py`

**Interfaces:**
- Consumes: `registry.enrich` (Task 2).
- Produces: CLI `manage.py backfill_enrichment [--dry-run] [--limit N]`.

- [ ] **Step 1: Write the failing test**

```python
import json
from io import StringIO
from pathlib import Path

from django.core.management import call_command
from django.test import TestCase

from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP

FIX = Path(__file__).parent / "fixtures" / "virustotal"


class BackfillEnrichmentTests(TestCase):
    def _vt_report(self, **kw):
        full = json.loads((FIX / "ip_lone_fp.json").read_text())["report_full"]
        a, _ = Analyzer.objects.get_or_create(name="VirusTotal_GetReport_3_1", defaults={"analyzer_cortex_id": "vt"})
        ip = IP.objects.create(address=kw.get("addr", "8.8.8.8"))
        return AnalyzerReport.objects.create(
            cortex_job_id=kw.get("job", "j"), type="ip", status="Success", analyzer=a, ip=ip,
            level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full=full,
        )

    def test_backfills_null_enrichment(self):
        r = self._vt_report()
        self.assertIsNone(r.enrichment)
        call_command("backfill_enrichment", stdout=StringIO())
        r.refresh_from_db()
        self.assertEqual(r.enrichment["source"], "virustotal")

    def test_dry_run_writes_nothing(self):
        r = self._vt_report(addr="9.9.9.9", job="j2")
        call_command("backfill_enrichment", "--dry-run", stdout=StringIO())
        r.refresh_from_db()
        self.assertIsNone(r.enrichment)

    def test_skips_already_enriched(self):
        r = self._vt_report(addr="1.2.3.4", job="j3")
        r.enrichment = {"source": "manual"}
        r.save(update_fields=["enrichment"])
        call_command("backfill_enrichment", stdout=StringIO())
        r.refresh_from_db()
        self.assertEqual(r.enrichment["source"], "manual")
```

- [ ] **Step 2: Implement**

```python
"""Backfill AnalyzerReport.enrichment for historical Success reports.
Display-only; does NOT re-score. Idempotent."""
from django.core.management.base import BaseCommand

from cortex_job.models import AnalyzerReport
from score_process.scoring.enrichment.registry import enrich


class Command(BaseCommand):
    help = "Extract enrichment for existing analyzer reports that have none."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--limit", type=int, default=None)

    def handle(self, *args, **opts):
        qs = (AnalyzerReport.objects
              .filter(enrichment__isnull=True, status="Success")
              .select_related("analyzer", "ip", "url", "hash", "domain", "file")
              .order_by("id"))
        if opts["limit"]:
            qs = qs[:opts["limit"]]

        scanned = written = 0
        batch = []
        for report in qs.iterator(chunk_size=500):
            scanned += 1
            e = enrich(report)
            if e is None:
                continue
            report.enrichment = e
            batch.append(report)
            if len(batch) >= 500 and not opts["dry_run"]:
                AnalyzerReport.objects.bulk_update(batch, ["enrichment"])
                written += len(batch)
                batch = []
        if batch and not opts["dry_run"]:
            AnalyzerReport.objects.bulk_update(batch, ["enrichment"])
            written += len(batch)

        verb = "would write" if opts["dry_run"] else "wrote"
        self.stdout.write(f"scanned {scanned}, {verb} {written if opts['dry_run'] else written} enrichment rows")
```

- [ ] **Step 3: Run + commit**

Named: `score_process.tests.test_backfill_enrichment`. Full suite (**~872**, +3).
```
git add Suspicious/Suspicious/score_process/management/commands/backfill_enrichment.py Suspicious/Suspicious/score_process/tests/test_backfill_enrichment.py
git commit -m "feat(score): backfill_enrichment management command"
```

---

## Task 6: API exposure — both roads

**Files:**
- Modify: `Suspicious/Suspicious/api/serializers/investigations.py` (`InvestigationAnalyzerReportSerializer.Meta.fields` ~line 204; `get_target` ~line 213)
- Modify: `Suspicious/Suspicious/api/utils/observable_report.py` (`assemble_observables`, the `sources.append({...})` dict)
- Test: `Suspicious/Suspicious/api/tests/test_investigation_group.py` (append), `api/tests/test_investigation_detail_challenge.py` or a new `api/tests/test_analyzer_enrichment_api.py`

**Interfaces:**
- Consumes: `AnalyzerReport.enrichment`, `analyzer_report_target_value` (Task 2).
- Produces: `enrichment` key in the mail-road `analyzer_reports[]` items and the IOC-road `observable_group.observables[].sources[]` items.

- [ ] **Step 1: Write the failing tests**

Add to `api/tests/test_investigation_group.py` (`InvestigationGroupApiTests`, which already has the CERT `_make_user` + `@override_settings`):

```python
    def test_source_carries_enrichment(self):
        g = ObservableGroup.objects.create()
        ip = IP.objects.create(address="8.8.8.8")
        ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=ip)
        case = Case.objects.create(description="d", reporter=self.user, observable_group=g)
        a = Analyzer.objects.create(name="VirusTotal_GetReport_3_1", analyzer_cortex_id="vt", tier=1)
        AnalyzerReport.objects.create(
            cortex_job_id="j", type="ip", status="Success", analyzer=a, ip=ip,
            level="suspicious", confidence=60, score=7,
            report_summary={}, report_taxonomy={},
            report_full={}, enrichment={"source": "virustotal", "as_owner": "Google LLC", "vendors": []},
        )
        r = self.client.get(f"/api/investigations/{case.id}/")
        src = r.json()["observable_group"]["observables"][0]["sources"][0]
        self.assertEqual(src["enrichment"]["as_owner"], "Google LLC")
```

New `api/tests/test_analyzer_enrichment_api.py` for the mail road — a mail case with a VT `AnalyzerReport` carrying `enrichment`, `GET /api/investigations/<id>/`, assert `analyzer_reports[0]["enrichment"]` is present. Use the CERT `_make_user` helper + `@override_settings(ROOT_URLCONF="suspicious.urls")`. (Model a minimal mail case: `Mail` + `CaseHasFileOrMail` + a `MailArtifact`/`ArtifactIsIp` so `collect_case_targets` yields the ip, then an `AnalyzerReport` on that ip.)

- [ ] **Step 2: Serializer — add the field**

`InvestigationAnalyzerReportSerializer.Meta.fields`: add `"enrichment"` after `"report_taxonomy"`. (Plain `JSONField` — no `SerializerMethodField`.)

`get_target`: replace the FK-walk body with a call to the shared helper for the *value*, keeping the `kind`/`id` logic:
```python
    def get_target(self, obj: AnalyzerReport) -> dict[str, Any]:
        from cortex_job.cortex_utils.report_target import analyzer_report_target_value
        value = analyzer_report_target_value(obj)
        for attr, kind in (("url_id", "URL"), ("domain_id", "DOMAIN"), ("mail_id", "MAIL"),
                           ("hash_id", "HASH"), ("file_id", "FILE"), ("ip_id", "IP"),
                           ("mail_body_id", "MAIL_BODY"), ("mail_header_id", "MAIL_HEADER")):
            fk = getattr(obj, attr)
            if fk:
                return {"kind": kind, "id": fk, "value": value if value is not None else str(fk)}
        return {"kind": "UNKNOWN", "id": None, "value": None}
```
(`analyzer_report_target_value` currently returns `None` for `mail_body`/`mail_header` — those targets keep their `fuzzy_hash` value. Extend the helper to cover them, OR special-case here. Prefer extending the helper: add `mail_body`/`mail_header` → `fuzzy_hash` branches.)

- [ ] **Step 3: `assemble_observables` — add the key**

In `api/utils/observable_report.py`, the `sources.append({...})` dict gains:
```python
                "enrichment": rep.enrichment,
```
Both `full=True` and `full=False` include it (it is already compact).

- [ ] **Step 4: Run + commit**

Named: `api.tests.test_investigation_group`, `api.tests.test_analyzer_enrichment_api`, `api.tests.test_investigation_detail_challenge` (regression — `get_target` refactor). Full suite (**~875**, +3).
```
git add Suspicious/Suspicious/api/serializers/investigations.py Suspicious/Suspicious/api/utils/observable_report.py Suspicious/Suspicious/cortex_job/cortex_utils/report_target.py Suspicious/Suspicious/api/tests/
git commit -m "feat(api): expose analyzer enrichment on both investigation roads"
```

---

## Task 7: Downloadable report template

**Files:**
- Modify: `Suspicious/Suspicious/templates/case_report/report.html` (the `{% for s in o.sources %}` block)
- Test: `Suspicious/Suspicious/api/tests/test_case_report.py` (append)

**Interfaces:**
- Consumes: the `enrichment` key on each source (Task 6, `full=True` path).

- [ ] **Step 1: Write the failing test**

Append to `api/tests/test_case_report.py`:
```python
    def test_report_renders_enrichment(self):
        from cortex_job.models import Analyzer, AnalyzerReport
        a = Analyzer.objects.create(name="VirusTotal_GetReport_3_1", analyzer_cortex_id="vt", tier=1)
        ip = self.case.observable_group.artifacts.first().ip
        AnalyzerReport.objects.create(
            cortex_job_id="j", type="ip", status="Success", analyzer=a, ip=ip,
            level="malicious", confidence=90, score=10,
            report_summary={}, report_taxonomy={}, report_full={},
            enrichment={"source": "virustotal", "malicious_count": 42, "total": 70,
                        "as_owner": "Evil Hosting LLC", "threat_label": "trojan.emotet",
                        "vendors": [{"name": "Kaspersky", "category": "malicious", "result": "Trojan"}]},
        )
        r = self.client.get(f"/api/cases/{self.case.id}/report/?format=html")
        body = r.content.decode()
        self.assertIn("Evil Hosting LLC", body)
        self.assertIn("42 / 70", body)
        self.assertIn("trojan.emotet", body)
```

- [ ] **Step 2: Add the template block**

Inside `{% for s in o.sources %}`, before the raw-report `<details>`:
```django
    {% if s.enrichment %}
    <div class="enrichment">
      {% if s.enrichment.malicious_count is not None %}
      <p class="sub">{{ s.enrichment.malicious_count }} / {{ s.enrichment.total }} vendors flagged this</p>
      {% endif %}
      {% if s.enrichment.threat_label %}<p class="sub">Threat: {{ s.enrichment.threat_label }}</p>{% endif %}
      {% if s.enrichment.as_owner %}<p class="sub">AS owner: {{ s.enrichment.as_owner }}{% if s.enrichment.country %} ({{ s.enrichment.country }}){% endif %}</p>{% endif %}
      {% if s.enrichment.first_seen %}<p class="sub">First seen: {{ s.enrichment.first_seen }}</p>{% endif %}
      {% if s.enrichment.last_seen %}<p class="sub">Last seen: {{ s.enrichment.last_seen }}</p>{% endif %}
      {% if s.enrichment.meaningful_name %}<p class="sub">Filename: {{ s.enrichment.meaningful_name }}</p>{% endif %}
      {% with flagged=s.enrichment.vendors %}
      {% if flagged %}
      <table><thead><tr><th>Vendor</th><th>Verdict</th><th>Result</th></tr></thead><tbody>
      {% for v in flagged %}{% if v.category == "malicious" or v.category == "suspicious" %}
        <tr><td>{{ v.name }}</td><td>{{ v.category }}</td><td>{{ v.result|default:"—" }}</td></tr>
      {% endif %}{% endfor %}
      </tbody></table>
      {% endif %}
      {% endwith %}
    </div>
    {% endif %}
```
Add a `.enrichment { margin: 8px 0; }` rule to the inline `<style>`.

- [ ] **Step 3: Run + commit**

Named: `api.tests.test_case_report`. Full suite (**~876**, +1).
```
git add Suspicious/Suspicious/templates/case_report/report.html Suspicious/Suspicious/api/tests/test_case_report.py
git commit -m "feat(api): render analyzer enrichment in the downloadable report"
```

---

## Task 8: Frontend — `enrichment.ts` + `<AnalyzerEnrichment>`

**Files:**
- Create: `suspicious-ui/src/features/investigation/enrichment.ts`
- Create: `suspicious-ui/src/features/investigation/AnalyzerEnrichment.tsx`
- Test: `suspicious-ui/src/features/investigation/__tests__/enrichment.test.ts`
- Test: `suspicious-ui/src/features/investigation/__tests__/AnalyzerEnrichment.test.tsx`

**Interfaces:**
- Produces: `type Enrichment`, `parseEnrichment(x) -> Enrichment | undefined`, `<AnalyzerEnrichment enrichment={Enrichment} />`. Consumed by Task 9.

- [ ] **Step 1: `enrichment.ts`**

```typescript
import { z } from "zod";

const vendorSchema = z.object({
  name: z.string(),
  category: z.string(),
  result: z.string().nullable().optional(),
});

export const enrichmentSchema = z.object({
  source: z.string(),
  vendors: z.array(vendorSchema).optional(),
  malicious_count: z.number().optional(),
  suspicious_count: z.number().optional(),
  total: z.number().optional(),
  reputation: z.number().optional(),
  first_seen: z.string().optional(),
  last_seen: z.string().optional(),
  tags: z.array(z.string()).optional(),
  vt_link: z.string().optional(),
  as_owner: z.string().optional(),
  asn: z.number().optional(),
  country: z.string().optional(),
  continent: z.string().optional(),
  network: z.string().optional(),
  registrar: z.string().optional(),
  creation_date: z.string().optional(),
  categories: z.record(z.string(), z.string()).optional(),
  final_url: z.string().optional(),
  page_title: z.string().optional(),
  meaningful_name: z.string().optional(),
  names: z.array(z.string()).optional(),
  size: z.number().optional(),
  type_description: z.string().optional(),
  threat_category: z.string().optional(),
  threat_label: z.string().optional(),
});

export type Vendor = z.infer<typeof vendorSchema>;
export type Enrichment = z.infer<typeof enrichmentSchema>;

export function parseEnrichment(x: unknown): Enrichment | undefined {
  if (x === undefined || x === null) return undefined;
  const parsed = enrichmentSchema.safeParse(x);
  if (!parsed.success) {
    console.warn("enrichment payload failed validation", parsed.error.issues);
    return undefined;
  }
  return parsed.data;
}
```

- [ ] **Step 2: `enrichment.test.ts`**

```typescript
import { describe, it, expect } from "vitest";
import { parseEnrichment } from "../enrichment";

describe("parseEnrichment", () => {
  it("parses a full VT enrichment", () => {
    const e = parseEnrichment({
      source: "virustotal", malicious_count: 42, total: 70,
      as_owner: "Google LLC", country: "US",
      vendors: [{ name: "K", category: "malicious", result: "Trojan" }],
    });
    expect(e?.as_owner).toBe("Google LLC");
    expect(e?.vendors?.[0].category).toBe("malicious");
  });
  it("returns undefined for null / garbage", () => {
    expect(parseEnrichment(null)).toBeUndefined();
    expect(parseEnrichment({ nope: 1 })).toBeUndefined();
  });
  it("accepts a sparse enrichment", () => {
    expect(parseEnrichment({ source: "virustotal" })?.source).toBe("virustotal");
  });
});
```

- [ ] **Step 3: `AnalyzerEnrichment.tsx`**

Component contract:
- Props: `{ enrichment: Enrichment }`.
- `<FactGrid>`: renders only rows with a value. Row set by which keys are present — AS owner · country · ASN · network; registrar · created · final URL · page title; filename · size · type · threat label; first seen · last seen · reputation · tags.
- `<VendorTable>`: MUI `<Table size="small">`. `const flagging = (enrichment.vendors ?? []).filter(v => v.category === "malicious" || v.category === "suspicious")`. Header line: `` `${enrichment.malicious_count ?? flagging.length} / ${enrichment.total ?? enrichment.vendors?.length ?? 0} security vendors flagged this` ``. Default shows `flagging` only; a `<Button size="small">show all N</Button>` toggles to `enrichment.vendors`. Cap rendered rows at 200 with a "+N more" line. Verdict `<Chip size="small">` colour: malicious→error, suspicious→warning, else default.
- A `<Link href={enrichment.vt_link} target="_blank" rel="noopener">View on VirusTotal</Link>` when `vt_link` present.
- Reuse MUI primitives already imported elsewhere in `features/investigation/` (`Table`, `Chip`, `Link`, `Button`, `Typography`, `Box`, `Stack`).

- [ ] **Step 4: `AnalyzerEnrichment.test.tsx`**

```tsx
import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { fireEvent } from "@testing-library/react";
import { AnalyzerEnrichment } from "../AnalyzerEnrichment";

const e = {
  source: "virustotal", malicious_count: 2, total: 70,
  as_owner: "Evil LLC", country: "RU", threat_label: "trojan.emotet",
  vendors: [
    { name: "Kaspersky", category: "malicious", result: "Trojan" },
    { name: "ESET", category: "suspicious", result: "Variant" },
    { name: "Microsoft", category: "undetected", result: null },
  ],
};

describe("AnalyzerEnrichment", () => {
  it("shows the fact grid and the flagged ratio", () => {
    render(<AnalyzerEnrichment enrichment={e} />);
    expect(screen.getByText("Evil LLC")).toBeInTheDocument();
    expect(screen.getByText(/2 \/ 70 security vendors flagged/i)).toBeInTheDocument();
    expect(screen.getByText("trojan.emotet")).toBeInTheDocument();
  });
  it("defaults to flagging vendors only, toggles to all", () => {
    render(<AnalyzerEnrichment enrichment={e} />);
    expect(screen.queryByText("Microsoft")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /show all/i }));
    expect(screen.getByText("Microsoft")).toBeInTheDocument();
  });
});
```

- [ ] **Step 5: Run + commit**

`exec vitest --run enrichment AnalyzerEnrichment`, then full `exec vitest --run` (expect **304 / 51**), `exec tsc -b` (clean), `run lint` (0 new).
```
git add suspicious-ui/src/features/investigation/enrichment.ts suspicious-ui/src/features/investigation/AnalyzerEnrichment.tsx suspicious-ui/src/features/investigation/__tests__/enrichment.test.ts suspicious-ui/src/features/investigation/__tests__/AnalyzerEnrichment.test.tsx
git commit -m "feat(ui): AnalyzerEnrichment component (fact grid + vendor table)"
```

---

## Task 9: Frontend — wire `<AnalyzerEnrichment>` into both roads

**Files:**
- Modify: `suspicious-ui/src/features/investigation/observableGroup.ts` (`sourceSchema`)
- Modify: `suspicious-ui/src/features/investigation/SourceTable.tsx`
- Modify: `suspicious-ui/src/features/investigation/api.ts` (`InvestigationAnalyzerReport` type + `normalizeAnalyzerReport`)
- Modify: `suspicious-ui/src/features/investigation/components/InvestigationAnalyzerReportCard.tsx`
- Test: extend `suspicious-ui/src/features/investigation/__tests__/ObservableGroupPanel.test.tsx`

**Interfaces:**
- Consumes: `<AnalyzerEnrichment>`, `parseEnrichment` (Task 8); the `enrichment` key from the API (Task 6).

- [ ] **Step 1: `observableGroup.ts` — add `enrichment` to `sourceSchema`**

```typescript
import { enrichmentSchema } from "./enrichment";
// in sourceSchema:
  enrichment: enrichmentSchema.nullable().optional(),
```

- [ ] **Step 2: `SourceTable.tsx` — render it**

In the detail `<AccordionDetails>`, before the raw-JSON `<Box component="pre">`:
```tsx
{source.enrichment ? <AnalyzerEnrichment enrichment={source.enrichment} /> : null}
```
Import `AnalyzerEnrichment` from `./AnalyzerEnrichment`.

- [ ] **Step 3: `api.ts` — type + normalize**

`InvestigationAnalyzerReport` type: `+ enrichment?: unknown;`
`normalizeAnalyzerReport`: `enrichment: report.enrichment,` (raw pass-through; the component's `parseEnrichment` validates).

- [ ] **Step 4: `InvestigationAnalyzerReportCard.tsx` — render it**

After the `{report.report_taxonomy ? (...) : null}` accordion and before `{report.report_summary ? ...}`, add:
```tsx
{report.enrichment ? (
  <Accordion disableGutters sx={{ /* same sx as the sibling accordions */ }}>
    <AccordionSummary expandIcon={<ExpandMoreOutlined />} onClick={(e) => e.stopPropagation()}>
      <Typography variant="body2" sx={{ fontWeight: 800 }}>Enrichment</Typography>
    </AccordionSummary>
    <AccordionDetails onClick={(e) => e.stopPropagation()}>
      {(() => {
        const parsed = parseEnrichment(report.enrichment);
        return parsed ? <AnalyzerEnrichment enrichment={parsed} /> : null;
      })()}
    </AccordionDetails>
  </Accordion>
) : null}
```
Import `AnalyzerEnrichment` + `parseEnrichment`.
(`SourceTable` gets `source.enrichment` pre-typed via the Zod schema so it doesn't need `parseEnrichment`; the card's `report` is `any`, so it does.)

- [ ] **Step 5: Extend `ObservableGroupPanel.test.tsx`**

Add a `report`-less enrichment to one source fixture and assert the AS-owner string renders inside the expanded panel. (The existing test's `group` const — add `enrichment: { source: "virustotal", as_owner: "Google LLC", vendors: [] }` to `sources[0]`, render, `expect(screen.getByText("Google LLC"))` after opening the accordion — or a dedicated `SourceTable.test.tsx`.)

- [ ] **Step 6: Run + commit**

Full `exec vitest --run` (expect **~306 / 51**), `exec tsc -b`, `run lint`.
```
git add suspicious-ui/src/features/investigation/
git commit -m "feat(ui): show analyzer enrichment on the IOC + mail investigation views"
```

---

## Task 10: End-to-end integration test

**Files:**
- Create: `Suspicious/Suspicious/api/tests/test_vt_enrichment_e2e.py`

- [ ] **Step 1: Write the test**

```python
import json
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth.models import Group, User
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact, Result
from cortex_job.models import Analyzer, AnalyzerReport
from ip_process.models import IP
from score_process.scoring.apply import finalise_ioc_group

FIX = Path(__file__).parents[1] / "score_process" / "tests" / "fixtures" / "virustotal"
# NB: adjust the relative path to the actual fixtures location


def _make_user(username):
    u = User.objects.create_user(username=username, password="pw-12345")
    g, _ = Group.objects.get_or_create(name="CERT")
    u.groups.add(g)
    return u


@override_settings(ROOT_URLCONF="suspicious.urls")
class VtEnrichmentE2ETests(TestCase):
    def test_lone_fp_ip_bands_suspicious_and_exposes_enrichment(self):
        user = _make_user("u")
        client = APIClient()
        client.force_authenticate(user)

        full = json.loads((FIX / "ip_lone_fp.json").read_text())["report_full"]
        g = ObservableGroup.objects.create()
        ip = IP.objects.create(address="8.8.8.8")
        ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=ip)
        case = Case.objects.create(description="d", reporter=user, observable_group=g)
        a = Analyzer.objects.create(name="VirusTotal_GetReport_3_1",
                                    analyzer_cortex_id="VirusTotal_GetReport_3_1", tier=1)
        AnalyzerReport.objects.create(
            cortex_job_id="j", type="ip", status="Success", analyzer=a, ip=ip,
            level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full=full,
        )
        # score the report the way the pipeline does
        from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports
        CortexAnalyzerReports.create_and_save_report(
            AnalyzerReport.objects.get(cortex_job_id="j"), "8.8.8.8", case.id,
        )
        finalise_ioc_group(case)

        case.refresh_from_db()
        # lone 1/N detection → NOT Dangerous
        self.assertNotEqual(case.results, Result.DANGEROUS)

        body = client.get(f"/api/investigations/{case.id}/").json()
        src = body["observable_group"]["observables"][0]["sources"][0]
        self.assertEqual(src["enrichment"]["source"], "virustotal")
        self.assertEqual(src["enrichment"]["as_owner"], "Google LLC")
```

- [ ] **Step 2: Run + commit**

Named module + full suite (expect **~877**). Frontend unchanged.
```
git add Suspicious/Suspicious/api/tests/test_vt_enrichment_e2e.py
git commit -m "test(api): VT enrichment end-to-end (score -> band -> API payload)"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task(s) |
|---|---|
| §3.1 `enrichment` field + migration | 1 |
| §3.2 enrichment dict shape | 2 (extractor), 8 (Zod mirror) |
| §4.1 `enrichment/virustotal.py::extract` | 2 |
| §4.2 `enrichment/registry.py::enrich` | 2 |
| §4.3 wiring into `create_and_save_report` | 3 (via direct calls, not the `run()` kwarg — deviation noted) |
| §5 VT verdict refinement | 4 |
| §5.4 fixtures + backtest + score_accuracy | 4 |
| §6.1 mail-road serializer field | 6 |
| §6.2 IOC-road `assemble_observables` | 6 |
| §6.3 report template | 7 |
| §7.1 `enrichment.ts` | 8 |
| §7.2 `<AnalyzerEnrichment>` + FactGrid + VendorTable | 8 |
| §7.3 render sites (both roads) | 9 |
| §7.4 frontend tests | 8, 9 |
| §8 `backfill_enrichment` | 5 |
| §10 risks — VT-only, fallback, backtest gate | 4 (fallback test + backtest step) |

**Placeholder scan:** every code step carries real code. The fixture *contents* in Tasks 2/4 are described by field + expected band, not always a full literal JSON — acceptable, since the implementer must pull a real VT sample first (Task 2 Step 3) and the field list + expectation pins what each fixture must contain. The `<AnalyzerEnrichment>` component body (Task 8 Step 3) is a contract, not literal JSX — acceptable for a presentational component whose tests (Step 4) pin the observable behaviour.

**Type consistency:**
- `extract(report_full, data_type, value=None) -> dict | None` — same signature in Task 2 (definition), Task 4 (VT parser call, `value` omitted → link built without id), Task 2 registry (`fn(report.report_full, report.type, value)`).
- enrichment dict keys — §3.2 ↔ Task 2 `_extract` ↔ Task 8 `enrichmentSchema` ↔ Task 7 template. Cross-checked: `source`, `vendors[{name,category,result}]`, `malicious_count`, `suspicious_count`, `total`, `reputation`, `first_seen`, `last_seen`, `tags`, `vt_link`, `as_owner`, `asn`, `country`, `continent`, `network`, `registrar`, `creation_date`, `categories`, `final_url`, `page_title`, `meaningful_name`, `names`, `size`, `type_description`, `threat_category`, `threat_label`.
- `analyzer_report_target_value(report) -> str | None` — Task 2 (def), Task 6 (serializer `get_target`), Task 2 registry.
- `AnalyzerReport.enrichment` — Task 1 (field), Tasks 3/5/6 (write/read).

**Sequencing constraint:** 1 → 2 → 3 → 4 (4 needs 2's `extract`; 3 needs 1+2); 5 needs 2; 6 needs 1+2; 7 needs 6; 8 standalone; 9 needs 8+6; 10 needs 3+4+6. Recommended order is the task order. Tasks 8 can run in parallel with 3–7 (different codebase) if executing with concurrency.

**Pre-merge manual step (not a task):** run `manage.py backtest_scoring --road all` against the **live** DB after Task 4, review the transition matrix — every `X → Y` must be a VT lone-FP correction, not a regression. Record the matrix in the PR / merge notes.
