# Derived Observables Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When an extractor analyzer (UnshortenLink, QrDecode) surfaces a new indicator, make it a real observable in the same case — analyzed, scored, and escalating its parent observable when it scores Suspicious/Dangerous.

**Architecture:** A per-analyzer extractor registry parses `AnalyzerReport.report_full`. A `DerivedObservable` provenance row links parent↔child. `ingest_derived_observables(case)` runs inside `reconcile_case_core` *before* finalize, creating the child observable, attaching it to the case (IOC group or mail), and dispatching its analyzers as normal `CaseAnalyzerJob`s — so the existing "any job still pending → stay ANALYZING" gate defers finalize with no lifecycle re-open. 1 hop only. Scoring adds a shared post-pass that escalates the parent and records why.

**Tech Stack:** Django 6, Celery, MariaDB, Cortex (cortex4py), pytest via `manage.py test`, React 19 + Vitest.

**Spec:** `docs/specs/2026-09-07-derived-observables-design.md`

## Global Constraints

- `auto_extract_artifacts` stays `false` — parse specific `report_full` fields, never Cortex's generic regex extraction.
- 1 hop: a derived observable is analyzed but never itself re-extracted.
- No new Cortex analyzers; UnshortenLink_1_2 and QrDecode_1_0 are already enabled.
- No case lifecycle re-opening — derived jobs are injected before first finalize.
- Every derived URL/domain passes the same SSRF (`_check_no_ssrf_ip`) and allow-list (`check_allow_list`) gates a submitted observable gets.
- Kill switch: `get_config("derived_observables.enabled", True)`.
- Run tests in the container (the running `suspicious` image is stale — no source mount):
  `cd deployment && docker compose --env-file .env run --rm --no-deps -v $PWD/../Suspicious/Suspicious:/app -w /app suspicious python manage.py test <label>`
- Commit messages: Conventional Commits; footer:
  `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>` then
  `Claude-Session: https://claude.ai/code/session_013EzA3TMGhR137KyAqF9aTf`

---

## File Structure

| File | Responsibility |
|---|---|
| `cortex_job/models.py` | + `DerivedObservable` model |
| `cortex_job/migrations/0014_derivedobservable.py` | schema |
| `cortex_job/cortex_utils/derived_observables.py` | **new** — `EXTRACTORS` registry, `_unshorten`, `_qrdecode`, `_blocked`, `_attach_to_case`, `ingest_derived_observables`, `score_derived_observables` |
| `cortex_job/cortex_utils/reconciliation.py` | wire `ingest_derived_observables` into `reconcile_case_core` |
| `score_process/scoring/apply.py` | IOC-road parent escalation in `finalise_ioc_group` |
| `score_process/scoring/cortex_analyzers/reports.py` | mail-road escalation in `get_report` mail branch |
| `score_process/scoring/engine.py` | extend `mail_band_escalation` rationale text |
| `api/utils/observable_report.py` | `derived_from` / `escalation_note` on each observable row |
| `api/serializers/investigations.py` | expose the same on the mail artifact list |
| `suspicious-ui/src/features/investigation/ObservableGroupPanel.tsx` | render provenance chip + escalation note |
| `suspicious-ui/src/features/investigation/observableGroup.ts` | type additions |

Tests live in each app's `tests/` dir (`cortex_job/tests/`, `score_process/tests/`, `api/tests/`) and `suspicious-ui/src/features/investigation/__tests__/`.

---

## Task 1: `DerivedObservable` model + migration

**Files:**
- Modify: `cortex_job/models.py` (after `CaseAnalyzerJob`)
- Create: `cortex_job/migrations/0014_derivedobservable.py`
- Test: `cortex_job/tests/test_derived_observable_model.py`

**Interfaces:**
- Produces: `DerivedObservable` with fields `case` (FK), `source_report` (FK AnalyzerReport), `via_analyzer: str`, `parent_type: str`, `parent_id: int`, `child_type: str`, `child_id: int`, `child_value: str`, `child_band: str`, `escalation_note: str`, `created_at`. Unique on `(source_report, child_type, child_id)`.

- [ ] **Step 1: Write the failing test**

```python
# cortex_job/tests/test_derived_observable_model.py
from django.db import IntegrityError
from django.test import TestCase

from case_handler.models import Case
from cortex_job.models import Analyzer, AnalyzerReport, DerivedObservable
from url_process.models import URL


class DerivedObservableModelTests(TestCase):
    def setUp(self):
        self.case = Case.objects.create()
        self.analyzer = Analyzer.objects.create(
            name="UnshortenLink_1_2", analyzer_cortex_id="UnshortenLink_1_2"
        )
        self.parent = URL.objects.create(address="https://tinyurl.com/x")
        self.child = URL.objects.create(address="https://evil.example/login")
        self.report = AnalyzerReport.objects.create(
            cortex_job_id="j1", type="url", status="Success", analyzer=self.analyzer,
            url=self.parent, level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={"found": True},
        )

    def _make(self, **kw):
        defaults = dict(
            case=self.case, source_report=self.report, via_analyzer="UnshortenLink_1_2",
            parent_type="url", parent_id=self.parent.pk,
            child_type="url", child_id=self.child.pk,
            child_value="https://evil.example/login",
        )
        defaults.update(kw)
        return DerivedObservable.objects.create(**defaults)

    def test_row_persists_with_defaults(self):
        d = self._make()
        self.assertEqual(d.child_band, "")
        self.assertEqual(d.escalation_note, "")
        self.assertEqual(self.case.derived_observables.count(), 1)

    def test_same_report_child_pair_is_unique(self):
        self._make()
        with self.assertRaises(IntegrityError):
            self._make()

    def test_different_child_same_report_is_allowed(self):
        self._make()
        other = URL.objects.create(address="https://evil.example/2")
        self._make(child_id=other.pk, child_value="https://evil.example/2")
        self.assertEqual(DerivedObservable.objects.count(), 2)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `... python manage.py test cortex_job.tests.test_derived_observable_model -v2`
Expected: FAIL — `ImportError: cannot import name 'DerivedObservable'`

- [ ] **Step 3: Add the model**

```python
# cortex_job/models.py — after CaseAnalyzerJob
class DerivedObservable(models.Model):
    """Provenance: an observable that an extractor analyzer surfaced from
    another observable's report, within one case. See
    docs/specs/2026-09-07-derived-observables-design.md."""

    case = models.ForeignKey(
        "case_handler.Case", on_delete=models.CASCADE, related_name="derived_observables"
    )
    source_report = models.ForeignKey(
        AnalyzerReport, on_delete=models.CASCADE, related_name="derived_observables"
    )
    via_analyzer = models.CharField(max_length=64)

    parent_type = models.CharField(max_length=16)   # url|domain|ip|hash|file
    parent_id = models.PositiveIntegerField()
    child_type = models.CharField(max_length=16)    # url|domain|ip|hash|mail
    child_id = models.PositiveIntegerField()
    child_value = models.CharField(max_length=512)

    child_band = models.CharField(max_length=16, blank=True, default="")
    escalation_note = models.CharField(max_length=255, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["source_report", "child_type", "child_id"],
                name="uniq_derived_per_report_child",
            )
        ]
        indexes = [models.Index(fields=["case", "parent_type", "parent_id"])]

    def __str__(self):
        return f"Case #{self.case_id}: {self.parent_type}#{self.parent_id} -> {self.child_type}#{self.child_id} via {self.via_analyzer}"
```

- [ ] **Step 4: Generate the migration**

Run: `... python manage.py makemigrations cortex_job --name derivedobservable`
Expected: creates `cortex_job/migrations/0014_derivedobservable.py`. Open it and confirm it only adds `DerivedObservable` (no unrelated changes).

- [ ] **Step 5: Run tests to verify they pass**

Run: `... python manage.py test cortex_job.tests.test_derived_observable_model -v2`
Expected: PASS (3 tests)

- [ ] **Step 6: Commit**

```bash
git add cortex_job/models.py cortex_job/migrations/0014_derivedobservable.py cortex_job/tests/test_derived_observable_model.py
git commit -m "feat(cortex-job): DerivedObservable provenance model"
```

---

## Task 2: Extractor registry

**Files:**
- Create: `cortex_job/cortex_utils/derived_observables.py`
- Test: `cortex_job/tests/test_derived_observables_registry.py`

**Interfaces:**
- Produces: `EXTRACTORS: dict[str, Callable[[dict], list[tuple[str, str]]]]` mapping a Cortex analyzer name to a function `(report_full) -> [(value, data_type), ...]`. Data types are lowercase: `"url"`, `"domain"`, `"ip"`, `"hash"`, `"mail"`.

- [ ] **Step 1: Write the failing test**

```python
# cortex_job/tests/test_derived_observables_registry.py
from unittest import TestCase

from cortex_job.cortex_utils.derived_observables import EXTRACTORS


class UnshortenExtractorTests(TestCase):
    fn = staticmethod(EXTRACTORS["UnshortenLink_1_2"])

    def test_found_true_yields_the_url(self):
        self.assertEqual(self.fn({"found": True, "url": "https://evil.example/x"}),
                         [("https://evil.example/x", "url")])

    def test_found_false_yields_nothing(self):
        self.assertEqual(self.fn({"found": False, "url": None}), [])

    def test_garbage_yields_nothing(self):
        for bad in [{}, None, {"found": True}, {"found": True, "url": ""}, "nope"]:
            self.assertEqual(self.fn(bad), [])


class QrDecodeExtractorTests(TestCase):
    fn = staticmethod(EXTRACTORS["QrDecode_1_0"])

    def _full(self, *entries):
        return {"results_list": [{"results": e} for e in entries],
                "stats": {"total_qr_codes": len(entries)}}

    def test_url_qr_yields_url(self):
        full = self._full({"data": "https://evil.example/q", "data_type": "url"})
        self.assertEqual(self.fn(full), [("https://evil.example/q", "url")])

    def test_multiple_and_mixed_types(self):
        full = self._full(
            {"data": "https://a.example", "data_type": "url"},
            {"data": "1.2.3.4", "data_type": "ip"},
            {"data": "hello world", "data_type": "other"},   # dropped
        )
        self.assertEqual(self.fn(full),
                         [("https://a.example", "url"), ("1.2.3.4", "ip")])

    def test_garbage_yields_nothing(self):
        for bad in [{}, None, {"results_list": "x"}, {"results_list": [{}]},
                    {"results_list": [{"results": {"data": "", "data_type": "url"}}]}]:
            self.assertEqual(self.fn(bad), [])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `... python manage.py test cortex_job.tests.test_derived_observables_registry -v2`
Expected: FAIL — `ModuleNotFoundError: cortex_job.cortex_utils.derived_observables`

- [ ] **Step 3: Write the registry**

```python
# cortex_job/cortex_utils/derived_observables.py
"""Turn an extractor analyzer's report into new observables in the same case.
See docs/specs/2026-09-07-derived-observables-design.md.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

logger = logging.getLogger("tasp.cron.update_ongoing_case_jobs")

_OBSERVABLE_TYPES = {"url", "domain", "ip", "hash", "mail"}


def _unshorten(full: Any) -> list[tuple[str, str]]:
    if not isinstance(full, dict) or not full.get("found"):
        return []
    url = full.get("url")
    return [(url, "url")] if isinstance(url, str) and url else []


def _qrdecode(full: Any) -> list[tuple[str, str]]:
    if not isinstance(full, dict):
        return []
    out: list[tuple[str, str]] = []
    for entry in full.get("results_list") or []:
        res = entry.get("results") if isinstance(entry, dict) else None
        if not isinstance(res, dict):
            continue
        value, dtype = res.get("data"), str(res.get("data_type") or "").lower()
        if isinstance(value, str) and value and dtype in _OBSERVABLE_TYPES:
            out.append((value, dtype))
    return out


EXTRACTORS: dict[str, Callable[[Any], list[tuple[str, str]]]] = {
    "UnshortenLink_1_2": _unshorten,
    "QrDecode_1_0": _qrdecode,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `... python manage.py test cortex_job.tests.test_derived_observables_registry -v2`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add cortex_job/cortex_utils/derived_observables.py cortex_job/tests/test_derived_observables_registry.py
git commit -m "feat(cortex-job): extractor registry for derived observables"
```

---

## Task 3: `_blocked` gate

**Files:**
- Modify: `cortex_job/cortex_utils/derived_observables.py`
- Test: `cortex_job/tests/test_derived_observables_blocked.py`

**Interfaces:**
- Consumes: `_check_no_ssrf_ip` from `api.serializers.submit`, `check_allow_list` from `score_process.scoring.cortex_analyzers.allow_list`.
- Produces: `_blocked(value: str, data_type: str) -> str` — returns a non-empty reason string when the value must NOT become an observable, `""` when it may.

- [ ] **Step 1: Write the failing test**

```python
# cortex_job/tests/test_derived_observables_blocked.py
from django.test import TestCase

from cortex_job.cortex_utils.derived_observables import _blocked
from settings.models import AllowListDomain


class BlockedTests(TestCase):
    def test_plain_url_is_allowed(self):
        self.assertEqual(_blocked("https://evil.example/login", "url"), "")

    def test_ssrf_url_is_blocked(self):
        self.assertTrue(_blocked("http://169.254.169.254/latest/meta-data/", "url"))

    def test_allow_listed_domain_is_blocked(self):
        AllowListDomain.objects.create(domain="good.example")
        self.assertTrue(_blocked("https://good.example/anything", "url"))
        self.assertTrue(_blocked("good.example", "domain"))

    def test_non_url_non_domain_types_are_allowed(self):
        self.assertEqual(_blocked("1.2.3.4", "ip"), "")
        self.assertEqual(_blocked("deadbeef" * 8, "hash"), "")
```

> Before writing: confirm `AllowListDomain`'s field name (`domain` vs `value`) by reading `settings/models.py`; adjust the test's `create(...)` kwarg to match.

- [ ] **Step 2: Run test to verify it fails**

Run: `... python manage.py test cortex_job.tests.test_derived_observables_blocked -v2`
Expected: FAIL — `ImportError: cannot import name '_blocked'`

- [ ] **Step 3: Implement `_blocked`**

```python
# cortex_job/cortex_utils/derived_observables.py — add
def _blocked(value: str, data_type: str) -> str:
    """Non-empty reason if `value` must not become a live observable."""
    if data_type == "url":
        from api.serializers.submit import _check_no_ssrf_ip
        try:
            _check_no_ssrf_ip(value)
        except ValueError as exc:
            return str(exc) or "SSRF-blocked target"
    if data_type in ("url", "domain"):
        from score_process.scoring.cortex_analyzers.allow_list import check_allow_list
        try:
            allow = check_allow_list(value, data_type)
            for reason in allow.model_dump().values():
                if reason:
                    return f"allow-listed ({reason})"
        except Exception:  # noqa: BLE001 — never block ingestion on an allow-list error
            logger.warning("derived: allow-list check failed for %r", value, exc_info=True)
    return ""
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `... python manage.py test cortex_job.tests.test_derived_observables_blocked -v2`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add cortex_job/cortex_utils/derived_observables.py cortex_job/tests/test_derived_observables_blocked.py
git commit -m "feat(cortex-job): SSRF + allow-list gate for derived observables"
```

---

## Task 4: `_attach_to_case` + observable get-or-create

**Files:**
- Modify: `cortex_job/cortex_utils/derived_observables.py`
- Test: `cortex_job/tests/test_derived_observables_attach.py`

**Interfaces:**
- Produces:
  - `_resolve_observable(value: str, data_type: str)` → model instance (`URL`/`Domain`/`IP`/`Hash`/`MailAddress`), created if missing. Returns `None` on an unknown `data_type`.
  - `_attach_to_case(case, obj, data_type: str) -> None` — links `obj` to the case: `ObservableGroupArtifact` for an IOC-group case, `MailArtifact` (+ `ArtifactIsUrl`/`ArtifactIsIp`/…) for a mail case. Idempotent (`get_or_create`).

- [ ] **Step 1: Write the failing test**

```python
# cortex_job/tests/test_derived_observables_attach.py
from django.test import TestCase

from case_handler.models import Case, ObservableGroup
from cortex_job.cortex_utils.derived_observables import _attach_to_case, _resolve_observable
from mail_feeder.models import Mail, MailArtifact
from url_process.models import URL


class ResolveObservableTests(TestCase):
    def test_url_created_once(self):
        a = _resolve_observable("https://evil.example/x", "url")
        b = _resolve_observable("https://evil.example/x", "url")
        self.assertEqual(a.pk, b.pk)
        self.assertEqual(URL.objects.filter(address="https://evil.example/x").count(), 1)

    def test_unknown_type_returns_none(self):
        self.assertIsNone(_resolve_observable("x", "bitcoin"))


class AttachToCaseTests(TestCase):
    def test_ioc_group_case_gets_observable_group_artifact(self):
        group = ObservableGroup.objects.create(label="g")
        case = Case.objects.create(observable_group=group)
        obj = _resolve_observable("https://evil.example/x", "url")
        _attach_to_case(case, obj, "url")
        _attach_to_case(case, obj, "url")  # idempotent
        self.assertEqual(group.artifacts.filter(artifact_type="URL", url=obj).count(), 1)

    def test_mail_case_gets_mail_artifact(self):
        from datetime import datetime, timezone as tz
        mail = Mail.objects.create(subject="s", reportedBy="r@x.test",
                                   date=datetime(2026, 1, 1, tzinfo=tz.utc),
                                   to="a@x.test", mail_id="m1")
        case = Case.objects.create()
        # wire case.fileOrMail -> mail the way the codebase does:
        from case_handler.models import CaseHasFileOrMail
        case.fileOrMail = CaseHasFileOrMail.objects.create(mail=mail, case=case)
        case.save()
        obj = _resolve_observable("https://evil.example/x", "url")
        _attach_to_case(case, obj, "url")
        self.assertTrue(
            MailArtifact.objects.filter(mail=mail, artifact_type="URL",
                                        artifactIsUrl__url=obj).exists()
        )
```

> Before writing: verify `CaseHasFileOrMail` is the right through-model and that `case.fileOrMail` is the accessor — read `case_handler/models.py` and `cortex_job/cortex_utils/case_targets.py` (it walks `case.fileOrMail.mail`). Adjust the mail-wiring lines to match exactly.

- [ ] **Step 2: Run test to verify it fails**

Run: `... python manage.py test cortex_job.tests.test_derived_observables_attach -v2`
Expected: FAIL — `ImportError: cannot import name '_attach_to_case'`

- [ ] **Step 3: Implement**

```python
# cortex_job/cortex_utils/derived_observables.py — add
_MODEL_BY_TYPE = {
    "url": ("url_process.models", "URL", "address"),
    "domain": ("domain_process.models", "Domain", "value"),
    "ip": ("ip_process.models", "IP", "address"),
    "hash": ("hash_process.models", "Hash", "value"),
    "mail": ("email_process.models", "MailAddress", "address"),
}


def _resolve_observable(value: str, data_type: str):
    spec = _MODEL_BY_TYPE.get(data_type)
    if spec is None:
        return None
    from importlib import import_module
    module, cls_name, field = spec
    model = getattr(import_module(module), cls_name)
    obj, _ = model.objects.get_or_create(**{field: value})
    return obj


_OGA_TYPE = {"url": "URL", "domain": "DOMAIN", "ip": "IP", "hash": "HASH"}
_MAIL_JOIN = {                       # data_type -> (join model, MailArtifact FK attr, MailArtifact.artifact_type)
    "url": ("ArtifactIsUrl", "artifactIsUrl", "URL", "url"),
    "ip": ("ArtifactIsIp", "artifactIsIp", "IP", "ip"),
    "hash": ("ArtifactIsHash", "artifactIsHash", "Hash", "hash"),
    "domain": ("ArtifactIsDomain", "artifactIsDomain", "Domain", "domain"),
    "mail": ("ArtifactIsMailAddress", "artifactIsMailAddress", "MailAddress", "mail_address"),
}


def _attach_to_case(case, obj, data_type: str) -> None:
    if getattr(case, "observable_group_id", None):
        art_type = _OGA_TYPE.get(data_type)
        if art_type is None:
            return
        from case_handler.models import ObservableGroupArtifact
        ObservableGroupArtifact.objects.get_or_create(
            group=case.observable_group, artifact_type=art_type, **{data_type: obj}
        )
        return

    mail = getattr(getattr(case, "fileOrMail", None), "mail", None)
    if mail is None:
        logger.warning("derived: case %s has neither observable_group nor mail", case.pk)
        return
    spec = _MAIL_JOIN.get(data_type)
    if spec is None:
        return
    import mail_feeder.models as mf
    join_cls_name, fk_attr, art_type, join_field = spec
    join_cls = getattr(mf, join_cls_name)
    if mf.MailArtifact.objects.filter(
        mail=mail, artifact_type=art_type, **{f"{fk_attr}__{join_field}": obj}
    ).exists():
        return
    ma = mf.MailArtifact.objects.create(mail=mail, artifact_type=art_type)
    join, _ = join_cls.objects.get_or_create(**{join_field: obj}, artifact=ma)
    setattr(ma, fk_attr, join)
    ma.save(update_fields=[fk_attr])
```

> Verify the `ArtifactIsUrl` field name for the observable FK (`url` vs `url_id`) and the `artifact` back-reference name against `mail_feeder/models.py` and `mail_feeder/utils/process_artifacts/artifacts.py::_process_url`. Fix `join_field` / the `get_or_create` kwargs to match that code exactly.

- [ ] **Step 4: Run tests to verify they pass**

Run: `... python manage.py test cortex_job.tests.test_derived_observables_attach -v2`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add cortex_job/cortex_utils/derived_observables.py cortex_job/tests/test_derived_observables_attach.py
git commit -m "feat(cortex-job): attach a derived observable to its case"
```

---

## Task 5: `ingest_derived_observables`

**Files:**
- Modify: `cortex_job/cortex_utils/derived_observables.py`
- Test: `cortex_job/tests/test_ingest_derived_observables.py`

**Interfaces:**
- Consumes: `EXTRACTORS`, `_blocked`, `_resolve_observable`, `_attach_to_case`, `DerivedObservable`; `CortexJob().launch_cortex_jobs(value, data_type, case) -> list` (list of report ids), `collect_case_targets` (`cortex_job.cortex_utils.case_targets`), `build_analyzer_report_filter`, `get_config`.
- Produces: `ingest_derived_observables(case) -> int` — number of derived observables newly attached + dispatched this call. `0` when disabled, nothing to do, or all extractor reports already processed.

- [ ] **Step 1: Write the failing test**

```python
# cortex_job/tests/test_ingest_derived_observables.py
from unittest.mock import patch

from django.test import TestCase

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from cortex_job.cortex_utils.derived_observables import ingest_derived_observables
from cortex_job.models import Analyzer, AnalyzerReport, DerivedObservable
from url_process.models import URL


class IngestTests(TestCase):
    def setUp(self):
        self.group = ObservableGroup.objects.create(label="g")
        self.case = Case.objects.create(observable_group=self.group)
        self.parent = URL.objects.create(address="https://tinyurl.com/x")
        ObservableGroupArtifact.objects.create(group=self.group, artifact_type="URL", url=self.parent)
        self.unshorten = Analyzer.objects.create(
            name="UnshortenLink_1_2", analyzer_cortex_id="UnshortenLink_1_2")
        self.report = AnalyzerReport.objects.create(
            cortex_job_id="j1", type="url", status="Success", analyzer=self.unshorten,
            url=self.parent, level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={},
            report_full={"found": True, "url": "https://evil.example/login"},
        )

    @patch("cortex_job.cortex_utils.derived_observables.CortexJob")
    def test_creates_observable_artifact_provenance_and_dispatches(self, MockCortex):
        MockCortex.return_value.launch_cortex_jobs.return_value = ["r1", "r2"]
        n = ingest_derived_observables(self.case)
        self.assertEqual(n, 1)
        child = URL.objects.get(address="https://evil.example/login")
        self.assertTrue(self.group.artifacts.filter(url=child).exists())
        d = DerivedObservable.objects.get(case=self.case)
        self.assertEqual((d.parent_type, d.parent_id), ("url", self.parent.pk))
        self.assertEqual((d.child_type, d.child_id), ("url", child.pk))
        MockCortex.return_value.launch_cortex_jobs.assert_called_once()

    @patch("cortex_job.cortex_utils.derived_observables.CortexJob")
    def test_second_call_is_a_noop(self, MockCortex):
        MockCortex.return_value.launch_cortex_jobs.return_value = ["r1"]
        ingest_derived_observables(self.case)
        MockCortex.return_value.launch_cortex_jobs.reset_mock()
        self.assertEqual(ingest_derived_observables(self.case), 0)
        MockCortex.return_value.launch_cortex_jobs.assert_not_called()

    @patch("cortex_job.cortex_utils.derived_observables.CortexJob")
    def test_one_hop_cap(self, MockCortex):
        """A report filed against a URL that is itself a derived child is not re-ingested."""
        MockCortex.return_value.launch_cortex_jobs.return_value = ["r1"]
        ingest_derived_observables(self.case)          # gen-1 child created
        child = URL.objects.get(address="https://evil.example/login")
        AnalyzerReport.objects.create(
            cortex_job_id="j2", type="url", status="Success", analyzer=self.unshorten,
            url=child, level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={},
            report_full={"found": True, "url": "https://evil.example/second-hop"},
        )
        MockCortex.return_value.launch_cortex_jobs.reset_mock()
        self.assertEqual(ingest_derived_observables(self.case), 0)
        self.assertFalseIfExists = URL.objects.filter(address="https://evil.example/second-hop")
        self.assertFalse(self.assertFalseIfExists.exists())

    @patch("cortex_job.cortex_utils.derived_observables.CortexJob")
    @patch("cortex_job.cortex_utils.derived_observables.get_config", return_value=False)
    def test_disabled_is_noop(self, _cfg, MockCortex):
        self.assertEqual(ingest_derived_observables(self.case), 0)

    @patch("cortex_job.cortex_utils.derived_observables.CortexJob")
    def test_ssrf_child_is_dropped(self, MockCortex):
        self.report.report_full = {"found": True, "url": "http://169.254.169.254/latest"}
        self.report.save(update_fields=["report_full"])
        self.assertEqual(ingest_derived_observables(self.case), 0)
        self.assertFalse(DerivedObservable.objects.exists())
```

- [ ] **Step 2: Run test to verify it fails**

Run: `... python manage.py test cortex_job.tests.test_ingest_derived_observables -v2`
Expected: FAIL — `ImportError: cannot import name 'ingest_derived_observables'`

- [ ] **Step 3: Implement**

```python
# cortex_job/cortex_utils/derived_observables.py — add
from settings.config import get_config
from cortex_job.cortex_utils.cortex_and_job_management import CortexJob

_PARENT_TYPE_BY_FIELD = {"url": "url", "domain": "domain", "ip": "ip",
                         "hash": "hash", "file": "file"}


def _finished_extractor_reports(case):
    """Success reports for this case's observables whose analyzer is an extractor."""
    from cortex_job.models import AnalyzerReport
    from cortex_job.cortex_utils.case_targets import (
        collect_case_targets, build_analyzer_report_filter,
    )
    targets = collect_case_targets(case)
    if not targets:
        return []
    q = build_analyzer_report_filter(targets)
    return list(
        AnalyzerReport.objects.filter(q, status="Success", analyzer__name__in=EXTRACTORS)
        .select_related("analyzer")
        .order_by("creation_date")
    )


def _report_parent(report):
    """(parent_type, parent_obj) the extractor report was filed against."""
    for field, ptype in _PARENT_TYPE_BY_FIELD.items():
        obj = getattr(report, field, None)
        if obj is not None:
            return ptype, obj
    return None, None


def ingest_derived_observables(case) -> int:
    if not get_config("derived_observables.enabled", True):
        return 0

    derived_children = {
        (d.child_type, d.child_id) for d in case.derived_observables.all()
    }
    processed_report_ids = set(
        case.derived_observables.values_list("source_report_id", flat=True)
    )
    new_jobs = 0

    for report in _finished_extractor_reports(case):
        if report.id in processed_report_ids:
            continue
        parent_type, parent = _report_parent(report)
        if parent is None:
            continue
        if (parent_type, parent.pk) in derived_children:
            continue  # 1-hop cap

        fn = EXTRACTORS[report.analyzer.name]
        for value, data_type in fn(report.report_full):
            reason = _blocked(value, data_type)
            if reason:
                logger.info("derived: skip %r (%s)", value, reason)
                continue
            obj = _resolve_observable(value, data_type)
            if obj is None:
                continue
            _attach_to_case(case, obj, data_type)
            _, created = case.derived_observables.get_or_create(
                source_report=report, child_type=data_type, child_id=obj.pk,
                defaults=dict(
                    via_analyzer=report.analyzer.name,
                    parent_type=parent_type, parent_id=parent.pk,
                    child_value=value[:512],
                ),
            )
            if not created:
                continue
            job_ids = CortexJob().launch_cortex_jobs(value=obj, data_type=data_type, case=case)
            new_jobs += len(job_ids or [])

    return new_jobs
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `... python manage.py test cortex_job.tests.test_ingest_derived_observables -v2`
Expected: PASS (5 tests). If `test_one_hop_cap` fails because `_report_parent` still sees the gen-1 child's report — confirm `AnalyzerReport.url` FK is populated in the test and that `derived_children` contains `("url", child.pk)`.

- [ ] **Step 5: Run the whole cortex_job suite**

Run: `... python manage.py test cortex_job`
Expected: PASS, no regressions.

- [ ] **Step 6: Commit**

```bash
git add cortex_job/cortex_utils/derived_observables.py cortex_job/tests/test_ingest_derived_observables.py
git commit -m "feat(cortex-job): ingest_derived_observables — create + dispatch + record provenance"
```

---

## Task 6: Wire into `reconcile_case_core`

**Files:**
- Modify: `cortex_job/cortex_utils/reconciliation.py:49-77`
- Test: `cortex_job/tests/test_reconcile_derived.py`

**Interfaces:**
- Consumes: `ingest_derived_observables(case) -> int`.

- [ ] **Step 1: Write the failing test**

```python
# cortex_job/tests/test_reconcile_derived.py
from unittest.mock import patch

from django.test import TestCase

from case_handler.lifecycle import LifecycleState
from case_handler.models import Case
from cortex_job.cortex_utils.reconciliation import reconcile_case_core


class ReconcileDerivedTests(TestCase):
    @patch("cortex_job.cortex_utils.reconciliation.ingest_derived_observables", return_value=2)
    @patch("cortex_job.cortex_utils.reconciliation.finalise")
    def test_case_stays_analyzing_when_derived_jobs_dispatched(self, m_finalise, _m_ingest):
        case = Case.objects.create(lifecycle_state=LifecycleState.ANALYZING)
        case.dispatched_at = case.creation_date
        case.save(update_fields=["dispatched_at"])
        reconcile_case_core(case)
        case.refresh_from_db()
        self.assertEqual(case.lifecycle_state, LifecycleState.ANALYZING)
        m_finalise.assert_not_called()

    @patch("cortex_job.cortex_utils.reconciliation.ingest_derived_observables", return_value=0)
    @patch("cortex_job.cortex_utils.reconciliation.finalise")
    def test_case_finalizes_when_nothing_more_to_ingest(self, m_finalise, _m_ingest):
        case = Case.objects.create(lifecycle_state=LifecycleState.ANALYZING)
        case.dispatched_at = case.creation_date
        case.save(update_fields=["dispatched_at"])
        reconcile_case_core(case)
        case.refresh_from_db()
        self.assertEqual(case.lifecycle_state, LifecycleState.FINALIZED)
        m_finalise.assert_called_once()
```

> Confirm no pending `CaseAnalyzerJob` rows exist for a bare `Case` (so `still_pending` is False) and that the `RECONCILE_DISPATCH_GRACE` check passes with `dispatched_at` set — read `reconcile_case_core` again and adjust the setup (e.g. back-date `creation_date`) if the grace window blocks finalize.

- [ ] **Step 2: Run test to verify it fails**

Run: `... python manage.py test cortex_job.tests.test_reconcile_derived -v2`
Expected: FAIL — `AttributeError: ... has no attribute 'ingest_derived_observables'` (patch target missing) or the ANALYZING test fails because finalize still runs.

- [ ] **Step 3: Wire it in**

```python
# cortex_job/cortex_utils/reconciliation.py
# add to imports:
from cortex_job.cortex_utils.derived_observables import ingest_derived_observables

# in reconcile_case_core, AFTER the `if still_pending:` block, BEFORE the
# `dispatched_at` grace check:
    if ingest_derived_observables(case) > 0:
        # extractors surfaced new indicators — they are now pending jobs;
        # the next reconcile pass (webhook or 300s poll) will carry on.
        return
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `... python manage.py test cortex_job.tests.test_reconcile_derived cortex_job.tests -v2`
Expected: PASS, no regressions in the reconciliation suite.

- [ ] **Step 5: Commit**

```bash
git add cortex_job/cortex_utils/reconciliation.py cortex_job/tests/test_reconcile_derived.py
git commit -m "feat(cortex-job): reconcile ingests derived observables before finalize"
```

---

## Task 7: `score_derived_observables` + IOC-road parent escalation

**Files:**
- Modify: `cortex_job/cortex_utils/derived_observables.py` (add `score_derived_observables`)
- Modify: `score_process/scoring/apply.py` (`finalise_ioc_group`)
- Test: `score_process/tests/test_derived_scoring.py`

**Interfaces:**
- Produces: `score_derived_observables(case) -> dict[tuple[str, int], tuple[str, str]]` — maps `(parent_type, parent_id)` → `(escalated_band, note)` for every derived observable that scored Suspicious/Dangerous above its parent's current band. Side effect: writes `child_band` + `escalation_note` on each `DerivedObservable` row.

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_derived_scoring.py
from django.test import TestCase

from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact, Result
from cortex_job.cortex_utils.derived_observables import score_derived_observables
from cortex_job.models import Analyzer, AnalyzerReport, DerivedObservable
from score_process.scoring.apply import finalise_ioc_group
from url_process.models import URL


def _report(analyzer, url, level, tier_name="VirusTotal_x"):
    return AnalyzerReport.objects.create(
        cortex_job_id=f"j{url.pk}-{level}", type="url", status="Success", analyzer=analyzer,
        url=url, level=level, confidence=90, score=9 if level == "malicious" else 0,
        report_summary={"taxonomies": [{"level": level}]}, report_taxonomy={}, report_full={},
    )


class DerivedScoringTests(TestCase):
    def setUp(self):
        self.group = ObservableGroup.objects.create(label="g")
        self.case = Case.objects.create(observable_group=self.group)
        self.parent = URL.objects.create(address="https://tinyurl.com/x")
        self.child = URL.objects.create(address="https://evil.example/login")
        ObservableGroupArtifact.objects.create(group=self.group, artifact_type="URL", url=self.parent)
        ObservableGroupArtifact.objects.create(group=self.group, artifact_type="URL", url=self.child)
        self.vt = Analyzer.objects.create(name="VirusTotal_GetReport_3_1",
                                          analyzer_cortex_id="VirusTotal_GetReport_3_1", tier=1)
        self.unshorten = Analyzer.objects.create(name="UnshortenLink_1_2",
                                                 analyzer_cortex_id="UnshortenLink_1_2")
        self.src = AnalyzerReport.objects.create(
            cortex_job_id="js", type="url", status="Success", analyzer=self.unshorten,
            url=self.parent, level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={"found": True, "url": self.child.address})
        DerivedObservable.objects.create(
            case=self.case, source_report=self.src, via_analyzer="UnshortenLink_1_2",
            parent_type="url", parent_id=self.parent.pk,
            child_type="url", child_id=self.child.pk, child_value=self.child.address)

    def test_malicious_child_yields_parent_escalation(self):
        _report(self.vt, self.child, "malicious")
        out = score_derived_observables(self.case)
        self.assertIn(("url", self.parent.pk), out)
        band, note = out[("url", self.parent.pk)]
        self.assertEqual(band, "Dangerous")
        self.assertIn("UnshortenLink_1_2", note)
        DerivedObservable.objects.get(pk=1).refresh_from_db()
        self.assertEqual(DerivedObservable.objects.get().child_band, "Dangerous")

    def test_safe_child_yields_nothing(self):
        _report(self.vt, self.child, "safe")
        self.assertEqual(score_derived_observables(self.case), {})

    def test_finalise_ioc_group_escalates_parent_and_group(self):
        _report(self.vt, self.child, "malicious")
        finalise_ioc_group(self.case)
        self.case.refresh_from_db()
        self.parent.refresh_from_db()
        self.assertEqual(self.parent.ioc_level, "malicious")
        self.assertEqual(self.case.results, Result.DANGEROUS)
        self.assertTrue(any("Escalated" in r for r in self.case.verdict_rationale))
```

> `score_observable`'s bands are `Dangerous/Suspicious/Safe/Inconclusive`. A single Tier-1 `malicious` with confidence ≥ 70 → `Dangerous` (engine Rule 1). Confirm against `score_process/scoring/observable_engine.py` and adjust `confidence`/`tier` in `_report` if the band comes out different.

- [ ] **Step 2: Run test to verify it fails**

Run: `... python manage.py test score_process.tests.test_derived_scoring -v2`
Expected: FAIL — `ImportError: cannot import name 'score_derived_observables'`

- [ ] **Step 3: Implement `score_derived_observables`**

```python
# cortex_job/cortex_utils/derived_observables.py — add
_BAND_RANK = {"Safe": 0, "Inconclusive": 0, "Suspicious": 1, "Dangerous": 2}
_IOC_LEVEL_TO_BAND = {"safe": "Safe", "info": "Inconclusive",
                      "suspicious": "Suspicious", "malicious": "Dangerous", "critical": "Dangerous"}


def _child_band(child_type, child_id) -> str:
    from cortex_job.models import AnalyzerReport
    from score_process.scoring.observable_engine import score_observable
    from score_process.scoring.sources import source_verdict_from_report
    reports = (AnalyzerReport.objects
               .filter(status="Success", **{f"{child_type}_id": child_id})
               .select_related("analyzer").order_by("-creation_date"))
    seen, svs = set(), []
    for r in reports:
        if r.analyzer_id in seen:
            continue
        seen.add(r.analyzer_id)
        svs.append(source_verdict_from_report(r))
    return score_observable(svs).band if svs else "Inconclusive"


def score_derived_observables(case) -> dict:
    out: dict = {}
    for d in case.derived_observables.all():
        band = _child_band(d.child_type, d.child_id)
        d.child_band = band
        note = ""
        parent_rank = _BAND_RANK.get(_parent_band(d), 0)
        if _BAND_RANK.get(band, 0) >= 1 and _BAND_RANK.get(band, 0) > parent_rank:
            note = (f"Escalated to {band}: {d.via_analyzer} extracted "
                    f"{d.child_value} → {band}.")
            out[(d.parent_type, d.parent_id)] = (band, note)
        d.escalation_note = note
        d.save(update_fields=["child_band", "escalation_note"])
    return out


def _parent_band(d) -> str:
    """Parent's current band. IOC road: from its URL/Domain ioc_level.
    Mail road: from MailArtifact.artifact_level."""
    spec = _MODEL_BY_TYPE.get(d.parent_type)
    if spec is None:
        return "Inconclusive"
    from importlib import import_module
    module, cls_name, _ = spec
    model = getattr(import_module(module), cls_name)
    obj = model.objects.filter(pk=d.parent_id).first()
    lvl = getattr(obj, "ioc_level", "info") if obj else "info"
    return _IOC_LEVEL_TO_BAND.get(str(lvl).lower(), "Inconclusive")
```

- [ ] **Step 4: Wire into `finalise_ioc_group`**

```python
# score_process/scoring/apply.py — in finalise_ioc_group, AFTER the
# `for (_art_type, _pk, obj), sources in per_obs.items():` loop that builds
# obs_verdicts and writes obj.ioc_*, and BEFORE `g = score_group(obs_verdicts)`:

    from cortex_job.cortex_utils.derived_observables import score_derived_observables
    escalations = score_derived_observables(case)
    if escalations:
        obj_by_key = {(_art.lower(), o.pk): (idx, o)
                      for idx, ((_art, _pk, o), _s) in enumerate(per_obs.items())}
        for (ptype, pid), (band, note) in escalations.items():
            hit = obj_by_key.get((ptype, pid))
            if hit is None:
                continue
            idx, obj = hit
            v = obs_verdicts[idx]
            if _BAND_ORDER_IDX(band) > _BAND_ORDER_IDX(v.band):
                obs_verdicts[idx] = ObservableVerdict(
                    band, v.confidence, None, v.counts, list(v.rationale) + [note])
                if obj.ioc_level not in _STICKY_IOC_LEVELS:
                    obj.ioc_level = _BAND_TO_IOC_LEVEL.get(band, "info")
                obj.ioc_score = _DERIVED_SCORE.get(band, 5)
                obj.save(update_fields=["ioc_level", "ioc_score"])
```

Add a tiny helper near the top of `apply.py`:

```python
_IOC_BAND_ORDER = {"Safe": 0, "Inconclusive": 0, "Suspicious": 1, "Dangerous": 2}
def _BAND_ORDER_IDX(band: str) -> int:
    return _IOC_BAND_ORDER.get(band, 0)
```

> `per_obs` is a dict — its iteration order is insertion order (Python 3.7+), and `obs_verdicts` is built in that same loop, so index `idx` lines up. Double-check by reading the current `finalise_ioc_group` loop; if it filters/reorders, switch to a `{(art_type, pk): verdict}` dict instead of a parallel list.

- [ ] **Step 5: Run tests to verify they pass**

Run: `... python manage.py test score_process.tests.test_derived_scoring score_process -v2`
Expected: PASS, no regressions in `score_process`.

- [ ] **Step 6: Commit**

```bash
git add cortex_job/cortex_utils/derived_observables.py score_process/scoring/apply.py score_process/tests/test_derived_scoring.py
git commit -m "feat(scoring): derived observable escalates its parent on the IOC road"
```

---

## Task 8: Mail-road parent escalation

**Files:**
- Modify: `score_process/scoring/engine.py` (`mail_band_escalation` rationale text)
- Modify: `score_process/scoring/cortex_analyzers/reports.py` (`get_report`, mail branch)
- Test: `score_process/tests/test_derived_scoring_mail.py`

**Interfaces:**
- Consumes: `score_derived_observables(case) -> dict`, `mail_band_escalation(verdict, embedded)`.

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_derived_scoring_mail.py
from datetime import datetime, timezone as tz
from django.test import TestCase

from case_handler.models import Case, CaseHasFileOrMail, Result
from cortex_job.models import Analyzer, AnalyzerReport, DerivedObservable
from mail_feeder.models import Mail, MailArtifact, ArtifactIsUrl
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports
from url_process.models import URL


class MailDerivedEscalationTests(TestCase):
    def setUp(self):
        self.mail = Mail.objects.create(subject="s", reportedBy="r@x.test",
            date=datetime(2026, 1, 1, tzinfo=tz.utc), to="a@x.test", mail_id="m1")
        self.case = Case.objects.create()
        self.case.fileOrMail = CaseHasFileOrMail.objects.create(mail=self.mail, case=self.case)
        self.case.save()
        self.parent = URL.objects.create(address="https://tinyurl.com/x")
        pj = ArtifactIsUrl.objects.create(url=self.parent,
             artifact=MailArtifact.objects.create(mail=self.mail, artifact_type="URL"))
        self.child = URL.objects.create(address="https://evil.example/login")
        cj = ArtifactIsUrl.objects.create(url=self.child,
             artifact=MailArtifact.objects.create(mail=self.mail, artifact_type="URL"))
        vt = Analyzer.objects.create(name="VirusTotal_GetReport_3_1",
             analyzer_cortex_id="VirusTotal_GetReport_3_1", tier=1)
        un = Analyzer.objects.create(name="UnshortenLink_1_2", analyzer_cortex_id="UnshortenLink_1_2")
        AnalyzerReport.objects.create(cortex_job_id="jc", type="url", status="Success",
            analyzer=vt, url=self.child, level="malicious", confidence=90, score=9,
            report_summary={"taxonomies": [{"level": "malicious"}]}, report_taxonomy={}, report_full={})
        src = AnalyzerReport.objects.create(cortex_job_id="js", type="url", status="Success",
            analyzer=un, url=self.parent, level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={"found": True, "url": self.child.address})
        DerivedObservable.objects.create(case=self.case, source_report=src,
            via_analyzer="UnshortenLink_1_2", parent_type="url", parent_id=self.parent.pk,
            child_type="url", child_id=self.child.pk, child_value=self.child.address)

    def test_mail_case_band_escalated_by_derived_url(self):
        CortexAnalyzerReports.get_report(self.case)
        self.case.refresh_from_db()
        self.assertEqual(self.case.results, Result.DANGEROUS)
        self.assertTrue(any("Escalated" in r or "embedded" in r
                            for r in self.case.verdict_rationale))
        parent_ma = MailArtifact.objects.get(artifactIsUrl__url=self.parent)
        self.assertEqual(parent_ma.artifact_level, "malicious")
```

> `get_report`'s mail branch runs `manage_ai_jobs` then `collect_signals`/`score_case`/`apply_verdict`. Read it and confirm where to slot the escalation call. `collect_signals` may need at least one mail-level signal to not short-circuit — if the test's verdict comes back `FAILURE` for lack of signals, add a benign mail-body/header `AnalyzerReport` in `setUp`.

- [ ] **Step 2: Run test to verify it fails**

Run: `... python manage.py test score_process.tests.test_derived_scoring_mail -v2`
Expected: FAIL — case not escalated / `artifact_level` still `info`.

- [ ] **Step 3: Implement**

In `score_process/scoring/engine.py`, change `mail_band_escalation` so the rationale line can carry detail:

```python
def mail_band_escalation(verdict, embedded, note: str = ""):
    ...
    line = note or f"Band raised to {worst} by an embedded indicator."
    return replace(verdict, result=worst, rationale=tuple(verdict.rationale) + (line,))
```

In `score_process/scoring/cortex_analyzers/reports.py`, mail branch of `get_report`, after `apply_verdict(case, verdict)`:

```python
            from cortex_job.cortex_utils.derived_observables import score_derived_observables
            escalations = score_derived_observables(case)
            if escalations:
                from score_process.scoring.engine import mail_band_escalation
                from score_process.scoring.observable_engine import ObservableVerdict
                worst_band = max((b for b, _n in escalations.values()),
                                 key=lambda b: {"Suspicious": 1, "Dangerous": 2}.get(b, 0))
                note = next(n for _b, n in escalations.values())
                embedded = [ObservableVerdict(worst_band, 100, None, {}, [])]
                verdict = mail_band_escalation(verdict, embedded, note=note)
                apply_verdict(case, verdict)
                # bump the parent MailArtifact level
                from mail_feeder.models import MailArtifact
                for (ptype, pid), (band, _n) in escalations.items():
                    ioc_level = {"Suspicious": "suspicious", "Dangerous": "malicious"}[band]
                    MailArtifact.objects.filter(**{f"artifactIs{ptype.capitalize()}__{ptype}_id": pid},
                                                mail=case.fileOrMail.mail).update(artifact_level=ioc_level)
```

> The `artifactIs{Type}` reverse-lookup kwarg must match `MailArtifact`'s FK names (`artifactIsUrl`, `artifactIsIp`, …) and the join model's observable FK. Verify against `mail_feeder/models.py` and fix the `filter(...)` kwargs. For `url` it is `artifactIsUrl__url_id=pid`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `... python manage.py test score_process.tests.test_derived_scoring_mail score_process -v2`
Expected: PASS, no regressions.

- [ ] **Step 5: Commit**

```bash
git add score_process/scoring/engine.py score_process/scoring/cortex_analyzers/reports.py score_process/tests/test_derived_scoring_mail.py
git commit -m "feat(scoring): derived observable escalates the mail case band"
```

---

## Task 9: API — expose `derived_from` / `escalation_note`

**Files:**
- Modify: `api/utils/observable_report.py` (`assemble_observables`)
- Test: `api/tests/test_observable_report_derived.py`

**Interfaces:**
- Produces: each observable dict from `assemble_observables` gains
  `"derived_from": {"value": str, "via_analyzer": str} | None` and
  `"escalation_note": str`.

- [ ] **Step 1: Write the failing test**

```python
# api/tests/test_observable_report_derived.py
from django.test import TestCase

from api.utils.observable_report import assemble_observables
from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from cortex_job.models import Analyzer, AnalyzerReport, DerivedObservable
from url_process.models import URL


class ObservableReportDerivedTests(TestCase):
    def test_child_row_has_derived_from_and_parent_has_note(self):
        group = ObservableGroup.objects.create(label="g")
        case = Case.objects.create(observable_group=group)
        parent = URL.objects.create(address="https://tinyurl.com/x")
        child = URL.objects.create(address="https://evil.example/login")
        for u in (parent, child):
            ObservableGroupArtifact.objects.create(group=group, artifact_type="URL", url=u)
        un = Analyzer.objects.create(name="UnshortenLink_1_2", analyzer_cortex_id="UnshortenLink_1_2")
        src = AnalyzerReport.objects.create(cortex_job_id="js", type="url", status="Success",
            analyzer=un, url=parent, level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={})
        DerivedObservable.objects.create(case=case, source_report=src, via_analyzer="UnshortenLink_1_2",
            parent_type="url", parent_id=parent.pk, child_type="url", child_id=child.pk,
            child_value=child.address, child_band="Dangerous",
            escalation_note="Escalated to Dangerous: UnshortenLink_1_2 extracted https://evil.example/login → Dangerous.")

        rows = {r["value"]: r for r in assemble_observables(case)}
        self.assertEqual(rows["https://evil.example/login"]["derived_from"],
                         {"value": "https://tinyurl.com/x", "via_analyzer": "UnshortenLink_1_2"})
        self.assertIn("Escalated", rows["https://tinyurl.com/x"]["escalation_note"])
        self.assertIsNone(rows["https://tinyurl.com/x"]["derived_from"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `... python manage.py test api.tests.test_observable_report_derived -v2`
Expected: FAIL — `KeyError: 'derived_from'`

- [ ] **Step 3: Implement**

```python
# api/utils/observable_report.py — in assemble_observables, before the loop:
    derived = {}       # (child_type, child_id) -> DerivedObservable
    escalation = {}    # (parent_type, parent_id) -> note
    for d in case.derived_observables.all():
        derived[(d.child_type, d.child_id)] = d
        if d.escalation_note:
            escalation[(d.parent_type, d.parent_id)] = d.escalation_note

# ... inside the loop, when building the observable dict:
        key = (art.artifact_type.lower(), obj.pk)
        d = derived.get(key)
        observables.append({
            ...
            "derived_from": ({"value": _parent_value(d), "via_analyzer": d.via_analyzer}
                             if d else None),
            "escalation_note": escalation.get(key, ""),
        })
```

with a helper:

```python
def _parent_value(d):
    from cortex_job.cortex_utils.derived_observables import _resolve_observable
    # _resolve_observable would create — instead do a plain lookup:
    from importlib import import_module
    from cortex_job.cortex_utils.derived_observables import _MODEL_BY_TYPE
    spec = _MODEL_BY_TYPE.get(d.parent_type)
    if not spec:
        return None
    module, cls_name, field = spec
    obj = getattr(import_module(module), cls_name).objects.filter(pk=d.parent_id).first()
    return getattr(obj, field, None) if obj else None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `... python manage.py test api.tests.test_observable_report_derived api.tests -v2`
Expected: PASS, no regressions.

- [ ] **Step 5: Commit**

```bash
git add api/utils/observable_report.py api/tests/test_observable_report_derived.py
git commit -m "feat(api): expose derived-observable provenance + escalation note"
```

---

## Task 10: Frontend — provenance chip + escalation note

**Files:**
- Modify: `suspicious-ui/src/features/investigation/observableGroup.ts` (types)
- Modify: `suspicious-ui/src/features/investigation/ObservableGroupPanel.tsx`
- Test: `suspicious-ui/src/features/investigation/__tests__/ObservableGroupPanel.test.tsx`

**Interfaces:**
- Consumes: `Observable.derived_from: { value: string; via_analyzer: string } | null` and `Observable.escalation_note: string` from the API (Task 9).

- [ ] **Step 1: Write the failing test**

```tsx
// add to ObservableGroupPanel.test.tsx
it("shows extraction provenance on a derived observable", () => {
  const group = makeGroup({
    observables: [
      { value: "https://tinyurl.com/x", type: "url", verdict: { band: "Dangerous", confidence: 80, rationale: [] }, sources: [],
        derived_from: null, escalation_note: "Escalated to Dangerous: UnshortenLink_1_2 extracted https://evil.example/login → Dangerous." },
      { value: "https://evil.example/login", type: "url", verdict: { band: "Dangerous", confidence: 90, rationale: [] }, sources: [],
        derived_from: { value: "https://tinyurl.com/x", via_analyzer: "UnshortenLink_1_2" }, escalation_note: "" },
    ],
  });
  render(<ObservableGroupPanel group={group} />);
  expect(screen.getByText(/extracted from/i)).toBeInTheDocument();
  expect(screen.getByText(/Escalated to Dangerous/)).toBeInTheDocument();
});
```

> Match `makeGroup` / render helper to whatever the existing test file uses. If the test file has no factory, mirror the shape from `observableGroup.ts`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd suspicious-ui && pnpm test -- ObservableGroupPanel`
Expected: FAIL — text not found.

- [ ] **Step 3: Implement**

In `observableGroup.ts`, add to the `Observable` type:

```ts
  derived_from: { value: string; via_analyzer: string } | null;
  escalation_note: string;
```

In `ObservableGroupPanel.tsx`, in the per-observable render:

```tsx
{observable.derived_from && (
  <Chip size="small" variant="outlined"
        label={`⛓ extracted from ${observable.derived_from.value} via ${observable.derived_from.via_analyzer}`} />
)}
{observable.escalation_note && (
  <Typography variant="caption" color="warning.main">{observable.escalation_note}</Typography>
)}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd suspicious-ui && pnpm test -- ObservableGroupPanel && pnpm lint`
Expected: PASS, lint clean.

- [ ] **Step 5: Commit**

```bash
git add suspicious-ui/src/features/investigation/
git commit -m "feat(ui): show derived-observable provenance + escalation note"
```

---

## Task 11: End-to-end verification on the dev stack

**Files:** none (verification only)

- [ ] **Step 1: Redeploy the branch**

Follow `CLAUDE.md` `/deploy-full-e2e` (or `cd deployment && make deploy` if the stack is already up), then `./scripts/enable-dev-analyzers.sh`.

- [ ] **Step 2: UnshortenLink path**

Submit (bulk IOC) a live shortener URL that resolves to something with reputation (e.g. a `bit.ly` you create pointing at a known-bad test host, or an existing one). Wait for finalize. Confirm via `manage.py shell`:
```python
from case_handler.models import Case
c = Case.objects.latest("id")
print(c.results, c.verdict_rationale)
print(list(c.derived_observables.values("via_analyzer", "child_value", "child_band", "escalation_note")))
```
Expected: a `DerivedObservable` row for the unshortened URL; if it scored ≥ Suspicious, an `escalation_note` and the parent short-link observable raised.

- [ ] **Step 3: QrDecode path**

Build a small email with a PNG attachment containing a QR code that encodes a URL (`python -c "import qrcode; qrcode.make('https://example.com/phish').save('/tmp/qr.png')"`), send it through greenmail, wait for the feeder + finalize. Confirm a `DerivedObservable` (via `QrDecode_1_0`) for the decoded URL and that it got its own analyzer reports.

- [ ] **Step 4: 1-hop cap**

Confirm no `DerivedObservable` whose `parent` is itself another row's `child` (should be impossible by construction):
```python
from cortex_job.models import DerivedObservable
children = {(d.child_type, d.child_id) for d in DerivedObservable.objects.all()}
parents = {(d.parent_type, d.parent_id) for d in DerivedObservable.objects.all()}
print("overlap:", children & parents)   # expect set()
```

- [ ] **Step 5: Kill switch**

Set `derived_observables.enabled = false` in `Suspicious/settings.json`, `make deploy` (or recreate `suspicious` + `suspicious_celery`), re-submit a shortener, confirm no new `DerivedObservable` rows.

- [ ] **Step 6: Full backend suite**

Run: `cd deployment && docker compose --env-file .env run --rm --no-deps -v $PWD/../Suspicious/Suspicious:/app -w /app suspicious python manage.py test`
Expected: green (previous baseline + the new tests).

- [ ] **Step 7: Commit any fixes found during verification, then update the spec + audit doc**

```bash
# mark Phase B done in docs/specs/2026-09-07-analyzer-taxonomy-audit.md
git add docs/ && git commit -m "docs: mark derived-observables Phase B complete"
```

---

## Self-Review Notes (for the planner, not the executor)

- **Spec coverage:** registry (T2), model (T1), SSRF/allow-list gate (T3), attach both roads (T4), ingest + 1-hop + idempotency + kill switch (T5), reconcile wiring / no lifecycle re-open (T6), IOC escalation + note (T7), mail escalation + `mail_band_escalation` wiring (T8), API fields (T9), frontend (T10), config default (T5 — `get_config` fallback, no seed needed), rollout/e2e (T11). `auto_extract_artifacts` unchanged — no task, correct.
- **Known soft spots the executor must resolve by reading code first** (flagged inline at each task): exact `ArtifactIs*` FK/join field names (T4, T8); `finalise_ioc_group`'s loop shape for the parallel-index assumption (T7); whether `collect_signals` needs a seed signal for the mail test (T8); `AllowListDomain` field name (T3).
