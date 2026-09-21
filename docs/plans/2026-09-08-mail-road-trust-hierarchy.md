# Mail-road Trust Hierarchy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A mail case's embedded observables (its URLs / IPs / domains / hashes) are scored by the trust-weighted `score_observable` engine the IOC road already uses, then merged into the mail verdict via `mail_band_escalation` — so a Tier-1 GTI/VT verdict outweighs Tier-3 OSINT noise on the mail road too.

**Architecture:** Split mail scoring in two. Mail-intrinsic analyzers (AI/YARA/sandbox/header/attachment-file) keep the weighted `score_case` path. Embedded observables move to a per-observable `score_observable` pass whose `ObservableVerdict`s feed `mail_band_escalation`. Phase B's derived-observable escalation becomes a strict subset of this unified path.

**Tech Stack:** Django 6, MariaDB, pytest via `manage.py test`. No migration, no new dependency.

**Spec:** `docs/specs/2026-09-08-mail-road-trust-hierarchy-design.md`

## Global Constraints

- No change to `score_observable` **rules** or the IOC-group road (`finalise_ioc_group`).
- No schema change; no new Cortex analyzer.
- `score_process` full suite must stay green; the labelled accuracy harness (`manage.py score_accuracy`, `test_score_accuracy.py`) must stay 5/5 aligned (it tests `score_observable` directly — untouched here, so this is a smoke check).
- Behaviour-preserving refactors (Tasks 1, 2) must not change any existing test's expected values.
- Kill switch: `get_config("scoring.mail_embedded_categorical", True)` — ON = new path, OFF = pre-change behaviour (embedded IOCs scored through `score_case`, only Phase-B derived escalation applied).
- Run tests in the repo (this is `design/ioc-road-and-verdict-model`, main checkout — no worktree needed unless the executor chooses one):
  `cd deployment && docker compose --env-file .env run --rm --no-deps -v $PWD/../Suspicious/Suspicious:/app -w /app suspicious python manage.py test <label>`
- Commit messages: Conventional Commits; footer:
  `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>` then
  `Claude-Session: https://claude.ai/code/session_013EzA3TMGhR137KyAqF9aTf`

## File Structure

| File | Responsibility |
|---|---|
| `score_process/scoring/bands.py` | **new** — the band-vocabulary maps shared by the IOC road, Phase B, and this change (`_BAND_RANK`, `_BAND_ORDER`, `_BAND_TO_IOC_LEVEL`, `_DERIVED_SCORE`, `_STICKY_IOC_LEVELS`) |
| `score_process/scoring/apply.py` | repoint to `bands.py` (delete the local copies) |
| `score_process/scoring/observable_collect.py` | extract `_bucket_reports(triples)`; add `mail_observable_reports(mail)` |
| `score_process/scoring/processing.py` | `process_mail(..., score_artifacts=True)` — skip the `mail_artifacts` scoring loop when `False` |
| `score_process/scoring/collect.py` | pass `score_artifacts=False` for a mail case when the flag is ON |
| `score_process/scoring/cortex_analyzers/reports.py` | replace `_apply_derived_escalation` with `_apply_embedded_escalation` |
| `score_process/scoring/engine.py` | `mail_band_escalation` — lift `final_confidence` when an embedded verdict is decisively worse (gated on the backtest) |

Tests: `score_process/tests/` (`test_observable_collect_mail.py` new; extend `test_collect.py`, `test_get_report.py`, `test_derived_scoring_mail.py`, `test_mail_escalation.py`, `test_processing_query_count.py`).

---

## Task 1: `bands.py` shared band-vocabulary module

**Files:**
- Create: `score_process/scoring/bands.py`
- Modify: `score_process/scoring/apply.py:12-22`
- Test: `score_process/tests/test_bands.py`

**Interfaces:**
- Produces: `bands._BAND_RANK`, `bands._BAND_ORDER`, `bands._BAND_TO_IOC_LEVEL`, `bands._DERIVED_SCORE`, `bands._STICKY_IOC_LEVELS`.

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_bands.py
from django.test import SimpleTestCase

from score_process.scoring import bands


class BandsModuleTests(SimpleTestCase):
    def test_maps_have_the_four_bands(self):
        for m in (bands._BAND_TO_IOC_LEVEL, bands._DERIVED_SCORE):
            self.assertEqual(
                set(m) & {"Safe", "Suspicious", "Dangerous", "Inconclusive"},
                {"Safe", "Suspicious", "Dangerous", "Inconclusive"},
            )

    def test_band_to_ioc_level_values(self):
        self.assertEqual(bands._BAND_TO_IOC_LEVEL["Dangerous"], "malicious")
        self.assertEqual(bands._BAND_TO_IOC_LEVEL["Safe"], "safe")
        self.assertEqual(bands._BAND_TO_IOC_LEVEL["Inconclusive"], "info")

    def test_sticky_set(self):
        self.assertIn("SAFE-ALLOW_LISTED", bands._STICKY_IOC_LEVELS)
        self.assertIn("critical", bands._STICKY_IOC_LEVELS)

    def test_rank_orders_dangerous_highest(self):
        self.assertGreater(bands._BAND_RANK["Dangerous"], bands._BAND_RANK["Suspicious"])
        self.assertEqual(bands._BAND_RANK["Safe"], bands._BAND_RANK["Inconclusive"])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `... python manage.py test score_process.tests.test_bands -v2`
Expected: FAIL — `ModuleNotFoundError: score_process.scoring.bands`

- [ ] **Step 3: Create the module**

```python
# score_process/scoring/bands.py
"""Categorical-band vocabulary shared across the scoring roads.

The IOC road (apply.finalise_ioc_group), the derived-observable escalation
(cortex_job.cortex_utils.derived_observables), and the mail-road embedded
escalation all map the same four ObservableVerdict bands onto scores, the
legacy IOC-level vocabulary, and a rank. One home so a change propagates.
"""
from __future__ import annotations

# ObservableVerdict.band -> comparable rank (Safe and Inconclusive tie low).
_BAND_RANK = {"Safe": 0, "Inconclusive": 0, "Suspicious": 1, "Dangerous": 2}

# worst-of ordering when picking the dominant embedded verdict.
_BAND_ORDER = {"Safe": 0, "Inconclusive": 1, "Suspicious": 2, "Dangerous": 3}

# band -> legacy ioc_level string that admin filters + cross-case reuse read.
_BAND_TO_IOC_LEVEL = {
    "Safe": "safe", "Inconclusive": "info",
    "Suspicious": "suspicious", "Dangerous": "malicious",
}

# band -> the 0-10 numeric score persisted on the observable / artifact rows.
_DERIVED_SCORE = {"Safe": 2, "Suspicious": 6, "Dangerous": 9, "Inconclusive": 5}

# ioc_level markers set by the deny/allow-list paths — never overwritten by a
# categorical re-score.
_STICKY_IOC_LEVELS = {"critical", "SAFE-ALLOW_LISTED"}
```

- [ ] **Step 4: Repoint `apply.py`**

In `score_process/scoring/apply.py`, delete the local `_DERIVED_SCORE`, `_BAND_TO_IOC_LEVEL`, `_STICKY_IOC_LEVELS`, `_IOC_BAND_ORDER`/`_BAND_ORDER_IDX` (whatever the current names are — read the file) and the `from cortex_job.cortex_utils.derived_observables import _BAND_RANK` line, replacing with:

```python
from score_process.scoring.bands import (
    _BAND_RANK, _BAND_TO_IOC_LEVEL, _DERIVED_SCORE, _STICKY_IOC_LEVELS,
)
```

If `apply.py` used a helper `_BAND_ORDER_IDX(band)`, replace its body with `bands._BAND_ORDER.get(band, 0)` or import `_BAND_ORDER` and index it. Keep call sites identical.

Also update `cortex_job/cortex_utils/derived_observables.py`: its local `_BAND_RANK` / `_IOC_LEVEL_TO_BAND` — repoint `_BAND_RANK` to `bands`; leave `_IOC_LEVEL_TO_BAND` (it is the inverse map, only used there) unless trivial to move.

- [ ] **Step 5: Run tests**

Run: `... python manage.py test score_process.tests.test_bands score_process.tests.test_apply score_process.tests.test_derived_scoring cortex_job -v1`
Expected: PASS, no expected-value changes anywhere.

- [ ] **Step 6: Commit**

```bash
git add score_process/scoring/bands.py score_process/scoring/apply.py Suspicious/Suspicious/cortex_job/cortex_utils/derived_observables.py score_process/tests/test_bands.py
git commit -m "refactor(score): lift shared band-vocabulary maps into scoring/bands.py"
```

---

## Task 2: Extract `_bucket_reports` from `observable_reports`

**Files:**
- Modify: `score_process/scoring/observable_collect.py`
- Test: `score_process/tests/test_observable_collect_bucket.py`

**Interfaces:**
- Produces: `_bucket_reports(triples: list[tuple]) -> dict[key, list[AnalyzerReport]]` where each triple is `(key, obj, field)`, `field ∈ {"url","ip","hash","domain","mail"}`. Handles the `analyzed_url` representative fold for `field == "url"`. One `AnalyzerReport` query. Reports newest first.
- `observable_reports(case)` unchanged externally — now a thin caller.

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_observable_collect_bucket.py
from django.test import TestCase

from cortex_job.models import Analyzer, AnalyzerReport
from score_process.scoring.observable_collect import _bucket_reports
from url_process.models import URL


class BucketReportsTests(TestCase):
    def setUp(self):
        self.a = Analyzer.objects.create(name="X", analyzer_cortex_id="X")
        self.u1 = URL.objects.create(address="https://a.test/")
        self.u2 = URL.objects.create(address="https://b.test/")

    def _rep(self, url, cid):
        return AnalyzerReport.objects.create(
            cortex_job_id=cid, type="url", status="Success", analyzer=self.a,
            url=url, level="info", confidence=0, score=0,
            report_summary={}, report_taxonomy={}, report_full={})

    def test_buckets_by_fk_id(self):
        r1, r2 = self._rep(self.u1, "j1"), self._rep(self.u2, "j2")
        out = _bucket_reports([("k1", self.u1, "url"), ("k2", self.u2, "url")])
        self.assertEqual([r.id for r in out["k1"]], [r1.id])
        self.assertEqual([r.id for r in out["k2"]], [r2.id])

    def test_analyzed_url_representative_folds_in(self):
        self.u2.analyzed_url = self.u1
        self.u2.save(update_fields=["analyzed_url"])
        r_rep = self._rep(self.u1, "jrep")
        out = _bucket_reports([("k2", self.u2, "url")])
        self.assertIn(r_rep.id, [r.id for r in out["k2"]])

    def test_one_query(self):
        self._rep(self.u1, "j1")
        with self.assertNumQueries(1):
            _bucket_reports([("k1", self.u1, "url")])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `... python manage.py test score_process.tests.test_observable_collect_bucket -v2`
Expected: FAIL — `cannot import name '_bucket_reports'`

- [ ] **Step 3: Refactor**

Read the current `observable_reports`. Move its middle (from building `pk_to_key` / `targets` through the `buckets` dict) into:

```python
def _bucket_reports(triples: list[tuple]) -> dict:
    """triples: (key, obj, field). One AnalyzerReport query, bucketed by FK id,
    newest first, folding each URL's analyzed_url representative into the same
    key. Returns {key: [AnalyzerReport, ...]}."""
    from cortex_job.models import AnalyzerReport
    from cortex_job.cortex_utils.case_targets import build_analyzer_report_filter

    if not triples:
        return {}
    pk_to_key: dict[tuple, object] = {}
    targets = []
    for (key, obj, field) in triples:
        pk_to_key[(field, obj.pk)] = key
        targets.append((obj, field))
        rep = getattr(obj, "analyzed_url", None) if field == "url" else None
        if rep is not None:
            pk_to_key[(field, rep.pk)] = key
            targets.append((rep, field))

    q = build_analyzer_report_filter(targets)
    reports = list(AnalyzerReport.objects.filter(q).select_related("analyzer")
                   .order_by("-creation_date"))
    fields = {f for (_k, _o, f) in triples}
    buckets: dict = {}
    for r in reports:
        for field in fields:
            rid = getattr(r, f"{field}_id", None)
            key = pk_to_key.get((field, rid)) if rid else None
            if key is not None:
                buckets.setdefault(key, []).append(r)
                break
    return buckets
```

`observable_reports(case)` becomes:

```python
def observable_reports(case) -> list[tuple]:
    arts = []
    for art in case.observable_group.artifacts.select_related(
        "url", "url__analyzed_url", "ip", "hash", "domain"
    ):
        field = _FIELD[art.artifact_type]
        obj = getattr(art, field)
        if obj is not None:
            arts.append((art, obj, field))
    if not arts:
        return []
    buckets = _bucket_reports([((f, o.pk), o, f) for (_a, o, f) in arts])
    return [(art, obj, field, buckets.get((field, obj.pk), []))
            for (art, obj, field) in arts]
```

- [ ] **Step 4: Run tests**

Run: `... python manage.py test score_process.tests.test_observable_collect_bucket score_process.tests.test_observable_engine score_process.tests.test_ioc_road_scoring score_process.tests.test_processing_query_count -v1`
Expected: PASS. The existing IOC-road tests must not change.

- [ ] **Step 5: Commit**

```bash
git add score_process/scoring/observable_collect.py score_process/tests/test_observable_collect_bucket.py
git commit -m "refactor(score): extract _bucket_reports from observable_reports"
```

---

## Task 3: `mail_observable_reports(mail)`

**Files:**
- Modify: `score_process/scoring/observable_collect.py`
- Test: `score_process/tests/test_observable_collect_mail.py`

**Interfaces:**
- Consumes: `_bucket_reports` (Task 2).
- Produces: `mail_observable_reports(mail) -> list[tuple]` — `(mail_artifact, obj, field, [reports])` per embedded observable of a mail (`URL`/`IP`/`Hash`/`Domain`/`MailAddress`). One `AnalyzerReport` query.

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_observable_collect_mail.py
from datetime import datetime, timezone as tz

from django.test import TestCase

from cortex_job.models import Analyzer, AnalyzerReport
from mail_feeder.models import Mail, MailArtifact, ArtifactIsUrl, ArtifactIsIp
from score_process.scoring.observable_collect import mail_observable_reports
from url_process.models import URL
from ip_process.models import IP


class MailObservableReportsTests(TestCase):
    def setUp(self):
        self.mail = Mail.objects.create(
            subject="s", reportedBy="r@x.test",
            date=datetime(2026, 1, 1, tzinfo=tz.utc), to="a@x.test", mail_id="m1")
        self.a = Analyzer.objects.create(name="GTI", analyzer_cortex_id="GTI", tier=1)
        self.url = URL.objects.create(address="https://evil.test/x")
        self.ip = IP.objects.create(address="1.2.3.4")
        ArtifactIsUrl.objects.create(
            url=self.url,
            artifact=MailArtifact.objects.create(mail=self.mail, artifact_type="URL"))
        ArtifactIsIp.objects.create(
            ip=self.ip,
            artifact=MailArtifact.objects.create(mail=self.mail, artifact_type="IP"))

    def _rep(self, **kw):
        return AnalyzerReport.objects.create(
            cortex_job_id=kw["cid"], type=kw["t"], status="Success", analyzer=self.a,
            level="malicious", confidence=90, score=9,
            report_summary={}, report_taxonomy={}, report_full={},
            **{kw["t"]: kw["obj"]})

    def test_yields_one_row_per_embedded_observable_with_its_reports(self):
        r = self._rep(cid="j1", t="url", obj=self.url)
        rows = {obj.pk: reps for (_a, obj, _f, reps) in mail_observable_reports(self.mail)}
        self.assertEqual([x.id for x in rows[self.url.pk]], [r.id])
        self.assertEqual(rows[self.ip.pk], [])

    def test_single_query_for_reports(self):
        self._rep(cid="j1", t="url", obj=self.url)
        # setUp objects already fetched; the walk + one report query:
        with self.assertNumQueries(2):     # mail_artifacts walk + _bucket_reports
            list(mail_observable_reports(self.mail))
```

> Verify `ArtifactIsUrl` / `ArtifactIsIp` field + `artifact` back-ref names against `mail_feeder/models.py` (Phase B's `_MAIL_JOIN` table has them: `url`/`ip`/`hash`/`domain`/`mail_address`). Adjust the `assertNumQueries` count to what the implementation actually does.

- [ ] **Step 2: Run test to verify it fails**

Run: `... python manage.py test score_process.tests.test_observable_collect_mail -v2`
Expected: FAIL — `cannot import name 'mail_observable_reports'`

- [ ] **Step 3: Implement**

```python
# score_process/scoring/observable_collect.py — add

_MAIL_ART = {                       # MailArtifact.artifact_type -> (fk attr, join field, bucket field)
    "URL": ("artifactIsUrl", "url", "url"),
    "IP": ("artifactIsIp", "ip", "ip"),
    "Hash": ("artifactIsHash", "hash", "hash"),
    "Domain": ("artifactIsDomain", "domain", "domain"),
    "MailAddress": ("artifactIsMailAddress", "mail_address", "mail"),
}


def mail_observable_reports(mail) -> list[tuple]:
    arts = []
    qs = mail.mail_artifacts.select_related(
        "artifactIsUrl__url", "artifactIsUrl__url__analyzed_url",
        "artifactIsIp__ip", "artifactIsHash__hash",
        "artifactIsDomain__domain", "artifactIsMailAddress__mail_address",
    )
    for m_art in qs:
        spec = _MAIL_ART.get(m_art.artifact_type)
        if spec is None:
            continue
        fk_attr, join_field, field = spec
        join = getattr(m_art, fk_attr, None)
        obj = getattr(join, join_field, None) if join else None
        if obj is not None:
            arts.append((m_art, obj, field))
    if not arts:
        return []
    buckets = _bucket_reports([((f, o.pk), o, f) for (_m, o, f) in arts])
    return [(m_art, obj, field, buckets.get((field, obj.pk), []))
            for (m_art, obj, field) in arts]
```

`_FIELD` in `_bucket_reports` uses `field` strings directly (`getattr(r, f"{field}_id")`) — for `mail` that is `AnalyzerReport.mail_id` (the `MailAddress` FK), which exists. Confirm.

- [ ] **Step 4: Run tests**

Run: `... python manage.py test score_process.tests.test_observable_collect_mail score_process.tests.test_observable_collect_bucket -v2`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add score_process/scoring/observable_collect.py score_process/tests/test_observable_collect_mail.py
git commit -m "feat(score): mail_observable_reports — per-embedded-observable analyzer reports for a mail"
```

---

## Task 4: `process_mail` opt-out + `collect_signals` stops feeding embedded IOCs to `score_case`

**Files:**
- Modify: `score_process/scoring/processing.py` (`process_mail`)
- Modify: `score_process/scoring/collect.py` (`collect_signals`)
- Test: extend `score_process/tests/test_collect.py`, `score_process/tests/test_processing.py`

**Interfaces:**
- `process_mail(mail, reports, total_scores, total_confidences, is_malicious, case_id, *, score_artifacts: bool = True)` — when `False`, the `mail_artifacts` loop is skipped entirely (no `process_mail_artifact` call).
- `collect_signals(case)` — for a mail case, calls `process_mail(..., score_artifacts=not get_config("scoring.mail_embedded_categorical", True))`.

- [ ] **Step 1: Write the failing test**

```python
# add to score_process/tests/test_collect.py
from unittest.mock import patch

class MailEmbeddedSignalOptOutTests(TestCase):
    """When scoring.mail_embedded_categorical is ON (default), an embedded
    URL's analyzer score must NOT appear among the Signals fed to score_case —
    it is scored by the categorical path instead."""

    def _mail_case_with_embedded_bad_url(self):
        from datetime import datetime, timezone as tz
        from django.contrib.auth import get_user_model
        from case_handler.models import Case, CaseHasFileOrMail
        from cortex_job.models import Analyzer, AnalyzerReport
        from mail_feeder.models import Mail, MailArtifact, ArtifactIsUrl, MailBody
        from url_process.models import URL

        u = get_user_model().objects.create_user("r", "", "x")
        mail = Mail.objects.create(subject="s", reportedBy="r@x.test",
            date=datetime(2026, 1, 1, tzinfo=tz.utc), to="a@x.test", mail_id="m1")
        case = Case.objects.create(description="", reporter=u)
        case.fileOrMail = CaseHasFileOrMail.objects.create(mail=mail, case=case)
        case.save()
        url = URL.objects.create(address="https://evil.test/login")
        ArtifactIsUrl.objects.create(url=url,
            artifact=MailArtifact.objects.create(mail=mail, artifact_type="URL"))
        a = Analyzer.objects.create(name="GTI", analyzer_cortex_id="GTI", tier=1)
        AnalyzerReport.objects.create(cortex_job_id="ju", type="url", status="Success",
            analyzer=a, url=url, level="malicious", confidence=95, score=9,
            report_summary={"taxonomies": [{"level": "malicious"}]}, report_taxonomy={}, report_full={})
        # a benign mail_body report so score_case has an intrinsic signal
        body = MailBody.objects.create(body_score=2, body_confidence=60, body_level="safe",
            body_value="hi", fuzzy_hash="bh")
        mail.mail_body = body; mail.save(update_fields=["mail_body"])
        AnalyzerReport.objects.create(cortex_job_id="jb", type="mail_body", status="Success",
            analyzer=Analyzer.objects.create(name="Yara_Boosted_3_2", analyzer_cortex_id="Yara_Boosted_3_2", tier=2),
            mail_body=body, level="safe", confidence=60, score=2,
            report_summary={}, report_taxonomy={}, report_full={})
        return case

    @patch("score_process.scoring.collect.get_config", return_value=True)
    def test_embedded_url_score_not_in_signals(self, _cfg):
        case = self._mail_case_with_embedded_bad_url()
        signals, *_ = collect_signals(case)
        # the only non-failure signals come from mail body/header, not the URL:
        self.assertTrue(all(s.source in {"mail", "file"} for s in signals if not s.is_failure))
        self.assertLessEqual(sum(1 for s in signals if not s.is_failure), 2)

    @patch("score_process.scoring.collect.get_config", return_value=False)
    def test_flag_off_keeps_embedded_url_in_signals(self, _cfg):
        case = self._mail_case_with_embedded_bad_url()
        signals, *_ = collect_signals(case)
        self.assertTrue(any(s.score >= 8 for s in signals))  # the bad URL still votes
```

- [ ] **Step 2: Run test to verify it fails**

Run: `... python manage.py test score_process.tests.test_collect.MailEmbeddedSignalOptOutTests -v2`
Expected: FAIL — `process_mail() got an unexpected keyword argument 'score_artifacts'` (or the URL score is still in signals).

- [ ] **Step 3: Implement**

In `processing.py::process_mail`, add the keyword-only param and guard the artifacts loop:

```python
def process_mail(mail, reports, total_scores, total_confidences, is_malicious,
                 case_id, *, score_artifacts: bool = True):
    ...
    if score_artifacts and hasattr(mail, "mail_artifacts"):
        update_cases_logger.info("Processing mail artifacts.")
        for artifact in mail.mail_artifacts.all():
            total_failures += log_and_process(
                artifact, process_mail_artifact, "artifact %s" % artifact.id,
                reports, total_scores, total_confidences, is_malicious, case_id,
            )
```

In `collect.py::collect_signals`, mail branch:

```python
from settings.config import get_config
...
        mail = getattr(case.fileOrMail, "mail", None)
        if mail:
            off = len(scores)
            score_artifacts = not get_config("scoring.mail_embedded_categorical", True)
            failures += process_mail(mail, reports, scores, confidences, 0, case.id,
                                     score_artifacts=score_artifacts)
            signals += _signals_from(scores, confidences, off, "mail")
```

- [ ] **Step 4: Run tests**

Run: `... python manage.py test score_process.tests.test_collect score_process.tests.test_processing score_process.tests.test_get_report -v1`
Expected: PASS. `test_get_report` mail-case verdicts may shift — see Task 5, which lands the categorical path in the same series; if a `test_get_report` case goes Inconclusive here (URL badness removed, escalation not yet wired), mark it `@expectedFailure` with a `# unblocked by Task 5` note and remove the marker in Task 5.

- [ ] **Step 5: Commit**

```bash
git add score_process/scoring/processing.py score_process/scoring/collect.py score_process/tests/test_collect.py
git commit -m "feat(score): mail embedded observables opt out of the score_case signal set"
```

---

## Task 5: `_apply_embedded_escalation` — the categorical merge

**Files:**
- Modify: `score_process/scoring/cortex_analyzers/reports.py`
- Test: `score_process/tests/test_derived_scoring_mail.py` (rename intent → mail embedded escalation), new cases in a `test_mail_embedded_escalation.py`

**Interfaces:**
- Consumes: `mail_observable_reports` (Task 3), `score_observable`, `source_verdict_from_report`, `mail_band_escalation`, `bands` maps, `get_config`.
- Produces: `_apply_embedded_escalation(case, mail, verdict) -> CaseVerdict` — replaces `_apply_derived_escalation`. Scores every embedded observable via `score_observable`, writes its `ioc_*` (global) and `MailArtifact.artifact_*` (case-scoped) fields, and raises the mail band to the worst embedded band with the analyzers' rationale.

- [ ] **Step 1: Write the failing test**

```python
# score_process/tests/test_mail_embedded_escalation.py
from datetime import datetime, timezone as tz
from django.contrib.auth import get_user_model
from django.test import TestCase

from case_handler.models import Case, CaseHasFileOrMail, Result
from cortex_job.models import Analyzer, AnalyzerReport
from mail_feeder.models import Mail, MailArtifact, ArtifactIsUrl
from score_process.scoring.cortex_analyzers.reports import CortexAnalyzerReports
from url_process.models import URL


class MailEmbeddedEscalationTests(TestCase):
    def setUp(self):
        u = get_user_model().objects.create_user("r", "", "x")
        self.mail = Mail.objects.create(subject="s", reportedBy="r@x.test",
            date=datetime(2026, 1, 1, tzinfo=tz.utc), to="a@x.test", mail_id="m1")
        self.case = Case.objects.create(description="", reporter=u)
        self.case.fileOrMail = CaseHasFileOrMail.objects.create(mail=self.mail, case=self.case)
        self.case.save()
        self.url = URL.objects.create(address="https://evil.test/login")
        ArtifactIsUrl.objects.create(url=self.url,
            artifact=MailArtifact.objects.create(mail=self.mail, artifact_type="URL"))
        self.gti = Analyzer.objects.create(name="GoogleThreatIntelligence_GetReport",
            analyzer_cortex_id="GoogleThreatIntelligence_GetReport", tier=1)
        self.urlscan = Analyzer.objects.create(name="Urlscan_io_Search_0_1_1",
            analyzer_cortex_id="Urlscan_io_Search_0_1_1", tier=3)

    def _rep(self, analyzer, level, conf, score):
        return AnalyzerReport.objects.create(
            cortex_job_id=f"j{analyzer.pk}", type="url", status="Success",
            analyzer=analyzer, url=self.url, level=level, confidence=conf, score=score,
            report_summary={"taxonomies": [{"level": level}]}, report_taxonomy={}, report_full={})

    def _verdict(self, band):
        from score_process.scoring.engine import CaseVerdict
        return CaseVerdict(final_score=2, final_confidence=30, result=band,
                           n_malicious=0, n_scored=1)

    def test_tier1_malicious_url_escalates_inconclusive_mail_to_dangerous(self):
        self._rep(self.gti, "malicious", 95, 9)
        self._rep(self.urlscan, "suspicious", 60, 6)
        v = CortexAnalyzerReports._apply_embedded_escalation(
            self.case, self.mail, self._verdict(Result.INCONCLUSIVE))
        self.assertEqual(v.result, Result.DANGEROUS)
        self.assertTrue(any("authoritative" in r.lower() or "GoogleThreatIntelligence" in r
                            for r in v.rationale))
        ma = MailArtifact.objects.get(artifactIsUrl__url=self.url)
        self.assertEqual(ma.artifact_level, "malicious")
        self.url.refresh_from_db()
        self.assertEqual(self.url.ioc_level, "malicious")

    def test_tier1_clean_beats_tier3_suspicious_no_escalation(self):
        self._rep(self.gti, "safe", 95, 0)
        self._rep(self.urlscan, "suspicious", 60, 6)
        v = CortexAnalyzerReports._apply_embedded_escalation(
            self.case, self.mail, self._verdict(Result.SAFE))
        self.assertEqual(v.result, Result.SAFE)

    def test_no_embedded_reports_returns_verdict_untouched(self):
        v_in = self._verdict(Result.SAFE)
        self.assertIs(
            CortexAnalyzerReports._apply_embedded_escalation(self.case, self.mail, v_in),
            v_in)

    def test_sticky_mail_artifact_keeps_its_level(self):
        MailArtifact.objects.filter(artifactIsUrl__url=self.url).update(artifact_level="SAFE-ALLOW_LISTED")
        self._rep(self.gti, "malicious", 95, 9)
        CortexAnalyzerReports._apply_embedded_escalation(
            self.case, self.mail, self._verdict(Result.INCONCLUSIVE))
        ma = MailArtifact.objects.get(artifactIsUrl__url=self.url)
        self.assertEqual(ma.artifact_level, "SAFE-ALLOW_LISTED")
```

> `GoogleThreatIntelligence` / `Urlscan` names must match `_tier_seed.TIER_1_PREFIXES` / land at tier 3. Confirm against `cortex_job/migrations/_tier_seed.py` and set `tier=` explicitly on the `Analyzer` rows (as above) so the test doesn't depend on the seed.

- [ ] **Step 2: Run test to verify it fails**

Run: `... python manage.py test score_process.tests.test_mail_embedded_escalation -v2`
Expected: FAIL — `_apply_embedded_escalation` does not exist.

- [ ] **Step 3: Implement**

```python
# score_process/scoring/cortex_analyzers/reports.py — replace _apply_derived_escalation
@staticmethod
def _apply_embedded_escalation(case, mail, verdict):
    """Score every embedded observable of `mail` via the trust-weighted
    categorical engine; raise the mail band to the worst embedded band and
    fold the analyzers' rationale in. Writes per-observable ioc_* (global)
    and per-MailArtifact artifact_* (case-scoped) levels."""
    from settings.config import get_config
    if not get_config("scoring.mail_embedded_categorical", True):
        return CortexAnalyzerReports._apply_derived_escalation(case, mail, verdict)

    from score_process.scoring.observable_collect import mail_observable_reports
    from score_process.scoring.observable_engine import score_observable
    from score_process.scoring.sources import source_verdict_from_report
    from score_process.scoring.engine import mail_band_escalation
    from score_process.scoring.bands import (
        _BAND_ORDER, _BAND_TO_IOC_LEVEL, _DERIVED_SCORE, _STICKY_IOC_LEVELS,
    )
    from cortex_job.cortex_utils.derived_observables import score_derived_observables

    # keep DerivedObservable.child_band / escalation_note fresh for the chip UI
    score_derived_observables(case)

    embedded = []
    rationale_lines = []
    for m_art, obj, _field, reports in mail_observable_reports(mail):
        seen, svs = set(), []
        for r in reports:
            if r.analyzer_id in seen:
                continue
            seen.add(r.analyzer_id)
            svs.append(source_verdict_from_report(r))
        if not svs:
            continue
        v = score_observable(svs)
        embedded.append(v)
        rationale_lines.extend(v.rationale)

        ioc_level = _BAND_TO_IOC_LEVEL.get(v.band, "info")
        if getattr(obj, "ioc_level", "info") not in _STICKY_IOC_LEVELS:
            obj.ioc_level = ioc_level
        obj.ioc_score = _DERIVED_SCORE.get(v.band, 5)
        obj.ioc_confidence = v.confidence
        obj.save(update_fields=["ioc_level", "ioc_score", "ioc_confidence"])

        if m_art.artifact_level not in _STICKY_IOC_LEVELS:
            m_art.artifact_level = ioc_level
            m_art.artifact_score = _DERIVED_SCORE.get(v.band, 5)
            m_art.artifact_confidence = v.confidence
            m_art.save(update_fields=["artifact_level", "artifact_score", "artifact_confidence"])

    if not embedded:
        return verdict

    worst = max(embedded, key=lambda v: _BAND_ORDER.get(v.band, 0))
    note = "; ".join(rationale_lines[:5]) or None
    return mail_band_escalation(verdict, embedded, note=note)
```

Rename the call site in `get_report`'s mail branch from `_apply_derived_escalation` to `_apply_embedded_escalation`. Keep `_apply_derived_escalation` in the file (it's the flag-OFF fallback).

- [ ] **Step 4: Run tests**

Run: `... python manage.py test score_process.tests.test_mail_embedded_escalation score_process.tests.test_derived_scoring_mail score_process.tests.test_get_report score_process.tests.test_mail_escalation -v1`
Expected: PASS. Remove any `@expectedFailure` markers added in Task 4.

- [ ] **Step 5: Commit**

```bash
git add score_process/scoring/cortex_analyzers/reports.py score_process/tests/test_mail_embedded_escalation.py score_process/tests/test_derived_scoring_mail.py
git commit -m "feat(score): mail case embedded observables scored by the categorical trust engine"
```

---

## Task 6: `mail_band_escalation` confidence lift (gated)

**Files:**
- Modify: `score_process/scoring/engine.py`
- Test: extend `score_process/tests/test_mail_escalation.py`

**Interfaces:**
- `mail_band_escalation(verdict, embedded, note="")` — when the band is raised and the worst embedded verdict's confidence exceeds `verdict.final_confidence`, set `final_confidence` to it. `final_score` still untouched.

- [ ] **Step 1: Write the failing test**

```python
# add to score_process/tests/test_mail_escalation.py
def test_raised_band_lifts_confidence_from_the_embedded_verdict(self):
    from score_process.scoring.observable_engine import ObservableVerdict
    v = cv(Result.INCONCLUSIVE, score=2)          # final_confidence low (see cv())
    out = mail_band_escalation(
        v, [ObservableVerdict("Dangerous", 92, None, {}, ["GTI reports malicious."])])
    self.assertEqual(out.result, Result.DANGEROUS)
    self.assertGreaterEqual(out.final_confidence, 92)

def test_confidence_not_lowered_when_band_not_raised(self):
    from score_process.scoring.observable_engine import ObservableVerdict
    v = cv(Result.DANGEROUS, score=9)             # already Dangerous, conf high
    out = mail_band_escalation(v, [ObservableVerdict("Suspicious", 40, None, {}, [])])
    self.assertEqual(out.final_confidence, v.final_confidence)
```

> Check `cv()` in the test file sets `final_confidence`; if not, add it.

- [ ] **Step 2: Run test to verify it fails**

Run: `... python manage.py test score_process.tests.test_mail_escalation -v2`
Expected: FAIL — confidence unchanged.

- [ ] **Step 3: Implement**

In `mail_band_escalation`, where it currently does `replace(verdict, result=worst if raising else verdict.result, rationale=...)`:

```python
    new_conf = verdict.final_confidence
    if raising:
        worst_conf = max((getattr(o, "confidence", 0) for o in embedded
                          if _OBS_TO_RESULT.get(o.band) == worst), default=0)
        new_conf = max(verdict.final_confidence, min(round(worst_conf), 100))
    return replace(
        verdict,
        result=worst if raising else verdict.result,
        final_confidence=new_conf,
        rationale=tuple(verdict.rationale) + (line,),
    )
```

- [ ] **Step 4: Run tests**

Run: `... python manage.py test score_process.tests.test_mail_escalation score_process.tests.test_engine score_process.tests.test_mail_embedded_escalation -v1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add score_process/scoring/engine.py score_process/tests/test_mail_escalation.py
git commit -m "feat(score): a raised mail band takes the embedded verdict's confidence"
```

---

## Task 7: Regression sweep + query budget + dev-stack verification

**Files:**
- Modify: `score_process/tests/test_processing_query_count.py` (if the count shifted)
- No production changes unless a regression is found.

- [ ] **Step 1: Full score_process suite**

Run: `... python manage.py test score_process`
Expected: PASS. Investigate every failure. A shifted expected verdict in `test_get_report` / `test_processing` is acceptable **only** with a one-line justification in the test (e.g. `# was Suspicious off Urlscan Tier-3 noise; GTI-clean now wins → Safe`).

- [ ] **Step 2: Query budget**

Run: `... python manage.py test score_process.tests.test_processing_query_count -v2`
If `test_process_mail_select_count_is_constant` fails: the artifacts loop was removed from `process_mail` and one `mail_observable_reports` query was added in `_apply_embedded_escalation` (a different code path, not counted by that test). Update the expected number with a comment explaining the net change; it should be **lower or equal** for `process_mail`.

- [ ] **Step 3: Labelled accuracy harness (smoke)**

Run: `... python manage.py test score_process.tests.test_score_accuracy` and `... python manage.py score_accuracy`
Expected: 5/5 aligned, unchanged (`score_observable` is untouched).

- [ ] **Step 4: Full backend suite**

Run: `... python manage.py test`
Expected: PASS (baseline 974).

- [ ] **Step 5: Dev-stack backtest + live mail**

On the running dev stack:
```
cd deployment && docker compose --env-file .env exec suspicious python manage.py backtest_scoring
```
Read the drift report. Every Safe↔Dangerous flip on a real case must be explainable by the Tier logic. Then send the phishing sample through greenmail→feeder (see `CLAUDE.md` §7), wait for finalize, and confirm via `manage.py shell`:
```python
c = Case.objects.latest("id")
print(c.results, c.confidence, c.verdict_rationale)
print(list(c.fileOrMail.mail.mail_artifacts.values("artifact_type", "artifact_level")))
```
Expected: verdict reflects the embedded IOC trust levels; rationale names the analyzers; `MailArtifact.artifact_level` populated.

- [ ] **Step 6: Commit any test-count updates + a short drift note**

```bash
git add score_process/tests/test_processing_query_count.py docs/specs/2026-09-08-mail-road-trust-hierarchy-design.md
git commit -m "test(score): mail-road query budget after embedded-observable split + drift notes"
```

---

## Self-Review Notes (planner, not executor)

- **Spec coverage:** §1 split → T4/T5; §2 `_bucket_reports` + `mail_observable_reports` → T2/T3; §3 opt-out → T4; §4 `_apply_embedded_escalation` → T5; §5 per-artifact + global writes → T5; §6 `mail_band_escalation` sufficiency + confidence tweak → T6; §5 bands module → T1; regression strategy → T7; kill switch → T4 (`collect_signals`) + T5 (`_apply_embedded_escalation`), both reading `scoring.mail_embedded_categorical`.
- **Flag consistency:** the flag must be read the same way in both places. If ON (default): `collect_signals` passes `score_artifacts=False` AND `_apply_embedded_escalation` runs the categorical path. If OFF: `score_artifacts=True` AND `_apply_embedded_escalation` delegates to the old `_apply_derived_escalation`. T4 and T5 each carry a test for their half; T7 step 1 is the end-to-end check that ON and OFF are each internally consistent.
- **Executor must verify before coding:** `ArtifactIs*` FK/join names (T3 — Phase B `_MAIL_JOIN` has them); whether an attachment file-hash is also a `mail_artifact` (spec §1 check); `AnalyzerReport.mail_id` is the `MailAddress` FK (T3); `cv()` / `CaseVerdict` fields in `test_mail_escalation.py` (T6); the current names of the band maps in `apply.py` (T1).
- **Known risk:** T4 lands the signal-removal before T5 lands the escalation, so mid-series a mail case can transiently under-score. Mitigated by keeping T4→T5 in one review batch (or one branch) and the `@expectedFailure` bridge noted in T4 step 4.
