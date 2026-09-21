# IOC Analysis Road Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dedicated IOC-analysis road — a new `ObservableGroup` container that lets one `Case` hold many indicators, a two-road submission UI (email/file vs. multi-line indicators), per-IOC Cortex dispatch, a VT-Tool-style analysis page, a downloadable report, and a bulk SOAR API — all shipping on the current scoring engine.

**Architecture:** `ObservableGroup` + `ObservableGroupArtifact` mirror `Mail` + `MailArtifact`: a thin container with N observables. A new nullable `Case.observable_group` FK carries it — `nonFileIocs` is left untouched, so legacy single-IOC cases need no migration and the two container shapes coexist behind a read-time branch in `collect_case_targets`. Everything downstream (Cortex dispatch, the webhook, `CaseAnalyzerJob`, `finalise_case`, `fail_stale_jobs`) is already per-artifact and unchanged. The verdict for group cases comes from the categorical engine in the sibling plan.

**Tech Stack:** Django 6.1, Python 3.12, DRF, Knox token auth. Frontend: React 19 + TypeScript + Vite + MUI v9 + TanStack Query v5 + React Hook Form + Zod. WeasyPrint for PDF (new dependency — see Global Constraints). Vitest + Playwright.

**Spec:** `docs/specs/2026-09-02-ioc-analysis-road-design.md`

## Global Constraints

- **Do not repoint or migrate `Case.nonFileIocs`.** Add `Case.observable_group` as a new nullable FK. Legacy cases keep working with zero data migration.
- **Do not change** `dispatch_pending`, the Cortex webhook, `CaseAnalyzerJob`, `finalise_case`, or `fail_stale_jobs`. They operate on `(instance, data_type)` targets and per-case job ledgers — already correct for N observables.
- `IOC_GROUP_MAX = 100` — reject larger submissions with HTTP 400 and a clear message.
- **New pip dependency:** `weasyprint` (Task 11 only). Pin it in `Suspicious/requirements*.txt`. If the reviewer rejects the dependency, the report endpoint ships HTML-only and PDF is dropped — do not add a headless-browser renderer.
- Conventional Commits. Commit after every task. Every backend task ends with `python manage.py test <apps>` green; every frontend task ends with `pnpm test` green and `pnpm lint` clean.
- Frontend: follow existing `suspicious-ui/src` patterns — TanStack Query for server state, Zod schemas in `features/*/`, MUI components, no new state libraries.

---

## File Structure

### Backend
| File | Responsibility |
|---|---|
| `case_handler/models.py` | `ObservableGroup`, `ObservableGroupArtifact`; `Case.observable_group` FK |
| `case_handler/migrations/00NN_observable_group.py` | schema |
| `case_handler/case_utils/case_creator.py` | attach an `ObservableGroup` to a new `Case` |
| `cortex_job/cortex_utils/case_targets.py` | `collect_case_targets` — `ObservableGroup` branch |
| `score_process/scoring/collect.py` | `collect_signals` — `ObservableGroup` branch (feeds sibling-plan engine) |
| `api/utils/indicators.py` | **new** — `parse_indicators(text) -> list[ParsedIndicator]` |
| `api/serializers/submit.py` | `SubmitIndicatorsSerializer` |
| `api/views/submit.py` | `SubmitIndicatorsView` |
| `api/urls.py` | route `submit/indicators/` |
| `api/serializers/investigations.py` | expose `observable_group` + `report_full` on the IOC road |
| `api/views/investigations.py` | include the group in the detail payload |
| `api/views/case_report.py` | **new** — `GET /api/cases/<id>/report/` |
| `api/templates/case_report/report.html` | **new** — report template |
| `connectors/contrib/thehive/phishing.py` | `build_group_observables` |

### Frontend
| File | Responsibility |
|---|---|
| `suspicious-ui/src/features/submit/types.ts` | add `"indicators"` mode + indicator types |
| `suspicious-ui/src/features/submit/parseIndicators.ts` | client-side preview parsing |
| `suspicious-ui/src/pages/SubmitPage.tsx` | indicators mode panel |
| `suspicious-ui/src/features/investigation/observableGroup.ts` | Zod schema + hook |
| `suspicious-ui/src/pages/InvestigationPage.tsx` | IOC-group layout branch |
| `suspicious-ui/src/features/investigation/SourceTable.tsx` | **new** — per-source verdict table (shared w/ mail embedded IOCs) |

---

## Task 1: `ObservableGroup` + `ObservableGroupArtifact` models

**Files:**
- Modify: `Suspicious/Suspicious/case_handler/models.py`
- Create: `Suspicious/Suspicious/case_handler/migrations/` (`observable_group`)
- Test: `Suspicious/Suspicious/case_handler/tests/test_observable_group.py`

**Interfaces:**
- Produces:
  ```python
  ObservableGroup(id, label: str = "", creation_date, last_update)
  ObservableGroupArtifact(id, group: FK(ObservableGroup, related_name="artifacts"),
      artifact_type: "URL"|"IP"|"HASH"|"DOMAIN", url/ip/hash/domain: FK(null=True),
      creation_date)
  ```

- [ ] **Step 1: Write the failing test**

`case_handler/tests/test_observable_group.py`:

```python
from django.test import TestCase
from ip_process.models import IP
from url_process.models import URL
from case_handler.models import ObservableGroup, ObservableGroupArtifact


class ObservableGroupTests(TestCase):
    def test_group_holds_many_artifacts(self):
        g = ObservableGroup.objects.create(label="alert #1")
        ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=IP.objects.create(address="1.1.1.1"))
        ObservableGroupArtifact.objects.create(group=g, artifact_type="URL", url=URL.objects.create(address="http://x.test"))
        self.assertEqual(g.artifacts.count(), 2)

    def test_artifact_str(self):
        g = ObservableGroup.objects.create()
        a = ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=IP.objects.create(address="9.9.9.9"))
        self.assertIn("9.9.9.9", str(a))
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test case_handler.tests.test_observable_group -v 2`
Expected: FAIL — `ImportError: cannot import name 'ObservableGroup'`.

- [ ] **Step 3: Add the models**

`case_handler/models.py` (near `CaseHasNonFileIocs`; `URL`, `IP`, `Hash`, `Domain` are already imported at the top):

```python
class ObservableGroup(models.Model):
    """A set of indicators submitted together and analysed as one Case.
    The IOC-road analogue of Mail: a thin envelope over N observables."""
    label = models.CharField(max_length=255, blank=True, default="")
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)
    last_update = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-creation_date"]

    def __str__(self):
        return self.label or f"ObservableGroup #{self.pk}"


class ObservableGroupArtifact(models.Model):
    class Type(models.TextChoices):
        URL = "URL", "URL"
        IP = "IP", "IP"
        HASH = "HASH", "Hash"
        DOMAIN = "DOMAIN", "Domain"

    group = models.ForeignKey(ObservableGroup, on_delete=models.CASCADE, related_name="artifacts", db_index=True)
    artifact_type = models.CharField(max_length=10, choices=Type.choices, db_index=True)
    url = models.ForeignKey(URL, on_delete=models.CASCADE, null=True, blank=True, related_name="observable_group_artifacts")
    ip = models.ForeignKey(IP, on_delete=models.CASCADE, null=True, blank=True, related_name="observable_group_artifacts")
    hash = models.ForeignKey(Hash, on_delete=models.CASCADE, null=True, blank=True, related_name="observable_group_artifacts")
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, null=True, blank=True, related_name="observable_group_artifacts")
    creation_date = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["creation_date"]
        indexes = [models.Index(fields=["group", "artifact_type"])]

    def observable(self):
        return self.url or self.ip or self.hash or self.domain

    def __str__(self):
        obj = self.observable()
        val = getattr(obj, "address", None) or getattr(obj, "value", None) or self.pk
        return f"{self.artifact_type}: {val}"
```

- [ ] **Step 4: Migrate + test**

```bash
python manage.py makemigrations case_handler --name observable_group
python manage.py test case_handler.tests.test_observable_group -v 2
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/case_handler/models.py Suspicious/Suspicious/case_handler/migrations/ Suspicious/Suspicious/case_handler/tests/test_observable_group.py
git commit -m "feat(case_handler): ObservableGroup container for multi-IOC cases"
```

---

## Task 2: `Case.observable_group` FK

**Files:**
- Modify: `Suspicious/Suspicious/case_handler/models.py` (class `Case`)
- Create: `Suspicious/Suspicious/case_handler/migrations/` (`case_observable_group`)
- Test: `Suspicious/Suspicious/case_handler/tests/test_observable_group.py` (append)

**Interfaces:**
- Produces: `Case.observable_group = FK(ObservableGroup, null=True, blank=True, related_name="cases", on_delete=CASCADE, db_index=True)`. Legacy cases leave it null.

- [ ] **Step 1: Write the failing test**

Append:

```python
from django.contrib.auth.models import User
from case_handler.models import Case

class CaseObservableGroupTests(TestCase):
    def test_case_links_group_and_legacy_stays_null(self):
        u = User.objects.create_user("u", password="p")
        legacy = Case.objects.create(description="legacy", reporter=u)
        self.assertIsNone(legacy.observable_group_id)
        g = ObservableGroup.objects.create()
        c = Case.objects.create(description="grp", reporter=u, observable_group=g)
        self.assertEqual(c.observable_group_id, g.id)
        self.assertIn(c, g.cases.all())
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test case_handler.tests.test_observable_group.CaseObservableGroupTests -v 2`
Expected: FAIL — `TypeError: 'observable_group' is an invalid keyword argument`.

- [ ] **Step 3: Add the field**

`case_handler/models.py`, class `Case`, next to `nonFileIocs`:

```python
    observable_group = models.ForeignKey(
        "ObservableGroup", on_delete=models.CASCADE, related_name="cases",
        null=True, blank=True, db_index=True,
    )
```

- [ ] **Step 4: Migrate + test**

```bash
python manage.py makemigrations case_handler --name case_observable_group
python manage.py test case_handler -v 2
```

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/case_handler/models.py Suspicious/Suspicious/case_handler/migrations/
git commit -m "feat(case_handler): Case.observable_group FK (additive, nullable)"
```

---

## Task 3: `CaseCreator` — attach an `ObservableGroup`

**Files:**
- Modify: `Suspicious/Suspicious/case_handler/case_utils/case_creator.py`
- Test: `Suspicious/Suspicious/case_handler/tests/test_case_creator_group.py`

**Interfaces:**
- Consumes: `ObservableGroup`, `ObservableGroupArtifact` (Task 1), `Case.observable_group` (Task 2).
- Produces: `CaseCreator(user).create_case(description=..., observable_group_instance=<ObservableGroup>)` sets `case.observable_group` and writes a `CaseArtifact` row per observable.

- [ ] **Step 1: Write the failing test**

`case_handler/tests/test_case_creator_group.py`:

```python
from django.test import TestCase
from django.contrib.auth.models import User
from ip_process.models import IP
from url_process.models import URL
from case_handler.models import ObservableGroup, ObservableGroupArtifact, CaseArtifact
from case_handler.case_utils.case_creator import CaseCreator


class CaseCreatorGroupTests(TestCase):
    def test_group_case_gets_group_and_case_artifacts(self):
        u = User.objects.create_user("u", password="p")
        g = ObservableGroup.objects.create()
        ip = IP.objects.create(address="8.8.4.4")
        url = URL.objects.create(address="http://a.test")
        ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=ip)
        ObservableGroupArtifact.objects.create(group=g, artifact_type="URL", url=url)

        case = CaseCreator(u).create_case(description="d", observable_group_instance=g)

        self.assertEqual(case.observable_group_id, g.id)
        self.assertEqual(CaseArtifact.objects.filter(case=case).count(), 2)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test case_handler.tests.test_case_creator_group -v 2`
Expected: FAIL — `observable_group` not set / no `CaseArtifact` rows.

- [ ] **Step 3: Handle the new kwarg**

`case_creator.py`, `create_case` loop over `kwargs.items()` — add a branch alongside the existing `_create_related_model` dispatch. Simplest: handle it explicitly after the loop:

```python
        group = kwargs.pop("observable_group_instance", None)
        # ... existing kwargs loop ...
        if group is not None:
            case.save()
            case.observable_group = group
            case.save(update_fields=["observable_group"])
            for art in group.artifacts.select_related("url", "ip", "hash", "domain"):
                obj = art.observable()
                if obj is None:
                    continue
                fk = {"URL": "url", "IP": "ip", "HASH": "hash", "DOMAIN": "domain"}[art.artifact_type]
                CaseArtifact.objects.get_or_create(
                    case=case,
                    artifact_type=getattr(CaseArtifact.ArtifactType, art.artifact_type),
                    **{fk: obj},
                )
```

Place this **before** the final `case.save()` / KPI block so stats see the group.

- [ ] **Step 4: Run tests + commit**

```bash
python manage.py test case_handler -v 2
git add Suspicious/Suspicious/case_handler/case_utils/case_creator.py Suspicious/Suspicious/case_handler/tests/test_case_creator_group.py
git commit -m "feat(case_handler): CaseCreator attaches ObservableGroup + CaseArtifact rows"
```

---

## Task 4: `collect_case_targets` — `ObservableGroup` branch

**Files:**
- Modify: `Suspicious/Suspicious/cortex_job/cortex_utils/case_targets.py`
- Test: `Suspicious/Suspicious/cortex_job/tests/test_case_targets_group.py`

**Interfaces:**
- Consumes: `Case.observable_group`, `ObservableGroupArtifact.observable()`.
- Produces: `collect_case_targets(group_case)` returns one `(instance, data_type)` per observable, deduped by `(data_type, pk)`, alongside any legacy targets.

- [ ] **Step 1: Write the failing test**

`cortex_job/tests/test_case_targets_group.py`:

```python
from django.test import TestCase
from django.contrib.auth.models import User
from ip_process.models import IP
from hash_process.models import Hash
from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from cortex_job.cortex_utils.case_targets import collect_case_targets


class CaseTargetsGroupTests(TestCase):
    def test_group_targets_enumerated(self):
        u = User.objects.create_user("u", password="p")
        g = ObservableGroup.objects.create()
        ip = IP.objects.create(address="2.2.2.2")
        h = Hash.objects.create(value="a" * 64)
        ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=ip)
        ObservableGroupArtifact.objects.create(group=g, artifact_type="HASH", hash=h)
        case = Case.objects.create(description="d", reporter=u, observable_group=g)

        targets = collect_case_targets(case)
        got = {(dt, inst.pk) for inst, dt in targets}
        self.assertEqual(got, {("ip", ip.pk), ("hash", h.pk)})
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test cortex_job.tests.test_case_targets_group -v 2`
Expected: FAIL — empty target list.

- [ ] **Step 3: Add the branch**

`case_targets.py`, in `collect_case_targets`, after the `if case.nonFileIocs_id and non_file_iocs:` block:

```python
    group = getattr(case, "observable_group", None)
    if case.observable_group_id and group:
        for art in group.artifacts.select_related("url", "ip", "hash", "domain"):
            obj = art.observable()
            if obj is not None:
                _add(obj, art.artifact_type.lower())
```

- [ ] **Step 4: Run tests + commit**

```bash
python manage.py test cortex_job -v 2
git add Suspicious/Suspicious/cortex_job/cortex_utils/case_targets.py Suspicious/Suspicious/cortex_job/tests/test_case_targets_group.py
git commit -m "feat(cortex_job): enumerate ObservableGroup targets for dispatch + reports"
```

---

## Task 5: `collect_signals` — `ObservableGroup` branch

**Files:**
- Modify: `Suspicious/Suspicious/score_process/scoring/collect.py`
- Test: `Suspicious/Suspicious/score_process/tests/test_collect.py` (append)

**Interfaces:**
- Consumes: `Case.observable_group`, `process_ioc` (existing in `processing.py`).
- Produces: `collect_signals(group_case)` yields one signal set per observable, so a group case can be scored (by the sibling plan's IOC engine, or `score_case` as a fallback before Task 13 of the sibling plan lands).

- [ ] **Step 1: Write the failing test**

Append to `test_collect.py`:

```python
class CollectSignalsGroupTests(TestCase):
    def test_group_case_produces_signal_per_observable(self):
        from django.contrib.auth.models import User
        from ip_process.models import IP
        from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
        from score_process.scoring.collect import collect_signals

        u = User.objects.create_user("u", password="p")
        g = ObservableGroup.objects.create()
        for a in ("3.3.3.3", "4.4.4.4"):
            ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=IP.objects.create(address=a))
        case = Case.objects.create(description="d", reporter=u, observable_group=g)

        signals, ai, deny, ai_missing, reason = collect_signals(case)
        self.assertGreaterEqual(len(signals), 2)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test score_process.tests.test_collect.CollectSignalsGroupTests -v 2`
Expected: FAIL — 0 signals (no branch for `observable_group`).

- [ ] **Step 3: Add the branch**

`collect.py`, in `collect_signals`, after the `if case.nonFileIocs:` block:

```python
    if case.observable_group_id:
        _FIELD = {"URL": "url", "IP": "ip", "HASH": "hash", "DOMAIN": "domain"}
        for art in case.observable_group.artifacts.select_related("url", "ip", "hash", "domain"):
            obj = art.observable()
            if obj is None:
                continue
            off = len(scores)
            failures += process_ioc(obj, _FIELD[art.artifact_type], reports, scores, confidences, 0)
            signals += _signals_from(scores, confidences, off, art.artifact_type.lower())
```

- [ ] **Step 4: Run tests + backtest + commit**

```bash
python manage.py test score_process -v 2
python manage.py backtest_scoring --road mail | tail -3   # unchanged
git add Suspicious/Suspicious/score_process/scoring/collect.py Suspicious/Suspicious/score_process/tests/test_collect.py
git commit -m "feat(score): collect_signals walks ObservableGroup observables"
```

---

## Task 6: `parse_indicators` utility

**Files:**
- Create: `Suspicious/Suspicious/api/utils/indicators.py`
- Test: `Suspicious/Suspicious/api/tests/test_parse_indicators.py`

**Interfaces:**
- Consumes: existing validators — `IPHandler().validate_ip`, `HashHandler().validate_hash` (from `case_handler.case_utils`), URL/domain checks.
- Produces:
  ```python
  @dataclass
  class ParsedIndicator:
      raw: str
      value: str        # refanged / normalised
      type: str | None  # "url" | "ip" | "hash" | "domain" | None
  def parse_indicators(text: str) -> list[ParsedIndicator]   # deduped, order preserved
  ```

- [ ] **Step 1: Write the failing tests**

`api/tests/test_parse_indicators.py`:

```python
from django.test import SimpleTestCase
from api.utils.indicators import parse_indicators


class ParseIndicatorsTests(SimpleTestCase):
    def test_splits_on_newline_comma_space(self):
        out = parse_indicators("8.8.8.8, 1.1.1.1\nhttp://a.test  9.9.9.9")
        self.assertEqual([p.value for p in out], ["8.8.8.8", "1.1.1.1", "http://a.test", "9.9.9.9"])

    def test_refangs(self):
        out = parse_indicators("hxxp://evil[.]com  1[.]2[.]3[.]4")
        self.assertEqual(out[0].value, "http://evil.com")
        self.assertEqual(out[0].type, "url")
        self.assertEqual(out[1].value, "1.2.3.4")
        self.assertEqual(out[1].type, "ip")

    def test_type_detection(self):
        types = {p.value: p.type for p in parse_indicators(
            "8.8.8.8\n" + "a" * 64 + "\nexample.com\nhttp://example.com/x"
        )}
        self.assertEqual(types["8.8.8.8"], "ip")
        self.assertEqual(types["a" * 64], "hash")
        self.assertEqual(types["example.com"], "domain")
        self.assertEqual(types["http://example.com/x"], "url")

    def test_dedupe_preserves_order(self):
        out = parse_indicators("8.8.8.8\n8.8.8.8\n1.1.1.1")
        self.assertEqual([p.value for p in out], ["8.8.8.8", "1.1.1.1"])

    def test_unparseable_line_kept_with_none_type(self):
        out = parse_indicators("not an indicator !!!")
        self.assertIsNone(out[0].type)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test api.tests.test_parse_indicators -v 2`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

`api/utils/indicators.py`:

```python
"""Parse a free-text blob of indicators into typed, deduped entries.
Reuses Suspicious's existing per-type validators — no new detection logic."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

_SPLIT = re.compile(r"[\s,;]+")
_HASH = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")


def _refang(s: str) -> str:
    return (s.replace("hxxp://", "http://").replace("hxxps://", "https://")
             .replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
             .replace("[dot]", ".").strip().strip("<>\"'"))


@dataclass
class ParsedIndicator:
    raw: str
    value: str
    type: Optional[str]


def _classify(value: str) -> Optional[str]:
    from case_handler.case_utils.ioc_handlers import IPHandler, HashHandler  # adjust to real import path
    if _HASH.match(value):
        return "hash"
    try:
        if IPHandler().validate_ip(value):
            return "ip"
    except Exception:
        pass
    if value.startswith(("http://", "https://")):
        return "url"
    if "." in value and " " not in value and "/" not in value:
        return "domain"
    return None


def parse_indicators(text: str) -> list[ParsedIndicator]:
    seen: set[str] = set()
    out: list[ParsedIndicator] = []
    for token in _SPLIT.split(text or ""):
        if not token:
            continue
        value = _refang(token)
        if not value or value.lower() in seen:
            continue
        seen.add(value.lower())
        out.append(ParsedIndicator(raw=token, value=value, type=_classify(value)))
    return out
```

Fix the `_classify` import path to wherever `IPHandler` / `HashHandler` actually live (grep `class IPHandler`).

- [ ] **Step 4: Run tests + commit**

```bash
python manage.py test api.tests.test_parse_indicators -v 2
git add Suspicious/Suspicious/api/utils/indicators.py Suspicious/Suspicious/api/tests/test_parse_indicators.py
git commit -m "feat(api): multi-line indicator parser (refang + type detect + dedupe)"
```

---

## Task 7: `SubmitIndicatorsView` + serializer + route

**Files:**
- Modify: `Suspicious/Suspicious/api/serializers/submit.py`
- Modify: `Suspicious/Suspicious/api/views/submit.py`
- Modify: `Suspicious/Suspicious/api/urls.py`
- Test: `Suspicious/Suspicious/api/tests/test_submit_indicators.py`

**Interfaces:**
- Consumes: `parse_indicators` (Task 6), `ObservableGroup`/`ObservableGroupArtifact` (Task 1), `CaseCreator` (Task 3), `handler.dispatch_pending` (existing), `check_allow_list` (existing + sibling plan Task 5).
- Produces: `POST /api/submit/indicators/` body `{indicators: str, context?: str}` → `201 {case_id, observable_count, accepted, skipped: [str]}`. `IsAuthenticated`.

- [ ] **Step 1: Write the failing tests**

`api/tests/test_submit_indicators.py`:

```python
from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from case_handler.models import Case, ObservableGroupArtifact


class SubmitIndicatorsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("u", password="p")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_bulk_creates_one_case_with_group(self):
        r = self.client.post("/api/submit/indicators/",
                             {"indicators": "8.8.8.8\n1.1.1.1\nhttp://a.test"}, format="json")
        self.assertEqual(r.status_code, 201)
        case = Case.objects.get(id=r.json()["case_id"])
        self.assertIsNotNone(case.observable_group_id)
        self.assertEqual(ObservableGroupArtifact.objects.filter(group=case.observable_group).count(), 3)
        self.assertEqual(r.json()["observable_count"], 3)

    def test_junk_lines_are_skipped_not_fatal(self):
        r = self.client.post("/api/submit/indicators/",
                             {"indicators": "8.8.8.8\n!!!garbage!!!"}, format="json")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json()["skipped"], ["!!!garbage!!!"])

    def test_zero_valid_is_400(self):
        r = self.client.post("/api/submit/indicators/", {"indicators": "??? ###"}, format="json")
        self.assertEqual(r.status_code, 400)

    def test_over_cap_is_400(self):
        blob = "\n".join(f"10.0.0.{i}" for i in range(1, 130))
        r = self.client.post("/api/submit/indicators/", {"indicators": blob}, format="json")
        self.assertEqual(r.status_code, 400)
        self.assertIn("100", r.json().get("detail", ""))

    def test_requires_auth(self):
        self.client.force_authenticate(None)
        r = self.client.post("/api/submit/indicators/", {"indicators": "8.8.8.8"}, format="json")
        self.assertEqual(r.status_code, 401)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test api.tests.test_submit_indicators -v 2`
Expected: FAIL — 404 (route missing).

- [ ] **Step 3: Serializer**

`api/serializers/submit.py`:

```python
class SubmitIndicatorsSerializer(OptionalContextMixin, serializers.Serializer):
    indicators = serializers.CharField(required=True, trim_whitespace=False)

    def validate_indicators(self, value):
        from api.utils.indicators import parse_indicators
        parsed = parse_indicators(value)
        valid = [p for p in parsed if p.type]
        if not valid:
            raise serializers.ValidationError("No valid indicator found.")
        if len(valid) > 100:  # IOC_GROUP_MAX
            raise serializers.ValidationError(
                f"Too many indicators ({len(valid)}). The limit is 100 per submission."
            )
        self.context["parsed"] = parsed
        return value
```

- [ ] **Step 4: View + route**

`api/views/submit.py`:

```python
class SubmitIndicatorsView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        ser = SubmitIndicatorsSerializer(data=request.data, context={"request": request})
        ser.is_valid(raise_exception=True)
        parsed = ser.context["parsed"]
        valid = [p for p in parsed if p.type]
        skipped = [p.raw for p in parsed if not p.type]

        from case_handler.models import ObservableGroup, ObservableGroupArtifact
        from case_handler.case_utils.case_creator import CaseCreator
        from url_process.models import URL
        from ip_process.models import IP
        from hash_process.models import Hash
        from domain_process.models import Domain

        _MODEL = {"url": (URL, "address", "url"), "ip": (IP, "address", "ip"),
                  "hash": (Hash, "value", "hash"), "domain": (Domain, "value", "domain")}

        group = ObservableGroup.objects.create(label=(request.data.get("context") or "")[:255])
        for p in valid:
            model, field, art_field = _MODEL[p.type]
            obj, _ = model.objects.get_or_create(**{field: p.value})
            ObservableGroupArtifact.objects.create(
                group=group, artifact_type=p.type.upper(), **{art_field: obj}
            )

        context = (request.data.get("context") or "")
        case = CaseCreator(request.user).create_case(
            description=context, reporter_context=context, observable_group_instance=group,
        )

        handler = CaseHandler(request, UploadFileForm(), UploadURLForm(), UploadOtherForm())
        handler.dispatch_pending(case)

        return Response(
            {"status": "success", "case_id": case.id, "observable_count": len(valid),
             "accepted": True, "skipped": skipped},
            status=status.HTTP_201_CREATED,
        )
```

`api/urls.py`, in the submit block:

```python
    path("submit/indicators/", SubmitIndicatorsView.as_view(), name="submit-indicators"),
```

and add `SubmitIndicatorsView` to the `from api.views.submit import (...)` list.

- [ ] **Step 5: Run tests + commit**

```bash
python manage.py test api.tests.test_submit_indicators -v 2
git add Suspicious/Suspicious/api/serializers/submit.py Suspicious/Suspicious/api/views/submit.py Suspicious/Suspicious/api/urls.py Suspicious/Suspicious/api/tests/test_submit_indicators.py
git commit -m "feat(api): POST /api/submit/indicators/ — bulk multi-IOC submission"
```

---

## Task 8: Frontend — Indicators submit mode

**Files:**
- Modify: `suspicious-ui/src/features/submit/types.ts`
- Create: `suspicious-ui/src/features/submit/parseIndicators.ts`
- Modify: `suspicious-ui/src/pages/SubmitPage.tsx`
- Modify: `suspicious-ui/src/features/submit/api.ts` (add `submitIndicators`)
- Test: `suspicious-ui/src/features/submit/__tests__/parseIndicators.test.ts`

**Interfaces:**
- Consumes: `POST /api/submit/indicators/` (Task 7).
- Produces: a third submit mode `"indicators"` with a textarea, a live preview list (`value → type`, junk flagged), and a submit button that navigates to the created case.

- [ ] **Step 1: Write the failing test**

`suspicious-ui/src/features/submit/__tests__/parseIndicators.test.ts`:

```typescript
import { describe, it, expect } from "vitest";
import { parseIndicators } from "../parseIndicators";

describe("parseIndicators", () => {
  it("splits, refangs, types, dedupes", () => {
    const out = parseIndicators("hxxp://evil[.]com\n8.8.8.8, 8.8.8.8\n" + "a".repeat(64));
    expect(out.map((p) => [p.value, p.type])).toEqual([
      ["http://evil.com", "url"],
      ["8.8.8.8", "ip"],
      ["a".repeat(64), "hash"],
    ]);
  });
  it("flags junk with null type", () => {
    expect(parseIndicators("!!!")[0].type).toBeNull();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd suspicious-ui && pnpm test parseIndicators`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `parseIndicators.ts`**

Port the regex + classification from `api/utils/indicators.py` (Task 6) to TS. This is a preview aid only — the server re-parses authoritatively.

```typescript
export type IndicatorType = "url" | "ip" | "hash" | "domain" | null;
export interface ParsedIndicator { raw: string; value: string; type: IndicatorType; }

const HASH = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;

const refang = (s: string) =>
  s.replace(/hxxps?:\/\//g, (m) => m.replace("hxxp", "http"))
   .replace(/\[\.\]|\(\.\)|\[dot\]/g, ".")
   .replace(/\[:\]/g, ":")
   .trim().replace(/^[<"']+|[>"']+$/g, "");

const classify = (v: string): IndicatorType => {
  if (HASH.test(v)) return "hash";
  if (IPV4.test(v) && v.split(".").every((o) => +o <= 255)) return "ip";
  if (/^https?:\/\//.test(v)) return "url";
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v) && !v.includes("/")) return "domain";
  return null;
};

export function parseIndicators(text: string): ParsedIndicator[] {
  const seen = new Set<string>();
  const out: ParsedIndicator[] = [];
  for (const tok of (text || "").split(/[\s,;]+/)) {
    if (!tok) continue;
    const value = refang(tok);
    if (!value || seen.has(value.toLowerCase())) continue;
    seen.add(value.toLowerCase());
    out.push({ raw: tok, value, type: classify(value) });
  }
  return out;
}
```

- [ ] **Step 4: Wire the mode into `SubmitPage.tsx`**

- `types.ts`: `export type SubmitMode = "file" | "artifact" | "indicators";`
- Add a third `ModeSelectorCard` ("Indicators", subtitle *"Paste one or many URLs, IPs, hashes or domains — analysed together as one case."*).
- `mode === "indicators"` panel: a `<TextField multiline minRows={6}>`, a `useMemo` preview list from `parseIndicators(value)` rendering each `value` with a type `<Chip>` (junk → red "unrecognised" chip), a count line ("N indicators, M unrecognised"), and a submit button calling `submitIndicators({ indicators, context })` then `navigate(/investigations/${case_id})`.
- `features/submit/api.ts`: `export const submitIndicators = (body: {indicators: string; context?: string}) => apiPost("/api/submit/indicators/", body);` (match the existing `apiPost` helper).

- [ ] **Step 5: Run tests + lint + commit**

```bash
cd suspicious-ui && pnpm test && pnpm lint
git add suspicious-ui/src/features/submit/ suspicious-ui/src/pages/SubmitPage.tsx
git commit -m "feat(ui): Indicators submit mode with multi-line preview"
```

---

## Task 9: Investigation API — expose the observable group + `report_full`

**Files:**
- Modify: `Suspicious/Suspicious/api/serializers/investigations.py`
- Modify: `Suspicious/Suspicious/api/views/investigations.py`
- Test: `Suspicious/Suspicious/api/tests/test_investigation_group.py`

**Interfaces:**
- Consumes: `Case.observable_group`, `AnalyzerReport.report_full`, the sibling plan's `source_verdict_from_report` + `score_observable` (import lazily; if the sibling plan has not landed, return raw reports without a computed per-observable verdict — the field is `null`).
- Produces: `GET /api/investigations/<id>/` — when `observable_group` is set, the payload includes:
  ```json
  {"observable_group": {"observables": [
     {"value": "...", "type": "ip",
      "verdict": {"band": "Safe", "confidence": 88, "rationale": [...]},
      "sources": [{"name": "GTI", "tier": 1, "verdict": "clean", "evidence": "...", "report_full": {...}}]}]}}
  ```
  For mail/file cases the key is absent (isolation).

- [ ] **Step 1: Write the failing test**

`api/tests/test_investigation_group.py`:

```python
from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from ip_process.models import IP
from cortex_job.models import Analyzer, AnalyzerReport
from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact


class InvestigationGroupApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("u", password="p", is_staff=True)
        self.client = APIClient(); self.client.force_authenticate(self.user)

    def test_group_case_exposes_observables_and_report_full(self):
        g = ObservableGroup.objects.create()
        ip = IP.objects.create(address="8.8.8.8")
        ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=ip)
        case = Case.objects.create(description="d", reporter=self.user, observable_group=g)
        a = Analyzer.objects.create(name="GTI", analyzer_cortex_id="g1", tier=1)
        AnalyzerReport.objects.create(cortex_job_id="j", type="ip", status="Success", analyzer=a,
            ip=ip, level="safe", confidence=95, score=0,
            report_summary={}, report_taxonomy={}, report_full={"as_owner": "Google LLC"})

        r = self.client.get(f"/api/investigations/{case.id}/")
        body = r.json()
        obs = body["observable_group"]["observables"]
        self.assertEqual(obs[0]["value"], "8.8.8.8")
        self.assertEqual(obs[0]["sources"][0]["report_full"]["as_owner"], "Google LLC")

    def test_mail_case_has_no_observable_group_key(self):
        case = Case.objects.create(description="d", reporter=self.user)
        r = self.client.get(f"/api/investigations/{case.id}/")
        self.assertNotIn("observable_group", r.json())
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test api.tests.test_investigation_group -v 2`
Expected: FAIL — `KeyError: 'observable_group'`.

- [ ] **Step 3: Implement the serializer method**

`api/serializers/investigations.py` — add a `SerializerMethodField` on the detail serializer:

```python
    observable_group = serializers.SerializerMethodField()

    def get_observable_group(self, case):
        if not case.observable_group_id:
            return None  # rendered as absent by the view (see step 4)
        from score_process.scoring.sources import source_verdict_from_report
        try:
            from score_process.scoring.observable_engine import score_observable
        except ImportError:
            score_observable = None
        from cortex_job.models import AnalyzerReport

        _FIELD = {"URL": "url", "IP": "ip", "HASH": "hash", "DOMAIN": "domain"}
        observables = []
        for art in case.observable_group.artifacts.select_related("url", "ip", "hash", "domain"):
            obj = art.observable()
            if obj is None:
                continue
            field = _FIELD[art.artifact_type]
            reports = (AnalyzerReport.objects.filter(**{field: obj})
                       .select_related("analyzer").order_by("-creation_date"))
            seen, sources, svs = set(), [], []
            for rep in reports:
                if rep.analyzer_id in seen:
                    continue
                seen.add(rep.analyzer_id)
                sv = source_verdict_from_report(rep)
                svs.append(sv)
                sources.append({
                    "name": sv.name, "tier": sv.tier, "verdict": sv.verdict,
                    "confidence": sv.confidence, "evidence": sv.evidence,
                    "failed": sv.failed, "report_full": rep.report_full,
                })
            verdict = None
            if score_observable and svs:
                v = score_observable(svs)
                verdict = {"band": v.band, "confidence": v.confidence, "rationale": v.rationale}
            observables.append({
                "value": getattr(obj, "address", None) or getattr(obj, "value", None),
                "type": art.artifact_type.lower(),
                "verdict": verdict,
                "sources": sources,
            })
        return {"observables": observables}
```

- [ ] **Step 4: Drop the key for non-group cases**

`api/views/investigations.py`, where the detail payload is assembled:

```python
        data = serializer.data
        if data.get("observable_group") is None:
            data.pop("observable_group", None)
```

- [ ] **Step 5: Run tests + commit**

```bash
python manage.py test api.tests.test_investigation_group -v 2
git add Suspicious/Suspicious/api/serializers/investigations.py Suspicious/Suspicious/api/views/investigations.py Suspicious/Suspicious/api/tests/test_investigation_group.py
git commit -m "feat(api): expose observable group + report_full on the IOC road"
```

---

## Task 10: Frontend — IOC-group investigation layout

**Files:**
- Create: `suspicious-ui/src/features/investigation/observableGroup.ts` (Zod schema + `useObservableGroup` selector)
- Create: `suspicious-ui/src/features/investigation/SourceTable.tsx`
- Create: `suspicious-ui/src/features/investigation/ObservableGroupPanel.tsx`
- Modify: `suspicious-ui/src/pages/InvestigationPage.tsx`
- Test: `suspicious-ui/src/features/investigation/__tests__/ObservableGroupPanel.test.tsx`

**Interfaces:**
- Consumes: the `observable_group` payload from Task 9.
- Produces: when the investigation detail has `observable_group`, `InvestigationPage` renders `<ObservableGroupPanel>` instead of the mail layout: a verdict header with the `X / N trusted sources flagged this` ratio, a count strip, and one expandable row per observable containing `<SourceTable>`.

- [ ] **Step 1: Write the failing test**

`__tests__/ObservableGroupPanel.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { ObservableGroupPanel } from "../ObservableGroupPanel";

const group = {
  observables: [{
    value: "8.8.8.8", type: "ip",
    verdict: { band: "Safe", confidence: 90, rationale: ["GTI (authoritative) reports clean."] },
    sources: [
      { name: "GTI", tier: 1, verdict: "clean", confidence: 95, evidence: "0 detections", failed: false, report_full: {} },
      { name: "AbuseIPDB", tier: 3, verdict: "suspicious", confidence: 30, evidence: "conf 12%", failed: false, report_full: {} },
    ],
  }],
};

describe("ObservableGroupPanel", () => {
  it("shows the trusted-source ratio and per-observable verdict", () => {
    render(<ObservableGroupPanel group={group} />);
    expect(screen.getByText("8.8.8.8")).toBeInTheDocument();
    expect(screen.getByText(/1 \/ 2/)).toBeInTheDocument(); // 1 of 2 sources flagged
    expect(screen.getByText("Safe")).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd suspicious-ui && pnpm test ObservableGroupPanel`
Expected: FAIL — component missing.

- [ ] **Step 3: Build the components**

- `observableGroup.ts`: Zod schema matching the Task 9 payload; `export type ObservableGroup = z.infer<...>`.
- `SourceTable.tsx`: an MUI `<Table>` — columns *Source · Verdict · Evidence*, a verdict `<Chip>` colour-coded (`malicious`=error, `suspicious`=warning, `clean`=success, `no-data`=default), a tier badge, and a "details" disclosure that pretty-prints `report_full` (reuse whatever JSON viewer the app already has, else `<pre>`). **This component is also used by the mail page for embedded IOCs** — keep it prop-driven (`sources: Source[]`), no group coupling.
- `ObservableGroupPanel.tsx`: header with the worst-of band chip + confidence + a computed ratio string `${flagged} / ${total} sources flagged this` where `flagged = sources.filter(s => s.verdict === "malicious" || s.verdict === "suspicious").length`; a count strip from the observables' bands; an MUI `<Accordion>` per observable wrapping `<SourceTable>`; a "Full report" button linking to `/api/cases/${caseId}/report/`.

- [ ] **Step 4: Branch `InvestigationPage.tsx`**

Where the detail query resolves:

```tsx
const group = detailsQuery.data?.observable_group;
// ...
{group ? (
  <ObservableGroupPanel group={group} caseId={caseId} />
) : (
  /* existing mail/file layout */
)}
```

- [ ] **Step 5: Run tests + lint + commit**

```bash
cd suspicious-ui && pnpm test && pnpm lint
git add suspicious-ui/src/features/investigation/ suspicious-ui/src/pages/InvestigationPage.tsx
git commit -m "feat(ui): VT-style IOC-group investigation layout"
```

---

## Task 11: `GET /api/cases/<id>/report/` — downloadable report

**Files:**
- Create: `Suspicious/Suspicious/api/views/case_report.py`
- Create: `Suspicious/Suspicious/api/templates/case_report/report.html`
- Modify: `Suspicious/Suspicious/api/urls.py`
- Modify: `Suspicious/requirements.txt` (add `weasyprint`)
- Test: `Suspicious/Suspicious/api/tests/test_case_report.py`

**Interfaces:**
- Consumes: the same data assembled in Task 9 (`observable_group` payload) + case metadata.
- Produces: `GET /api/cases/<id>/report/?format=html|pdf` — `html` returns `text/html`; `pdf` returns `application/pdf` via WeasyPrint. `IsAuthenticated` + the same case-access permission the investigation detail view uses.

- [ ] **Step 1: Write the failing tests**

`api/tests/test_case_report.py`:

```python
from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from ip_process.models import IP
from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact


class CaseReportTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("u", password="p", is_staff=True)
        self.client = APIClient(); self.client.force_authenticate(self.user)
        g = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=IP.objects.create(address="8.8.8.8"))
        self.case = Case.objects.create(description="d", reporter=self.user, observable_group=g, results="Safe")

    def test_html_report(self):
        r = self.client.get(f"/api/cases/{self.case.id}/report/?format=html")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/html", r["Content-Type"])
        self.assertIn("8.8.8.8", r.content.decode())
        self.assertIn("Safe", r.content.decode())

    def test_pdf_report(self):
        r = self.client.get(f"/api/cases/{self.case.id}/report/?format=pdf")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r["Content-Type"], "application/pdf")
        self.assertTrue(r.content.startswith(b"%PDF"))

    def test_requires_auth(self):
        self.client.force_authenticate(None)
        self.assertEqual(self.client.get(f"/api/cases/{self.case.id}/report/").status_code, 401)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test api.tests.test_case_report -v 2`
Expected: FAIL — 404.

- [ ] **Step 3: Add `weasyprint` + the template**

`Suspicious/requirements.txt`: add `weasyprint==<latest 62.x>`. Run `pip install -r requirements.txt`.

`api/templates/case_report/report.html` — a self-contained styled document (inline `<style>`, print-friendly, theme-neutral; mirror the council-report layout: header block, verdict, per-observable sections with source tables and formatted `report_full`). Use Django template tags over `{{ case }}`, `{{ observables }}`, `{{ generated_at }}`.

- [ ] **Step 4: View + route**

`api/views/case_report.py`:

```python
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from django.http import HttpResponse
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from case_handler.models import Case


class CaseReportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, case_id):
        case = get_object_or_404(Case, pk=case_id)
        # reuse the observable-group assembly from the investigation serializer
        from api.serializers.investigations import InvestigationDetailSerializer  # or the method
        ctx = {
            "case": case,
            "observables": _assemble_observables(case),   # extract Task 9's logic into a shared helper
            "generated_at": timezone.now(),
        }
        html = render_to_string("case_report/report.html", ctx)
        if request.query_params.get("format") == "pdf":
            from weasyprint import HTML
            pdf = HTML(string=html).write_pdf()
            resp = HttpResponse(pdf, content_type="application/pdf")
            resp["Content-Disposition"] = f'attachment; filename="case-{case.id}-report.pdf"'
            return resp
        return HttpResponse(html, content_type="text/html")
```

Refactor Task 9's `get_observable_group` body into `api/utils/observable_report.py::assemble_observables(case)` and call it from both places (DRY).

`api/urls.py`:

```python
    path("cases/<int:case_id>/report/", CaseReportView.as_view(), name="case-report"),
```

- [ ] **Step 5: Run tests + commit**

```bash
python manage.py test api.tests.test_case_report -v 2
git add Suspicious/Suspicious/api/views/case_report.py Suspicious/Suspicious/api/templates/ Suspicious/Suspicious/api/urls.py Suspicious/Suspicious/api/utils/observable_report.py Suspicious/requirements.txt Suspicious/Suspicious/api/tests/test_case_report.py
git commit -m "feat(api): downloadable case report (HTML + PDF)"
```

---

## Task 12: Connector — one alert, N observables

**Files:**
- Modify: `Suspicious/Suspicious/connectors/contrib/thehive/phishing.py`
- Modify: the TheHive connector's `case_finalised` handler (grep `case_finalised` in `connectors/contrib/thehive/`)
- Test: `Suspicious/Suspicious/connectors/tests/test_thehive_group.py`

**Interfaces:**
- Consumes: `collect_case_targets(case)` (Task 4), `add_observables_to_item` (existing).
- Produces: for a group case, the TheHive connector creates one alert and attaches one observable per `collect_case_targets` entry.

- [ ] **Step 1: Write the failing test**

`connectors/tests/test_thehive_group.py`:

```python
from django.test import TestCase
from django.contrib.auth.models import User
from ip_process.models import IP
from case_handler.models import Case, ObservableGroup, ObservableGroupArtifact
from connectors.contrib.thehive.phishing import build_group_observables


class ThehiveGroupObservablesTests(TestCase):
    def test_builds_one_observable_per_target(self):
        u = User.objects.create_user("u", password="p")
        g = ObservableGroup.objects.create()
        for a in ("8.8.8.8", "1.1.1.1"):
            ObservableGroupArtifact.objects.create(group=g, artifact_type="IP", ip=IP.objects.create(address=a))
        case = Case.objects.create(description="d", reporter=u, observable_group=g)

        obs = build_group_observables(case)
        self.assertEqual(sorted(o["data"] for o in obs), ["1.1.1.1", "8.8.8.8"])
        self.assertTrue(all(o["dataType"] == "ip" for o in obs))
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test connectors.tests.test_thehive_group -v 2`
Expected: FAIL — `cannot import name 'build_group_observables'`.

- [ ] **Step 3: Implement**

`phishing.py`:

```python
_THEHIVE_DATATYPE = {"ip": "ip", "url": "url", "domain": "domain", "hash": "hash", "file": "file", "mail": "mail"}


def build_group_observables(case):
    from cortex_job.cortex_utils.case_targets import collect_case_targets
    out = []
    for inst, data_type in collect_case_targets(case):
        value = getattr(inst, "address", None) or getattr(inst, "value", None)
        if not value:
            continue
        out.append({
            "dataType": _THEHIVE_DATATYPE.get(data_type, "other"),
            "data": value,
            "message": f"Suspicious IOC-road observable ({data_type})",
            "tags": [f"suspicious:case:{case.id}"],
        })
    return out
```

In the `case_finalised` handler, after `create_new_alert(...)`, when `case.observable_group_id`:

```python
        observables = build_group_observables(case)
        if observables:
            add_observables_to_item("alert", alert_id, observables, thehive_url, api_key)
```

- [ ] **Step 4: Run tests + commit**

```bash
python manage.py test connectors -v 2
git add Suspicious/Suspicious/connectors/contrib/thehive/ Suspicious/Suspicious/connectors/tests/test_thehive_group.py
git commit -m "feat(connectors): TheHive alert carries all IOC-group observables"
```

---

## Task 13: End-to-end smoke test

**Files:**
- Create: `Suspicious/Suspicious/api/tests/test_ioc_road_e2e.py`

**Interfaces:** none new — exercises Tasks 1–12 together.

- [ ] **Step 1: Write the test**

```python
from unittest.mock import patch
from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from case_handler.models import Case


class IocRoadE2ETests(TestCase):
    @patch("cortex_job.cortex_utils.cortex_and_job_management.CortexJob.run", return_value=None)
    def test_submit_bulk_then_fetch_investigation(self, _run):
        u = User.objects.create_user("u", password="p", is_staff=True)
        c = APIClient(); c.force_authenticate(u)

        r = c.post("/api/submit/indicators/", {"indicators": "8.8.8.8\nhttp://a.test\n" + "a" * 64}, format="json")
        self.assertEqual(r.status_code, 201)
        case_id = r.json()["case_id"]

        case = Case.objects.get(id=case_id)
        self.assertEqual(case.observable_group.artifacts.count(), 3)

        detail = c.get(f"/api/investigations/{case_id}/").json()
        self.assertEqual(len(detail["observable_group"]["observables"]), 3)

        report = c.get(f"/api/cases/{case_id}/report/?format=html")
        self.assertEqual(report.status_code, 200)
        self.assertIn("8.8.8.8", report.content.decode())
```

- [ ] **Step 2: Run + commit**

```bash
python manage.py test api.tests.test_ioc_road_e2e -v 2
git add Suspicious/Suspicious/api/tests/test_ioc_road_e2e.py
git commit -m "test(api): IOC road end-to-end smoke (submit -> investigate -> report)"
```

---

## Task 14: Playwright — submit indicators flow

**Files:**
- Create: `suspicious-ui/e2e/ioc-road.spec.ts`

- [ ] **Step 1: Write the spec**

```typescript
import { test, expect } from "@playwright/test";

test("bulk indicator submission lands on a group investigation", async ({ page }) => {
  await page.goto("/submit");
  await page.getByRole("button", { name: /indicators/i }).click();
  await page.getByRole("textbox").fill("8.8.8.8\n1.1.1.1\nhttp://example.test");
  await expect(page.getByText(/3 indicators/i)).toBeVisible();
  await page.getByRole("button", { name: /^submit$/i }).click();
  await expect(page).toHaveURL(/\/investigations\/\d+/);
  await expect(page.getByText("8.8.8.8")).toBeVisible();
});
```

- [ ] **Step 2: Run against the dev stack + commit**

```bash
cd suspicious-ui && pnpm test:e2e ioc-road
git add suspicious-ui/e2e/ioc-road.spec.ts
git commit -m "test(e2e): IOC road submission flow"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task(s) |
|---|---|
| §3.1 `ObservableGroup` + `ObservableGroupArtifact` | 1 |
| §3.2 `Case.observable_group`, no repoint | 2 |
| §3.3 migrations (additive) | 1, 2 |
| §4.1 two roads UI | 8 |
| §4.2 `SubmitIndicatorsView` | 6, 7 |
| §4.3 `CaseCreator` changes | 3 |
| §5 `collect_case_targets` branch | 4 |
| §6 scoring wiring | 5 (+ sibling plan Task 13 for the verdict) |
| §7 IP allow-list | sibling plan Tasks 4–6 |
| §8.1 in-app IOC view | 10 |
| §8.2 API — `observable_group` + `report_full` | 9 |
| §8.3 full report endpoint | 11 |
| §9 bulk concerns (cap, KPI, notification) | 7 (cap), 3/5 (one case = one KPI row / one email — inherited) |
| §10 connectors | 12 |
| §11 out of scope | not implemented (correct) |
| §12 testing | every task + 13, 14 |
| §13 sequencing | task order |

**Placeholder scan:** Task 6 `_classify` and Task 11 `_assemble_observables` / template say "adjust import path" / "extract Task 9's logic" — these are concrete refactors with the target named, not open questions. The report template body (Task 11 Step 3) is described by its sections and reference layout rather than given verbatim — acceptable for an HTML template, but the implementer should produce real markup, not a stub. All Python/TS logic steps have runnable code.

**Type consistency:**
- `ParsedIndicator` (`raw, value, type`) — identical in Task 6 (Python) and Task 8 (`parseIndicators.ts`, camelCase-free, same fields).
- `ObservableGroupArtifact.observable()` — defined Task 1, used Tasks 3, 4, 5, 9.
- `_FIELD`/`_MODEL` maps — Task 5, 7, 9 each define their own local copy (intentional — small, avoids a shared-import dependency between apps).
- The `observable_group` payload shape (`{observables: [{value, type, verdict, sources}]}`) — produced Task 9, consumed Tasks 10, 11.
- `source_verdict_from_report` / `score_observable` — **owned by the sibling plan (Tasks 8, 9).** Tasks 9 and 11 import them lazily and degrade to `verdict: null` if absent, so this plan can land first; the computed per-observable verdict appears once the sibling plan merges.

**Cross-plan dependency:** this plan's Tasks 1–8, 12, 14 stand alone. Tasks 9–11, 13 render `verdict: null` until the sibling plan's `observable_engine` exists — functional but incomplete. Recommended merge order: sibling plan Tasks 1–12 → this plan Tasks 1–14 → sibling plan Task 13.
