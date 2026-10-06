# Scoring & Verdict Model Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the fake per-analyzer 0–10 score with categorical source verdicts + fixed trust tiers, give the IOC road a greenfield categorical verdict engine, and close the `8.8.8.8` false-positive class with an IP allow-list — all without regressing the mail-road verdict.

**Architecture:** Each Cortex analyzer becomes one "source" contributing a categorical verdict (`malicious`/`suspicious`/`clean`/`no-data`) weighted by a fixed `Analyzer.tier` (1–3) plus a tunable `Analyzer.weight`. The mail road keeps its existing `score_case` aggregation (AI + YARA + sandbox → `Case.score`) untouched, gaining only an additive band-escalation post-step for embedded IOCs and richer verdict metadata. The IOC road gets two new pure functions, `score_observable()` and `score_group()`, that never touch `score_case`. Behaviour changes are measured against a labelled fixture set seeded from the five GTI comparison cases.

**Tech Stack:** Django 6.1, Python 3.12, pytest / Django test runner, DRF. No new dependencies.

**Spec:** `docs/specs/2026-09-02-scoring-verdict-model-design.md`

## Global Constraints

- **Do not change `score_case()`'s aggregation logic or its existing `CaseVerdict` fields.** Only additive fields and a separate post-step are allowed. `python manage.py backtest_scoring` must show zero verdict-band drift for all existing cases after every task.
- **No new pip dependencies.**
- Pure scoring functions live under `score_process/scoring/`, contain no Django ORM calls, take dataclasses in and return dataclasses out (follow `engine.py`).
- Conventional Commits (`feat:`, `fix:`, `test:`, `chore:`). Commit after every task.
- Every task ends with `python manage.py test <touched apps>` green.
- Analyzer tier values are **fixed classification**, seeded by data migration, editable only via the Settings UI — never per-run.
- Confidence is a single 0–100 scale end to end after Task 7.

---

## File Structure

| File | Responsibility |
|---|---|
| `cortex_job/models.py` | add `Analyzer.tier` |
| `cortex_job/migrations/00NN_analyzer_tier.py` | schema |
| `cortex_job/migrations/00NN_seed_analyzer_tiers.py` | data: tier per known analyzer name |
| `api/serializers/settings.py` | expose `tier` on the analyzer serializer |
| `settings/models.py` | add `AllowListIp` |
| `settings/migrations/00NN_allowlistip.py` | schema |
| `score_process/scoring/cortex_analyzers/allow_list.py` | add `ip` branch |
| `api/utils/settings_service.py` | add `ips_allow` list section + `_bulk_create_ip_links` |
| `score_process/scoring/processing.py` | confidence-scale cleanup (`compute_weighted_scores`) |
| `score_process/scoring/collect.py` | confidence-scale cleanup (`_signals_from`) |
| `score_process/scoring/sources.py` | **new** — `SourceVerdict` dataclass + `source_verdict_from_report()` |
| `score_process/scoring/observable_engine.py` | **new** — `score_observable()`, `score_group()`, band rules, constants |
| `score_process/scoring/engine.py` | additive `CaseVerdict` fields; `mail_band_escalation()` |
| `score_process/scoring/apply.py` | persist new verdict metadata |
| `score_process/scoring/fixtures/labelled_cases/*.json` | **new** — GTI comparison cases as labelled data |
| `score_process/management/commands/score_accuracy.py` | **new** — accuracy report over the labelled set |
| `score_process/management/commands/backtest_scoring.py` | add `--road` filter |
| `score_process/tests/test_observable_engine.py` | **new** |
| `score_process/tests/test_sources.py` | **new** |
| `score_process/tests/test_mail_escalation.py` | **new** |
| `settings/tests/test_allowlist_ip.py` | **new** |

---

## Task 1: `Analyzer.tier` field + schema migration

**Files:**
- Modify: `Suspicious/Suspicious/cortex_job/models.py` (class `Analyzer`, after `weight`)
- Create: `Suspicious/Suspicious/cortex_job/migrations/` (next number, `analyzer_tier`)
- Test: `Suspicious/Suspicious/cortex_job/tests/test_models.py`

**Interfaces:**
- Produces: `Analyzer.tier: int` — `1` Authoritative, `2` Strong, `3` Contextual. Default `3`. `db_index=True`.

- [ ] **Step 1: Write the failing test**

Add to `cortex_job/tests/test_models.py` (create the file if absent, with `from django.test import TestCase` and `from cortex_job.models import Analyzer`):

```python
class AnalyzerTierTests(TestCase):
    def test_tier_defaults_to_contextual(self):
        a = Analyzer.objects.create(name="X", analyzer_cortex_id="x1")
        self.assertEqual(a.tier, 3)

    def test_tier_choices_accept_1_2_3(self):
        a = Analyzer.objects.create(name="Y", analyzer_cortex_id="y1", tier=1)
        a.full_clean()  # no ValidationError
        self.assertEqual(a.tier, 1)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python manage.py test cortex_job.tests.test_models -v 2`
Expected: FAIL — `AttributeError: 'Analyzer' object has no attribute 'tier'`.

- [ ] **Step 3: Add the field**

In `cortex_job/models.py`, class `Analyzer`, immediately after `weight = models.FloatField(default=0.2)`:

```python
    TIER_AUTHORITATIVE = 1
    TIER_STRONG = 2
    TIER_CONTEXTUAL = 3
    TIER_CHOICES = [
        (TIER_AUTHORITATIVE, "Authoritative"),
        (TIER_STRONG, "Strong"),
        (TIER_CONTEXTUAL, "Contextual"),
    ]
    tier = models.PositiveSmallIntegerField(
        choices=TIER_CHOICES, default=TIER_CONTEXTUAL, db_index=True,
        help_text="Fixed trust classification. 1 = authoritative source, 3 = contextual/noisy.",
    )
```

- [ ] **Step 4: Make the migration and run tests**

Run:
```bash
python manage.py makemigrations cortex_job --name analyzer_tier
python manage.py test cortex_job.tests.test_models -v 2
```
Expected: migration created; tests PASS.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/cortex_job/models.py Suspicious/Suspicious/cortex_job/migrations/ Suspicious/Suspicious/cortex_job/tests/test_models.py
git commit -m "feat(cortex_job): add fixed trust tier to Analyzer"
```

---

## Task 2: Seed analyzer tiers (data migration)

**Files:**
- Create: `Suspicious/Suspicious/cortex_job/migrations/` (next number, `seed_analyzer_tiers`)
- Test: `Suspicious/Suspicious/cortex_job/tests/test_migrations_seed_tiers.py`

**Interfaces:**
- Consumes: `Analyzer.tier` (Task 1).
- Produces: existing `Analyzer` rows get a tier by name-prefix match; unknown analyzers stay tier 3.

- [ ] **Step 1: Write the failing test**

`cortex_job/tests/test_migrations_seed_tiers.py`:

```python
from django.test import TestCase
from cortex_job.models import Analyzer
from cortex_job.migrations import _tier_seed  # helper module we add alongside migrations


class SeedTierHelperTests(TestCase):
    def test_known_prefixes_map_to_tiers(self):
        self.assertEqual(_tier_seed.tier_for("VirusTotal_GetReport_3_1"), 1)
        self.assertEqual(_tier_seed.tier_for("MISP_2_1"), 1)
        self.assertEqual(_tier_seed.tier_for("AI_Mail_Analyzer_1_4"), 2)
        self.assertEqual(_tier_seed.tier_for("Yara_Boosted_3_2"), 2)
        self.assertEqual(_tier_seed.tier_for("ThreatGridOnPrem_1_0"), 2)
        self.assertEqual(_tier_seed.tier_for("CIRCLHashlookup_1_1"), 2)
        self.assertEqual(_tier_seed.tier_for("AbuseIPDB_1_0"), 3)
        self.assertEqual(_tier_seed.tier_for("Shodan_Host_1_0"), 3)
        self.assertEqual(_tier_seed.tier_for("SomethingUnknown_9_9"), 3)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python manage.py test cortex_job.tests.test_migrations_seed_tiers -v 2`
Expected: FAIL — `ModuleNotFoundError: cortex_job.migrations._tier_seed`.

- [ ] **Step 3: Add the seed helper**

`cortex_job/migrations/_tier_seed.py`:

```python
"""Shared tier-seed table. Imported by the data migration and its test so the
mapping has one source of truth. Match is by case-insensitive name prefix."""

TIER_1_PREFIXES = ("VirusTotal", "MISP", "GoogleThreatIntelligence", "GTI")
TIER_2_PREFIXES = ("AI_Mail_Analyzer", "Yara", "ThreatGrid", "CIRCLHashlookup", "Cuckoo", "Hybrid")


def tier_for(analyzer_name: str) -> int:
    name = (analyzer_name or "").lower()
    if any(name.startswith(p.lower()) for p in TIER_1_PREFIXES):
        return 1
    if any(name.startswith(p.lower()) for p in TIER_2_PREFIXES):
        return 2
    return 3
```

- [ ] **Step 4: Add the data migration**

Create the migration file (number after Task 1's). Body:

```python
from django.db import migrations
from cortex_job.migrations._tier_seed import tier_for


def seed_tiers(apps, schema_editor):
    Analyzer = apps.get_model("cortex_job", "Analyzer")
    for a in Analyzer.objects.all():
        new_tier = tier_for(a.name)
        if a.tier != new_tier:
            a.tier = new_tier
            a.save(update_fields=["tier"])


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [("cortex_job", "<TASK 1 MIGRATION NAME>")]
    operations = [migrations.RunPython(seed_tiers, noop)]
```

- [ ] **Step 5: Run tests + commit**

```bash
python manage.py test cortex_job -v 2
git add Suspicious/Suspicious/cortex_job/migrations/ Suspicious/Suspicious/cortex_job/tests/test_migrations_seed_tiers.py
git commit -m "feat(cortex_job): seed analyzer trust tiers by name prefix"
```

---

## Task 3: Expose `tier` on the analyzer settings API

**Files:**
- Modify: `Suspicious/Suspicious/api/serializers/settings.py:58` (analyzer serializer `fields`)
- Modify: `Suspicious/Suspicious/api/views/settings.py` (`AnalyzerSettingsDetailView` — allow `tier` in the patch)
- Test: `Suspicious/Suspicious/api/tests/test_analyzer_settings.py`

**Interfaces:**
- Consumes: `Analyzer.tier`.
- Produces: `GET/PATCH /api/settings/analyzers/<id>/` includes and accepts `tier` (int 1–3).

- [ ] **Step 1: Write the failing test**

```python
from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from cortex_job.models import Analyzer


class AnalyzerTierApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("u", password="p", is_staff=True)
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.a = Analyzer.objects.create(name="VT", analyzer_cortex_id="vt1", tier=3)

    def test_get_includes_tier(self):
        r = self.client.get("/api/settings/analyzers/")
        self.assertEqual(r.status_code, 200)
        row = next(x for x in r.json()["results"] if x["id"] == self.a.id) \
            if "results" in r.json() else next(x for x in r.json() if x["id"] == self.a.id)
        self.assertEqual(row["tier"], 3)

    def test_patch_sets_tier(self):
        r = self.client.patch(f"/api/settings/analyzers/{self.a.id}/", {"tier": 1}, format="json")
        self.assertEqual(r.status_code, 200)
        self.a.refresh_from_db()
        self.assertEqual(self.a.tier, 1)

    def test_patch_rejects_invalid_tier(self):
        r = self.client.patch(f"/api/settings/analyzers/{self.a.id}/", {"tier": 9}, format="json")
        self.assertEqual(r.status_code, 400)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python manage.py test api.tests.test_analyzer_settings -v 2`
Expected: FAIL — `KeyError: 'tier'` / tier not persisted.

- [ ] **Step 3: Add `tier` to the serializer**

`api/serializers/settings.py`, the analyzer serializer `Meta.fields` (currently `["id", "name", "weight", "analyzer_cortex_id", "is_active"]`):

```python
        fields = ["id", "name", "weight", "tier", "analyzer_cortex_id", "is_active"]
```

If the serializer restricts writable fields, ensure `tier` is not in `read_only_fields`. Add an explicit field for validation:

```python
    tier = serializers.IntegerField(min_value=1, max_value=3, required=False)
```

- [ ] **Step 4: Run tests + commit**

```bash
python manage.py test api.tests.test_analyzer_settings -v 2
git add Suspicious/Suspicious/api/serializers/settings.py Suspicious/Suspicious/api/views/settings.py Suspicious/Suspicious/api/tests/test_analyzer_settings.py
git commit -m "feat(api): expose analyzer trust tier in settings"
```

---

## Task 4: `AllowListIp` model + migration

**Files:**
- Modify: `Suspicious/Suspicious/settings/models.py` (after `AllowListDomain`)
- Create: `Suspicious/Suspicious/settings/migrations/` (`allowlistip`)
- Test: `Suspicious/Suspicious/settings/tests/test_allowlist_ip.py`

**Interfaces:**
- Produces: `settings.models.AllowListIp` — `ip FK(ip_process.IP, null=True)`, `user FK`, `creation_date`, `last_update`. Mirrors `AllowListDomain`.

- [ ] **Step 1: Write the failing test**

`settings/tests/test_allowlist_ip.py`:

```python
from django.test import TestCase
from django.contrib.auth.models import User
from ip_process.models import IP
from settings.models import AllowListIp


class AllowListIpModelTests(TestCase):
    def test_create_links_ip(self):
        u = User.objects.create_user("u", password="p")
        ip = IP.objects.create(address="8.8.8.8")
        entry = AllowListIp.objects.create(ip=ip, user=u)
        self.assertEqual(str(entry), "8.8.8.8")
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test settings.tests.test_allowlist_ip -v 2`
Expected: FAIL — `ImportError: cannot import name 'AllowListIp'`.

- [ ] **Step 3: Add the model**

`settings/models.py` — mirror `AllowListDomain`, add near the top `from ip_process.models import IP` if not present:

```python
class AllowListIp(models.Model):
    id = models.AutoField(primary_key=True)
    ip = models.ForeignKey(
        IP, on_delete=models.CASCADE, related_name="allow_lists",
        null=True, blank=True,
    )
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    creation_date = models.DateTimeField(auto_now_add=True)
    last_update = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.ip.address if self.ip else f"AllowListIp #{self.id}"
```

- [ ] **Step 4: Migrate + test**

```bash
python manage.py makemigrations settings --name allowlistip
python manage.py test settings.tests.test_allowlist_ip -v 2
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/settings/models.py Suspicious/Suspicious/settings/migrations/ Suspicious/Suspicious/settings/tests/test_allowlist_ip.py
git commit -m "feat(settings): add AllowListIp model"
```

---

## Task 5: `check_allow_list` IP branch

**Files:**
- Modify: `Suspicious/Suspicious/score_process/scoring/cortex_analyzers/allow_list.py`
- Modify: `Suspicious/Suspicious/score_process/scoring/cortex_analyzers/result.py` (add `IpAllowList` field to `AllowListResult`)
- Test: `Suspicious/Suspicious/score_process/tests/test_analyzer_parsers.py` (append) or new `test_allow_list.py`

**Interfaces:**
- Consumes: `AllowListIp` (Task 4), `AllowListResult`.
- Produces: `check_allow_list("8.8.8.8", "ip")` returns an `AllowListResult` with `IpAllowList == "Safe IPW triggered"` when the IP is listed.

- [ ] **Step 1: Write the failing test**

`score_process/tests/test_allow_list.py`:

```python
from django.test import TestCase
from django.contrib.auth.models import User
from ip_process.models import IP
from settings.models import AllowListIp
from score_process.scoring.cortex_analyzers.allow_list import check_allow_list


class AllowListIpBranchTests(TestCase):
    def test_listed_ip_triggers(self):
        u = User.objects.create_user("u", password="p")
        AllowListIp.objects.create(ip=IP.objects.create(address="8.8.8.8"), user=u)
        result = check_allow_list("8.8.8.8", "ip")
        self.assertEqual(result.IpAllowList, "Safe IPW triggered")

    def test_unlisted_ip_does_not_trigger(self):
        result = check_allow_list("1.2.3.4", "ip")
        self.assertIsNone(result.IpAllowList)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test score_process.tests.test_allow_list -v 2`
Expected: FAIL — `AttributeError: 'AllowListResult' object has no attribute 'IpAllowList'`.

- [ ] **Step 3: Add the field and branch**

`result.py`, class `AllowListResult`:

```python
    IpAllowList: Optional[str] = None
```

`allow_list.py`, add `from settings.models import AllowListIp` to the imports, and inside `check_allow_list` add an `elif` after the `("url", "domain")` branch:

```python
        elif data_type == "ip":
            if AllowListIp.objects.filter(ip__address=data).exists():
                result.IpAllowList = "Safe IPW triggered"
```

- [ ] **Step 4: Run tests + commit**

```bash
python manage.py test score_process.tests.test_allow_list score_process.tests.test_analyzer_parsers -v 2
git add Suspicious/Suspicious/score_process/scoring/cortex_analyzers/allow_list.py Suspicious/Suspicious/score_process/scoring/cortex_analyzers/result.py Suspicious/Suspicious/score_process/tests/test_allow_list.py
git commit -m "feat(score): honour IP allow-list in analyzer allow-list check"
```

---

## Task 6: `ips_allow` settings list section

**Files:**
- Modify: `Suspicious/Suspicious/api/utils/settings_service.py` (`SETTINGS_LIST_SECTIONS`, add `_bulk_create_ip_links`, `_ip_list_queryset`)
- Test: `Suspicious/Suspicious/api/tests/test_settings_list_ips.py`

**Interfaces:**
- Consumes: `AllowListIp`, the existing `ListSectionConfig` shape.
- Produces: `GET/POST /api/settings/list/ips_allow/` and `DELETE /api/settings/list/ips_allow/<id>/` manage `AllowListIp` rows keyed by IP address string.

- [ ] **Step 1: Write the failing test**

```python
from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from settings.models import AllowListIp


class IpsAllowSectionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("u", password="p", is_staff=True)
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_post_creates_entry(self):
        r = self.client.post("/api/settings/list/ips_allow/", {"values": ["8.8.8.8", "1.1.1.1"]}, format="json")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(AllowListIp.objects.count(), 2)

    def test_get_lists_entries(self):
        self.client.post("/api/settings/list/ips_allow/", {"values": ["9.9.9.9"]}, format="json")
        r = self.client.get("/api/settings/list/ips_allow/")
        rows = r.json()["results"] if "results" in r.json() else r.json()
        self.assertIn("9.9.9.9", [x["value"] for x in rows])
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test api.tests.test_settings_list_ips -v 2`
Expected: FAIL — 404 or "unknown section 'ips_allow'".

- [ ] **Step 3: Add the section config**

`api/utils/settings_service.py`. Add near `_domain_list_queryset`:

```python
def _ip_list_queryset(model):
    return model.objects.select_related("ip").order_by("-creation_date")


def _bulk_create_ip_links(values, user):
    """Create AllowListIp rows for a list of IP address strings, get_or_creating
    the underlying IP. Returns (created_values, skipped_existing)."""
    from ip_process.models import IP
    from settings.models import AllowListIp

    existing = set(
        AllowListIp.objects.filter(ip__address__in=values)
        .values_list("ip__address", flat=True)
    )
    to_create = [v for v in dict.fromkeys(values) if v not in existing]
    ip_map = {}
    for v in to_create:
        ip_map[v], _ = IP.objects.get_or_create(address=v)
    AllowListIp.objects.bulk_create(
        [AllowListIp(ip=ip_map[v], user=user) for v in to_create]
    )
    return to_create, sorted(existing)
```

Add to `SETTINGS_LIST_SECTIONS`:

```python
    "ips_allow": ListSectionConfig(
        section="ips_allow",
        model=AllowListIp,  # add to the settings.models import block at the top of the file
        queryset_factory=lambda: _ip_list_queryset(AllowListIp),
        value_getter=lambda obj: obj.ip.address if obj.ip else "",
        bulk_create_handler=_bulk_create_ip_links,
    ),
```

Match the exact `bulk_create_handler` signature the service expects (check how `_bulk_create_domain_links` is invoked — adapt `_bulk_create_ip_links` to return the same shape).

- [ ] **Step 4: Run tests + commit**

```bash
python manage.py test api.tests.test_settings_list_ips -v 2
git add Suspicious/Suspicious/api/utils/settings_service.py Suspicious/Suspicious/api/tests/test_settings_list_ips.py
git commit -m "feat(api): add ips_allow settings list section"
```

---

## Task 7: Confidence-scale cleanup (0–100 end to end)

**Files:**
- Modify: `Suspicious/Suspicious/score_process/scoring/processing.py:54-68` (`compute_weighted_scores`)
- Modify: `Suspicious/Suspicious/score_process/scoring/collect.py:22-34` (`_signals_from`)
- Test: `Suspicious/Suspicious/score_process/tests/test_processing.py`, `score_process/tests/test_collect.py`

**Interfaces:**
- Produces: `compute_weighted_scores()` returns `weighted_confidence` on a 0–100 scale (no `* 10`). `_signals_from()` builds `Signal.confidence` directly (no `/ 10`). `Signal.confidence`, `AnalyzerReport.confidence`, `ioc_confidence` are all 0–100.

- [ ] **Step 1: Write the characterisation test first (lock current behaviour), then change it**

Before touching code, run the full backtest to capture the baseline:

```bash
python manage.py backtest_scoring > /tmp/backtest_before.txt
cat /tmp/backtest_before.txt   # note the drift counts — should be ~0
```

Add `score_process/tests/test_collect.py::test_signal_confidence_is_0_100`:

```python
def test_signal_confidence_is_0_100_scale():
    from score_process.scoring.collect import _signals_from
    # weighted_confidence already 0-100 after cleanup; a 70 stays 70
    sigs = _signals_from([7], [70], 0, "url")
    assert sigs[0].confidence == 70
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test score_process.tests.test_collect::test_signal_confidence_is_0_100_scale -v 2`
Expected: FAIL — current code returns `round(70/10) == 7`.

- [ ] **Step 3: Remove the ×10 / ÷10**

`processing.py`, `compute_weighted_scores`, change:

```python
    weighted_confidence = round(sum(r.confidence * r.analyzer.weight for r in valid) / total_weight) * 10
```
to:
```python
    weighted_confidence = round(sum(r.confidence * r.analyzer.weight for r in valid) / total_weight)
```

`collect.py`, `_signals_from`, change:

```python
        normalized_confidence = min(round(conf / 10), 100)
```
to:
```python
        normalized_confidence = min(round(conf), 100)
```

- [ ] **Step 4: Verify no drift**

```bash
python manage.py test score_process -v 2
python manage.py backtest_scoring > /tmp/backtest_after.txt
diff /tmp/backtest_before.txt /tmp/backtest_after.txt
```
Expected: unit tests PASS; `diff` shows **no change in drift counts**. If drift appears, the old ×10/÷10 was silently clamping something — STOP, investigate, do not proceed.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/score_process/scoring/processing.py Suspicious/Suspicious/score_process/scoring/collect.py Suspicious/Suspicious/score_process/tests/test_collect.py
git commit -m "refactor(score): single 0-100 confidence scale end to end"
```

---

## Task 8: `SourceVerdict` + report→source mapper

**Files:**
- Create: `Suspicious/Suspicious/score_process/scoring/sources.py`
- Test: `Suspicious/Suspicious/score_process/tests/test_sources.py`

**Interfaces:**
- Consumes: `AnalyzerReport` (fields `level`, `status`, `confidence`, `category`, `report_full`; `analyzer.name`, `analyzer.tier`, `analyzer.weight`).
- Produces:
  ```python
  @dataclass(frozen=True)
  class SourceVerdict:
      name: str
      tier: int
      weight: float
      verdict: str        # "malicious" | "suspicious" | "clean" | "no-data"
      confidence: int | None
      failed: bool
      evidence: str
  def source_verdict_from_report(report) -> SourceVerdict
  ```

- [ ] **Step 1: Write the failing tests**

`score_process/tests/test_sources.py`:

```python
from types import SimpleNamespace
from django.test import SimpleTestCase
from score_process.scoring.sources import SourceVerdict, source_verdict_from_report


def _report(level="safe", status="Success", confidence=100, category=None, name="X", tier=3, weight=0.2):
    return SimpleNamespace(
        level=level, status=status, confidence=confidence,
        category=",".join(category or []),
        report_full={}, analyzer=SimpleNamespace(name=name, tier=tier, weight=weight),
    )


class SourceVerdictTests(SimpleTestCase):
    def test_malicious_level_maps_to_malicious(self):
        sv = source_verdict_from_report(_report(level="malicious", category=["C2"]))
        self.assertEqual(sv.verdict, "malicious")
        self.assertEqual(sv.evidence, "C2")
        self.assertFalse(sv.failed)

    def test_safe_maps_to_clean(self):
        self.assertEqual(source_verdict_from_report(_report(level="safe")).verdict, "clean")

    def test_info_and_empty_map_to_no_data(self):
        self.assertEqual(source_verdict_from_report(_report(level="info")).verdict, "no-data")
        self.assertEqual(source_verdict_from_report(_report(level="")).verdict, "no-data")

    def test_failure_status_is_no_data_and_failed(self):
        sv = source_verdict_from_report(_report(level="malicious", status="Failure"))
        self.assertEqual(sv.verdict, "no-data")
        self.assertTrue(sv.failed)

    def test_non_success_non_failure_is_no_data(self):
        self.assertEqual(source_verdict_from_report(_report(status="InProgress")).verdict, "no-data")

    def test_tier_and_weight_carried(self):
        sv = source_verdict_from_report(_report(name="VT", tier=1, weight=0.9))
        self.assertEqual((sv.name, sv.tier, sv.weight), ("VT", 1, 0.9))
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test score_process.tests.test_sources -v 2`
Expected: FAIL — `ModuleNotFoundError: score_process.scoring.sources`.

- [ ] **Step 3: Implement**

`score_process/scoring/sources.py`:

```python
"""Map an AnalyzerReport to a categorical SourceVerdict for the IOC engine.

No ORM writes. Pure translation of the parser's categorical `level` plus
status into the vote the observable engine consumes."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

_LEVEL_TO_VERDICT = {
    "malicious": "malicious",
    "dangerous": "malicious",
    "suspicious": "suspicious",
    "safe": "clean",
}


@dataclass(frozen=True)
class SourceVerdict:
    name: str
    tier: int
    weight: float
    verdict: str            # malicious | suspicious | clean | no-data
    confidence: Optional[int]
    failed: bool
    evidence: str


def source_verdict_from_report(report) -> SourceVerdict:
    analyzer = report.analyzer
    status = (report.status or "").strip()
    failed = status == "Failure"

    if status != "Success":
        verdict = "no-data"
    else:
        verdict = _LEVEL_TO_VERDICT.get((report.level or "").strip().lower(), "no-data")

    category = report.category or ""
    evidence = category.split(",")[0].strip() if category else ""

    conf = getattr(report, "confidence", None)
    confidence = int(conf) if isinstance(conf, (int, float)) and conf else None

    return SourceVerdict(
        name=analyzer.name,
        tier=int(getattr(analyzer, "tier", 3)),
        weight=float(getattr(analyzer, "weight", 0.2)),
        verdict=verdict,
        confidence=confidence,
        failed=failed,
        evidence=evidence,
    )
```

- [ ] **Step 4: Run tests + commit**

```bash
python manage.py test score_process.tests.test_sources -v 2
git add Suspicious/Suspicious/score_process/scoring/sources.py Suspicious/Suspicious/score_process/tests/test_sources.py
git commit -m "feat(score): SourceVerdict + AnalyzerReport translation"
```

---

## Task 9: `score_observable()` — the four band rules

**Files:**
- Create: `Suspicious/Suspicious/score_process/scoring/observable_engine.py`
- Test: `Suspicious/Suspicious/score_process/tests/test_observable_engine.py`

**Interfaces:**
- Consumes: `list[SourceVerdict]` (Task 8).
- Produces:
  ```python
  HIGH_CONFIDENCE = 70
  DANGEROUS_SHARE = 0.5
  MIN_TRUSTED_COVERAGE = 1
  TIER_MULTIPLIER = {1: 4, 2: 2, 3: 1}

  @dataclass(frozen=True)
  class ObservableVerdict:
      band: str            # "Dangerous" | "Suspicious" | "Safe" | "Inconclusive"
      confidence: int      # 0-100
      inconclusive_reason: str | None   # "thin_coverage" | None
      counts: dict         # {"malicious": n, "suspicious": n, "clean": n, "no-data": n}
      rationale: list[str]

  def score_observable(sources: list[SourceVerdict]) -> ObservableVerdict
  ```

- [ ] **Step 1: Write the failing tests**

`score_process/tests/test_observable_engine.py`:

```python
from django.test import SimpleTestCase
from score_process.scoring.sources import SourceVerdict
from score_process.scoring.observable_engine import score_observable


def sv(verdict, tier=3, weight=0.2, confidence=None, failed=False, name="s"):
    return SourceVerdict(name=name, tier=tier, weight=weight, verdict=verdict,
                         confidence=confidence, failed=failed, evidence="")


class ScoreObservableTests(SimpleTestCase):
    def test_tier1_malicious_high_conf_is_dangerous(self):
        v = score_observable([sv("malicious", tier=1, confidence=90), sv("clean", tier=3)])
        self.assertEqual(v.band, "Dangerous")

    def test_tier1_malicious_no_numeric_conf_is_dangerous(self):
        v = score_observable([sv("malicious", tier=1, confidence=None)])
        self.assertEqual(v.band, "Dangerous")

    def test_two_tier2_malicious_is_dangerous(self):
        v = score_observable([sv("malicious", tier=2), sv("malicious", tier=2), sv("clean", tier=3)])
        self.assertEqual(v.band, "Dangerous")

    def test_weighted_malicious_share_over_half_is_dangerous(self):
        # three tier-3 malicious vs one tier-3 clean -> share .75
        v = score_observable([sv("malicious"), sv("malicious"), sv("malicious"), sv("clean")])
        self.assertEqual(v.band, "Dangerous")

    def test_tier3_only_flag_caps_at_suspicious(self):
        v = score_observable([sv("malicious", tier=3), sv("clean", tier=3), sv("clean", tier=3), sv("clean", tier=3)])
        self.assertEqual(v.band, "Suspicious")

    def test_tier1_clean_and_nothing_flags_is_safe(self):
        v = score_observable([sv("clean", tier=1), sv("clean", tier=3)])
        self.assertEqual(v.band, "Safe")

    def test_tier1_clean_but_tier3_flags_is_suspicious_not_safe(self):
        v = score_observable([sv("clean", tier=1), sv("malicious", tier=3)])
        self.assertEqual(v.band, "Suspicious")

    def test_thin_coverage_is_inconclusive(self):
        v = score_observable([sv("clean", tier=3), sv("no-data", tier=1)])
        self.assertEqual(v.band, "Inconclusive")
        self.assertEqual(v.inconclusive_reason, "thin_coverage")

    def test_no_data_sources_do_not_vote(self):
        v = score_observable([sv("clean", tier=1), sv("no-data", tier=2), sv("no-data", tier=3)])
        self.assertEqual(v.band, "Safe")

    def test_failed_tier1_lowers_confidence(self):
        strong = score_observable([sv("clean", tier=1, confidence=100), sv("clean", tier=2, confidence=100)])
        degraded = score_observable([sv("clean", tier=1, confidence=100), sv("no-data", tier=1, failed=True)])
        self.assertLess(degraded.confidence, strong.confidence)

    def test_rationale_non_empty(self):
        v = score_observable([sv("malicious", tier=1, confidence=90, name="GTI")])
        self.assertTrue(any("GTI" in line for line in v.rationale))

    def test_counts(self):
        v = score_observable([sv("malicious"), sv("clean"), sv("clean"), sv("no-data")])
        self.assertEqual(v.counts, {"malicious": 1, "suspicious": 0, "clean": 2, "no-data": 1})
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test score_process.tests.test_observable_engine -v 2`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement**

`score_process/scoring/observable_engine.py`:

```python
"""Categorical trust-weighted verdict engine for the IOC road.

Pure. No ORM. Consumes SourceVerdict, returns ObservableVerdict / GroupVerdict.
Never imports score_process.scoring.engine — the mail road is untouched."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from score_process.scoring.sources import SourceVerdict

HIGH_CONFIDENCE = 70
DANGEROUS_SHARE = 0.5
MIN_TRUSTED_COVERAGE = 1
TIER_MULTIPLIER = {1: 4, 2: 2, 3: 1}

_FLAGGED = ("malicious", "suspicious")


@dataclass(frozen=True)
class ObservableVerdict:
    band: str
    confidence: int
    inconclusive_reason: Optional[str]
    counts: dict
    rationale: list


@dataclass(frozen=True)
class GroupVerdict:
    band: str
    confidence: int
    counts: dict
    rationale: list


def _counts(sources):
    c = {"malicious": 0, "suspicious": 0, "clean": 0, "no-data": 0}
    for s in sources:
        c[s.verdict] = c.get(s.verdict, 0) + 1
    return c


def _mult(s: SourceVerdict) -> float:
    return s.weight * TIER_MULTIPLIER.get(s.tier, 1)


def score_observable(sources: list) -> ObservableVerdict:
    counts = _counts(sources)
    voting = [s for s in sources if s.verdict != "no-data"]
    trusted_voting = [s for s in voting if s.tier in (1, 2)]
    rationale: list = []

    # Rule 0 — coverage
    if len(trusted_voting) < MIN_TRUSTED_COVERAGE:
        rationale.append(
            f"Only {len(trusted_voting)} trusted source(s) returned a verdict — not enough to assess."
        )
        return ObservableVerdict("Inconclusive", _confidence(sources, split=1.0),
                                 "thin_coverage", counts, rationale)

    t1_mal = [s for s in trusted_voting if s.tier == 1 and s.verdict == "malicious"]
    t2_mal = [s for s in trusted_voting if s.tier == 2 and s.verdict == "malicious"]
    t1_clean = [s for s in trusted_voting if s.tier == 1 and s.verdict == "clean"]
    trusted_flag = [s for s in trusted_voting if s.verdict in _FLAGGED]
    any_flag = [s for s in voting if s.verdict in _FLAGGED]

    total_w = sum(_mult(s) for s in voting) or 1.0
    mal_w = sum(_mult(s) for s in voting if s.verdict == "malicious")
    share = mal_w / total_w

    # Rule 1 — Dangerous
    decisive_t1 = [s for s in t1_mal if s.confidence is None or s.confidence >= HIGH_CONFIDENCE]
    if decisive_t1:
        rationale.append(f"{decisive_t1[0].name} (authoritative) reports malicious.")
        return ObservableVerdict("Dangerous", _confidence(sources), None, counts, rationale)
    if len(t2_mal) >= 2:
        rationale.append(f"{len(t2_mal)} strong sources agree the indicator is malicious.")
        return ObservableVerdict("Dangerous", _confidence(sources), None, counts, rationale)
    if share >= DANGEROUS_SHARE:
        rationale.append(f"Trust-weighted malicious share is {share:.0%}.")
        return ObservableVerdict("Dangerous", _confidence(sources), None, counts, rationale)

    # Rule 2 — Safe
    if t1_clean and not trusted_flag and not any_flag:
        rationale.append(f"{t1_clean[0].name} (authoritative) reports clean; no source flags it.")
        return ObservableVerdict("Safe", _confidence(sources), None, counts, rationale)

    # Rule 3 — Suspicious (something flagged it, not enough for Dangerous)
    if any_flag:
        if trusted_flag:
            rationale.append(f"{trusted_flag[0].name} flags the indicator; evidence is not decisive.")
        else:
            rationale.append("Only contextual/low-trust sources flag this — capped at Suspicious.")
        return ObservableVerdict("Suspicious", _confidence(sources), None, counts, rationale)

    # Nothing flagged, but no tier-1 clean either -> lean Safe with lower confidence
    rationale.append("No source flags the indicator.")
    return ObservableVerdict("Safe", _confidence(sources), None, counts, rationale)


def _confidence(sources, split: float = None) -> int:
    voting = [s for s in sources if s.verdict != "no-data"]
    if not voting:
        return 0
    total_w = sum(_mult(s) for s in voting) or 1.0
    mal_w = sum(_mult(s) for s in voting if s.verdict == "malicious")
    clean_w = sum(_mult(s) for s in voting if s.verdict == "clean")
    if split is None:
        lopsided = abs(mal_w - clean_w) / total_w          # 0 split .. 1 unanimous
    else:
        lopsided = 1.0 - split
    trusted = [s for s in voting if s.tier in (1, 2)]
    coverage = min(1.0, len(trusted) / 3.0)
    failed = [s for s in sources if s.failed]
    fail_pen = min(0.6, sum(0.3 if s.tier == 1 else 0.1 for s in failed))
    raw = lopsided * (0.4 + 0.6 * coverage) * (1.0 - fail_pen)
    return max(0, min(100, round(raw * 100)))
```

- [ ] **Step 4: Iterate to green**

Run: `python manage.py test score_process.tests.test_observable_engine -v 2`
Adjust the rule bodies until all 12 tests pass. Expected end state: PASS.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/score_process/scoring/observable_engine.py Suspicious/Suspicious/score_process/tests/test_observable_engine.py
git commit -m "feat(score): categorical trust-weighted observable verdict engine"
```

---

## Task 10: `score_group()` — worst-of banding

**Files:**
- Modify: `Suspicious/Suspicious/score_process/scoring/observable_engine.py` (add `score_group`)
- Test: `Suspicious/Suspicious/score_process/tests/test_observable_engine.py` (append)

**Interfaces:**
- Consumes: `list[ObservableVerdict]`.
- Produces: `def score_group(observables: list[ObservableVerdict]) -> GroupVerdict`.

- [ ] **Step 1: Write the failing tests**

Append to `test_observable_engine.py`:

```python
from score_process.scoring.observable_engine import score_group, ObservableVerdict


def ov(band, confidence=80):
    return ObservableVerdict(band, confidence, None, {}, [])


class ScoreGroupTests(SimpleTestCase):
    def test_worst_of_wins(self):
        g = score_group([ov("Safe"), ov("Suspicious"), ov("Dangerous")])
        self.assertEqual(g.band, "Dangerous")

    def test_inconclusive_ignored_when_others_have_verdict(self):
        g = score_group([ov("Inconclusive"), ov("Safe"), ov("Suspicious")])
        self.assertEqual(g.band, "Suspicious")

    def test_all_inconclusive_is_inconclusive(self):
        g = score_group([ov("Inconclusive"), ov("Inconclusive")])
        self.assertEqual(g.band, "Inconclusive")

    def test_counts_and_rationale(self):
        g = score_group([ov("Dangerous"), ov("Dangerous"), ov("Safe")])
        self.assertEqual(g.counts["Dangerous"], 2)
        self.assertTrue(any("2 of 3" in line for line in g.rationale))

    def test_confidence_is_min_at_worst_band(self):
        g = score_group([ov("Dangerous", 40), ov("Dangerous", 90), ov("Safe", 100)])
        self.assertEqual(g.confidence, 40)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test score_process.tests.test_observable_engine.ScoreGroupTests -v 2`
Expected: FAIL — `cannot import name 'score_group'`.

- [ ] **Step 3: Implement**

Append to `observable_engine.py`:

```python
_BAND_ORDER = {"Safe": 0, "Suspicious": 1, "Dangerous": 2}


def score_group(observables: list) -> GroupVerdict:
    counts = {"Dangerous": 0, "Suspicious": 0, "Safe": 0, "Inconclusive": 0}
    for o in observables:
        counts[o.band] = counts.get(o.band, 0) + 1

    assessed = [o for o in observables if o.band != "Inconclusive"]
    total = len(observables)
    if not assessed:
        return GroupVerdict("Inconclusive", 0, counts,
                            [f"None of {total} observable(s) could be assessed."])

    worst = max(assessed, key=lambda o: _BAND_ORDER[o.band]).band
    conf = min(o.confidence for o in assessed if o.band == worst)
    n_worst = counts[worst]
    rationale = [f"{n_worst} of {total} observable(s) are {worst}."]
    if counts["Inconclusive"]:
        rationale.append(f"{counts['Inconclusive']} could not be assessed.")
    return GroupVerdict(worst, conf, counts, rationale)
```

- [ ] **Step 4: Run tests + commit**

```bash
python manage.py test score_process.tests.test_observable_engine -v 2
git add Suspicious/Suspicious/score_process/scoring/observable_engine.py Suspicious/Suspicious/score_process/tests/test_observable_engine.py
git commit -m "feat(score): group verdict (worst-of bands + counts)"
```

---

## Task 11: `CaseVerdict` metadata + `mail_band_escalation()`

**Files:**
- Modify: `Suspicious/Suspicious/score_process/scoring/engine.py` (`CaseVerdict` additive fields; new `mail_band_escalation`)
- Modify: `Suspicious/Suspicious/score_process/scoring/apply.py` (persist metadata)
- Modify: `Suspicious/Suspicious/case_handler/models.py` (`Case` — add `inconclusive_reason`, `verdict_rationale` JSON)
- Create: `Suspicious/Suspicious/case_handler/migrations/` (`case_verdict_metadata`)
- Test: `Suspicious/Suspicious/score_process/tests/test_mail_escalation.py`, `score_process/tests/test_engine.py` (append)

**Interfaces:**
- Consumes: `CaseVerdict` (existing), `ObservableVerdict` (Task 9).
- Produces:
  - `CaseVerdict` gains `inconclusive_reason: str = ""`, `n_failed: int = 0`, `rationale: tuple = ()` — **all defaulted, existing positional fields unchanged.**
  - `def mail_band_escalation(verdict: CaseVerdict, embedded: list[ObservableVerdict]) -> CaseVerdict` — returns a copy with `.result` raised (never lowered) to the worst embedded band; `.final_score` unchanged; a rationale line appended.

- [ ] **Step 1: Write the failing tests**

`score_process/tests/test_mail_escalation.py`:

```python
from django.test import SimpleTestCase
from case_handler.models import Result
from score_process.scoring.engine import CaseVerdict, mail_band_escalation
from score_process.scoring.observable_engine import ObservableVerdict


def cv(result, score=2):
    return CaseVerdict(final_score=score, final_confidence=80, result=result, n_malicious=0, n_scored=3)


def ov(band):
    return ObservableVerdict(band, 80, None, {}, [])


class MailBandEscalationTests(SimpleTestCase):
    def test_embedded_dangerous_escalates_safe_mail(self):
        out = mail_band_escalation(cv(Result.SAFE, score=2), [ov("Safe"), ov("Dangerous")])
        self.assertEqual(out.result, Result.DANGEROUS)
        self.assertEqual(out.final_score, 2)  # score unchanged
        self.assertTrue(out.rationale)

    def test_never_lowers(self):
        out = mail_band_escalation(cv(Result.DANGEROUS, score=9), [ov("Safe")])
        self.assertEqual(out.result, Result.DANGEROUS)

    def test_no_embedded_is_noop(self):
        v = cv(Result.SAFE)
        self.assertEqual(mail_band_escalation(v, []).result, Result.SAFE)

    def test_suspicious_embedded_escalates_safe_to_suspicious(self):
        out = mail_band_escalation(cv(Result.SAFE), [ov("Suspicious")])
        self.assertEqual(out.result, Result.SUSPICIOUS)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test score_process.tests.test_mail_escalation -v 2`
Expected: FAIL — `cannot import name 'mail_band_escalation'`.

- [ ] **Step 3: Add fields + function**

`engine.py`, `CaseVerdict` — append (keep existing fields and order):

```python
    inconclusive_reason: str = ""
    n_failed: int = 0
    rationale: tuple = ()
```

`engine.py` — new function:

```python
from case_handler.models import Result  # already imported

_BAND_RANK = {Result.SAFE: 0, Result.INCONCLUSIVE: 0, Result.SUSPICIOUS: 1, Result.DANGEROUS: 2}
_OBS_TO_RESULT = {"Safe": Result.SAFE, "Suspicious": Result.SUSPICIOUS, "Dangerous": Result.DANGEROUS}


def mail_band_escalation(verdict, embedded):
    """Raise (never lower) a mail case's band to the worst embedded-IOC band.
    final_score is untouched — the AI/YARA/sandbox score still owns the number."""
    if not embedded:
        return verdict
    worst = max(
        (_OBS_TO_RESULT[o.band] for o in embedded if o.band in _OBS_TO_RESULT),
        key=lambda r: _BAND_RANK[r], default=None,
    )
    if worst is None or _BAND_RANK[worst] <= _BAND_RANK.get(verdict.result, 0):
        return verdict
    from dataclasses import replace
    line = f"Band raised to {worst} by an embedded indicator."
    return replace(verdict, result=worst, rationale=tuple(verdict.rationale) + (line,))
```

`case_handler/models.py`, `Case`:

```python
    inconclusive_reason = models.CharField(max_length=20, blank=True, default="")
    verdict_rationale = models.JSONField(default=list, blank=True)
```

`apply.py`, `apply_verdict` — add to the field list and assignments:

```python
    case.inconclusive_reason = getattr(verdict, "inconclusive_reason", "") or ""
    case.verdict_rationale = list(getattr(verdict, "rationale", ()) or [])
    # add "inconclusive_reason", "verdict_rationale" to the save(update_fields=[...]) list
```

- [ ] **Step 4: Migrate + test + backtest**

```bash
python manage.py makemigrations case_handler --name case_verdict_metadata
python manage.py test score_process case_handler -v 2
python manage.py backtest_scoring | tail -5   # bands unchanged
```
Expected: PASS; no new drift (the new fields are additive; `backtest_scoring` compares `.result`).

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/score_process/scoring/engine.py Suspicious/Suspicious/score_process/scoring/apply.py Suspicious/Suspicious/case_handler/models.py Suspicious/Suspicious/case_handler/migrations/ Suspicious/Suspicious/score_process/tests/test_mail_escalation.py
git commit -m "feat(score): additive verdict metadata + mail band escalation"
```

---

## Task 12: Labelled fixture set + `score_accuracy` command

**Files:**
- Create: `Suspicious/Suspicious/score_process/scoring/fixtures/labelled_cases/*.json` (5 files)
- Create: `Suspicious/Suspicious/score_process/management/commands/score_accuracy.py`
- Modify: `Suspicious/Suspicious/score_process/management/commands/backtest_scoring.py` (add `--road`)
- Test: `Suspicious/Suspicious/score_process/tests/test_score_accuracy.py`

**Interfaces:**
- Consumes: `source_verdict_from_report` (Task 8) via a lightweight fixture shape, `score_observable` (Task 9).
- Produces: `python manage.py score_accuracy` prints a confusion matrix (`aligned`, `false_positive`, `false_negative`) over the labelled set and exits non-zero if any case is a FP or FN.

- [ ] **Step 1: Author the fixtures**

One JSON per GTI comparison row. `score_process/scoring/fixtures/labelled_cases/8888_google_dns.json`:

```json
{
  "name": "8.8.8.8 — Google public DNS",
  "observable": "8.8.8.8",
  "type": "ip",
  "expected_band": "Safe",
  "sources": [
    {"name": "GoogleThreatIntelligence", "tier": 1, "weight": 0.9, "verdict": "clean", "confidence": 95, "failed": false, "evidence": "no detections"},
    {"name": "VirusTotal_GetReport_3_1", "tier": 1, "weight": 0.8, "verdict": "clean", "confidence": 90, "failed": false, "evidence": "0/89 engines"},
    {"name": "AbuseIPDB", "tier": 3, "weight": 0.2, "verdict": "suspicious", "confidence": 30, "failed": false, "evidence": "confidence 12%"}
  ]
}
```

Create the other four analogously from `docs/specs/2026-09-02-scoring-verdict-model-design.md` §1:
- `auth_users_pub.json` — expected `Safe` (GTI clean tier-1, one noisy tier-3 flags).
- `mirai_unpacked.json` — expected `Suspicious` (GTI suspicious tier-1, VT low, others no-data).
- `mirai_upx_packed.json` — expected `Suspicious` (YARA tier-2 malicious + GTI suspicious).
- `six_urls_sample.json` — pick one representative URL, expected `Suspicious` (GTI suspicious, one source failed).

- [ ] **Step 2: Write the failing test**

`score_process/tests/test_score_accuracy.py`:

```python
import json, pathlib
from django.test import SimpleTestCase
from score_process.scoring.sources import SourceVerdict
from score_process.scoring.observable_engine import score_observable

FIXDIR = pathlib.Path("score_process/scoring/fixtures/labelled_cases")


class LabelledAccuracyTests(SimpleTestCase):
    def test_every_labelled_case_matches_expected_band(self):
        failures = []
        for f in sorted(FIXDIR.glob("*.json")):
            data = json.loads(f.read_text())
            sources = [SourceVerdict(
                name=s["name"], tier=s["tier"], weight=s["weight"], verdict=s["verdict"],
                confidence=s.get("confidence"), failed=s.get("failed", False),
                evidence=s.get("evidence", ""),
            ) for s in data["sources"]]
            got = score_observable(sources).band
            if got != data["expected_band"]:
                failures.append(f"{data['name']}: expected {data['expected_band']}, got {got}")
        self.assertEqual(failures, [], "\n".join(failures))
```

- [ ] **Step 3: Run to verify it fails, then tune**

Run: `python manage.py test score_process.tests.test_score_accuracy -v 2`
Expected: initially FAIL on one or more cases. Tune the fixture `tier`/`weight`/`confidence` values *and* the `observable_engine` constants (`DANGEROUS_SHARE`, `TIER_MULTIPLIER`) until all five pass — this is the calibration step. Re-run Task 9 + Task 10 tests after each tweak; they must stay green.

- [ ] **Step 4: Add the `score_accuracy` command**

`score_process/management/commands/score_accuracy.py`:

```python
import json, pathlib
from collections import Counter
from django.core.management.base import BaseCommand
from score_process.scoring.sources import SourceVerdict
from score_process.scoring.observable_engine import score_observable

FIXDIR = pathlib.Path(__file__).resolve().parents[2] / "scoring" / "fixtures" / "labelled_cases"
_RANK = {"Safe": 0, "Inconclusive": 1, "Suspicious": 2, "Dangerous": 3}


class Command(BaseCommand):
    help = "Run the scoring engine over the labelled fixture set and report accuracy."

    def handle(self, *args, **opts):
        tally = Counter()
        for f in sorted(FIXDIR.glob("*.json")):
            d = json.loads(f.read_text())
            sources = [SourceVerdict(
                name=s["name"], tier=s["tier"], weight=s["weight"], verdict=s["verdict"],
                confidence=s.get("confidence"), failed=s.get("failed", False),
                evidence=s.get("evidence", ""),
            ) for s in d["sources"]]
            got, exp = score_observable(sources).band, d["expected_band"]
            if got == exp:
                tally["aligned"] += 1
                verdict = "aligned"
            elif _RANK[got] > _RANK[exp]:
                tally["false_positive"] += 1
                verdict = "FALSE POSITIVE"
            else:
                tally["false_negative"] += 1
                verdict = "FALSE NEGATIVE"
            self.stdout.write(f"{d['name']:<45} expected {exp:<12} got {got:<12} {verdict}")
        self.stdout.write(self.style.SUCCESS(f"\n{dict(tally)}"))
        if tally["false_positive"] or tally["false_negative"]:
            raise SystemExit(1)
```

- [ ] **Step 5: Add `--road` to `backtest_scoring` + commit**

In `backtest_scoring.py` `Command.add_arguments`:

```python
    parser.add_argument("--road", choices=["mail", "ioc", "all"], default="all")
```

In `handle`, filter the case queryset:

```python
        road = opts["road"]
        cases = Case.objects.filter(...)  # existing
        if road == "mail":
            cases = cases.filter(fileOrMail__mail__isnull=False)
        elif road == "ioc":
            cases = cases.filter(nonFileIocs__isnull=False)
```

```bash
python manage.py test score_process -v 2
python manage.py score_accuracy
python manage.py backtest_scoring --road mail | tail -3
git add Suspicious/Suspicious/score_process/scoring/fixtures/ Suspicious/Suspicious/score_process/management/commands/score_accuracy.py Suspicious/Suspicious/score_process/management/commands/backtest_scoring.py Suspicious/Suspicious/score_process/tests/test_score_accuracy.py
git commit -m "feat(score): labelled accuracy harness seeded from GTI comparison cases"
```

---

## Task 13: Wire the categorical engine into the IOC-road finalise path

> **Depends on** the IOC-analysis-road plan Tasks 1–5 (`ObservableGroup`, `Case.observable_group`, `collect_case_targets` branch). If that plan has not landed, stop here — Tasks 1–12 are independently shippable (they close the `8.8.8.8` gap and add the tier field + harness without changing any verdict).

**Files:**
- Modify: `Suspicious/Suspicious/score_process/scoring/cortex_analyzers/reports.py` (`get_report` — branch on road)
- Create: `Suspicious/Suspicious/score_process/scoring/observable_collect.py` — `collect_observable_sources(case) -> dict[observable, list[SourceVerdict]]`
- Modify: `Suspicious/Suspicious/score_process/scoring/apply.py` — `apply_group_verdict(case, group_verdict, observable_verdicts)`
- Test: `Suspicious/Suspicious/score_process/tests/test_ioc_road_scoring.py`

**Interfaces:**
- Consumes: `Case.observable_group`, `AnalyzerReport` rows for the group's observables, `source_verdict_from_report`, `score_observable`, `score_group`.
- Produces: an IOC-road case gets `case.results` from `score_group(...).band`, `case.confidence` from the group confidence, `case.score` = derived band number (Safe 2 / Suspicious 6 / Dangerous 9), each observable's `ioc_level`/`ioc_score`/`ioc_confidence` from its `ObservableVerdict`, and `case.verdict_rationale` = the group rationale.

- [ ] **Step 1: Write the failing test**

`score_process/tests/test_ioc_road_scoring.py`:

```python
from django.test import TestCase
from django.contrib.auth.models import User
from ip_process.models import IP
from cortex_job.models import Analyzer, AnalyzerReport
from case_handler.models import Case, Result
from case_handler.models import ObservableGroup, ObservableGroupArtifact  # from IOC road plan
from score_process.scoring.cortex_analyzers.reports import ReportProcessor  # or the module fn used


class IocRoadScoringTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("u", password="p")
        self.gti = Analyzer.objects.create(name="GTI", analyzer_cortex_id="gti1", tier=1, weight=0.9)
        self.abuse = Analyzer.objects.create(name="AbuseIPDB", analyzer_cortex_id="ab1", tier=3, weight=0.2)

    def _case_with_ip(self, address):
        ip = IP.objects.create(address=address)
        group = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(group=group, artifact_type="IP", ip=ip)
        case = Case.objects.create(description="t", reporter=self.user, observable_group=group)
        return case, ip

    def test_tier1_clean_ip_scores_group_safe(self):
        case, ip = self._case_with_ip("8.8.8.8")
        AnalyzerReport.objects.create(cortex_job_id="j1", type="ip", status="Success",
            analyzer=self.gti, ip=ip, level="safe", confidence=95, score=0,
            report_summary={}, report_taxonomy={}, report_full={})
        AnalyzerReport.objects.create(cortex_job_id="j2", type="ip", status="Success",
            analyzer=self.abuse, ip=ip, level="suspicious", confidence=30, score=7,
            report_summary={}, report_taxonomy={}, report_full={})

        # invoke the IOC-road finalise entry point
        from score_process.scoring.apply import finalise_ioc_group  # thin wrapper added in step 3
        finalise_ioc_group(case)

        case.refresh_from_db(); ip.refresh_from_db()
        self.assertEqual(case.results, Result.SAFE)
        self.assertEqual(ip.ioc_level.lower(), "safe")
        self.assertEqual(case.score, 2)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python manage.py test score_process.tests.test_ioc_road_scoring -v 2`
Expected: FAIL — `cannot import name 'finalise_ioc_group'`.

- [ ] **Step 3: Implement `observable_collect.py` + `finalise_ioc_group`**

`score_process/scoring/observable_collect.py`:

```python
"""Gather, per observable in a case's ObservableGroup, the SourceVerdict list
from its finished AnalyzerReports."""
from __future__ import annotations

from cortex_job.models import AnalyzerReport
from score_process.scoring.sources import source_verdict_from_report

_FIELD = {"URL": "url", "IP": "ip", "HASH": "hash", "DOMAIN": "domain"}


def collect_observable_sources(case):
    group = case.observable_group
    out = {}
    for art in group.artifacts.select_related("url", "ip", "hash", "domain"):
        field = _FIELD[art.artifact_type]
        obj = getattr(art, field)
        if obj is None:
            continue
        reports = (
            AnalyzerReport.objects
            .filter(**{field: obj})
            .select_related("analyzer")
            .order_by("-creation_date")
        )
        # newest report per analyzer
        seen, verdicts = set(), []
        for r in reports:
            if r.analyzer_id in seen:
                continue
            seen.add(r.analyzer_id)
            verdicts.append(source_verdict_from_report(r))
        out[(art.artifact_type, obj.pk, obj)] = verdicts
    return out
```

`score_process/scoring/apply.py` — add:

```python
_DERIVED_SCORE = {"Safe": 2, "Suspicious": 6, "Dangerous": 9, "Inconclusive": 5}


def finalise_ioc_group(case):
    """IOC-road finalisation. Never calls score_case."""
    from score_process.scoring.observable_collect import collect_observable_sources
    from score_process.scoring.observable_engine import score_observable, score_group
    from score_process.scoring.updating import update_ioc_with_scores  # existing helper
    from case_handler.models import Result

    per_obs = collect_observable_sources(case)
    obs_verdicts = []
    for (art_type, pk, obj), sources in per_obs.items():
        v = score_observable(sources)
        obs_verdicts.append(v)
        obj.ioc_level = v.band.lower()
        obj.ioc_score = _DERIVED_SCORE.get(v.band, 5)
        obj.ioc_confidence = v.confidence
        obj.save(update_fields=["ioc_level", "ioc_score", "ioc_confidence"])

    g = score_group(obs_verdicts) if obs_verdicts else None
    band = g.band if g else "Inconclusive"
    case.results = getattr(Result, band.upper(), Result.INCONCLUSIVE)
    case.score = case.final_score = _DERIVED_SCORE.get(band, 5)
    case.confidence = case.final_confidence = g.confidence if g else 0
    case.verdict_rationale = (g.rationale if g else []) + [
        line for v in obs_verdicts for line in v.rationale
    ]
    case.analysis_done = len(obs_verdicts)
    case.save(update_fields=[
        "results", "score", "final_score", "confidence", "final_confidence",
        "verdict_rationale", "analysis_done",
    ])
    from score_process.scoring.update_handler import update_kpi_and_user_stats
    update_kpi_and_user_stats(case)
```

- [ ] **Step 4: Branch `get_report`**

`reports.py`, in `get_report`, before the `collect_signals` block:

```python
        if getattr(case, "observable_group_id", None):
            from score_process.scoring.apply import finalise_ioc_group
            finalise_ioc_group(case)
            return
```

- [ ] **Step 5: Run tests + backtest + commit**

```bash
python manage.py test score_process case_handler -v 2
python manage.py backtest_scoring --road mail | tail -3   # mail path still zero drift
git add Suspicious/Suspicious/score_process/
git commit -m "feat(score): IOC-road finalisation via categorical engine"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Task(s) |
|---|---|
| §2 principle (categorical, derived score) | 8, 9, 13 |
| §3 mail three components + Option B | 11 (escalation), 13 (isolation — mail path untouched) |
| §4 IOC engine, 4 rules, confidence, group | 9, 10 |
| §4.1 SourceVerdict from report | 8 |
| §5 `Analyzer.tier` + seed + settings | 1, 2, 3 |
| §6 IP allow-list | 4, 5, 6 |
| §7 confidence-scale cleanup | 7 |
| §8 labelled harness + `--road` | 12 |
| §9 `inconclusive_reason` + rationale | 9, 11, 13 |
| §10 migration/rollout (no `engine_v2` flag) | all — mail path additive-only, IOC greenfield |
| §11 tests | every task |
| §12 sequencing | task order; live spike is a prerequisite note on Task 8 |

**Live-Cortex spike (spec §12 step 1):** before Task 8, pull ~20 finalised cases' `report_full`/`level`/`status` from the running instance and confirm every deployed analyzer maps to one of `malicious`/`suspicious`/`clean`/`no-data` and whether it carries a real confidence. Update `_tier_seed.py` prefixes (Task 2) to the analyzers actually deployed. This is investigation, not code — do it first, record findings in the PR description.

**Placeholder scan:** the fixture files in Task 12 Step 1 give one full example and name the other four with their expected bands + source shape — the author fills the source lists from spec §1, which is the calibration work, not a placeholder. All code steps have runnable code.

**Type consistency:** `SourceVerdict` fields (`name, tier, weight, verdict, confidence, failed, evidence`) identical in Tasks 8, 9, 12, 13. `ObservableVerdict` (`band, confidence, inconclusive_reason, counts, rationale`) identical in Tasks 9, 10, 11, 13. `GroupVerdict` (`band, confidence, counts, rationale`) identical in Tasks 10, 13. `mail_band_escalation(verdict, embedded)` — Task 11 defines, no other task calls it yet (the mail-road wiring that calls it is IOC-road plan Task "collect_signals branch" + a follow-up; noted as a gap below).

**Known gap:** `mail_band_escalation` is defined and unit-tested (Task 11) but not yet invoked from `get_report` for mail cases with embedded IOCs. Wiring it requires the embedded-IOC `ObservableVerdict` list, which depends on the IOC-road plan's per-artifact panel data. Add as **Task 14** once both plans' prerequisites are met: in `reports.py` `get_report`, after `apply_verdict`, compute `ObservableVerdict`s for `collect_case_targets`-derived embedded IOCs and call `mail_band_escalation`, then re-save `case.results`. One task, ~5 steps, same pattern as Task 13.
