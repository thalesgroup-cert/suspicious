# Case integrity constraints Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce in the database the "exactly one target" and "group case isolation" rules that every prod row already satisfies, add unique allow/deny entries, and make `CaseCreator` warn on case shapes outside the allowed set.

**Architecture:** A small `exactly_one_not_null()` helper builds the `Q` for each one-target `CheckConstraint`; constraints live in `Meta.constraints` and ship as plain `AddConstraint` migrations (MariaDB 12.3.3 adds a CHECK without rebuilding the table; verified with `LOCK=NONE`). `CaseCreator.create_case` computes the case shape from its artifact arguments and logs a warning for anything that is not mail alone, file (optionally with its own hash), IOCs without mail/file, or a group alone. No existing row is changed.

**Tech Stack:** Django 6.1 (`CheckConstraint(condition=...)`, `UniqueConstraint`), MariaDB 12.3, SQLite test DB (enforces CHECK), `ww test backend`.

**Spec:** `docs/specs/2026-10-08-case-integrity-constraints-design.md`

## Global Constraints

- Prod facts that must stay true: 97 `Case` rows have both `fileOrMail` and `nonFileIocs` (a file and its own hash), 46 have no road. Neither is rejected by any new constraint.
- No constraint on "exactly one road per `Case`". Only: `observable_group` set implies `fileOrMail` and `nonFileIocs` are NULL.
- Constraint names: `<model>_one_target_chk`, `case_group_excludes_other_roads_chk`, `uniq_<table>_<column>`.
- `CaseCreator` never refuses a case because of its shape: log a warning, create the case.
- Use `CheckConstraint(condition=...)` (Django 6.1; `check=` no longer exists).
- Paths are relative to `Suspicious/Suspicious/` unless they start with `docs/`. Tests: `ww test backend <labels>`. Remove the stray `Suspicious/Suspicious/gunicorn.conf.py` before committing. Commit with explicit `git add <paths>`; end messages with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- Generate migrations in the container: from `deployment/`, `docker compose --env-file .env run --rm --no-deps -w /app -v $PWD/../Suspicious/Suspicious:/app suspicious python manage.py makemigrations <app> -n <name>`.

## Review Focus

- A file submitted with its own hash (the 97 prod cases) must not log a warning. Test in Task 1.
- Non-artifact keyword arguments (`allow_listed`) and falsy values must be ignored by the shape check. Test in Task 1.
- A case with no road at all (the 46 legacy rows) and a group-only case must stay creatable. Test in Task 2.
- `bulk_create(..., ignore_conflicts=True)` on the allow lists (used by `api/utils/settings_service.py`) must keep skipping duplicates silently once the unique constraints exist. Test in Task 2.
- A hash-only IOC case (one `CaseHasNonFileIocs` row with only `hash`) is valid. Test in Task 2.

---

### Task 1: `CaseCreator` shape guard

**Files:**
- Modify: `case_handler/case_utils/case_creator.py` (add `unexpected_case_shape`, call it in `create_case`)
- Create: `case_handler/tests/test_case_shapes.py`

**Interfaces:**
- Produces: `unexpected_case_shape(artifacts: dict) -> str | None` in `case_handler.case_utils.case_creator`. Returns `None` for an allowed shape, else a `+`-joined description such as `"mail+url"`. Artifact keys: `mail_instance`, `file_instance`, `ip_instance`, `url_instance`, `hash_instance`, `observable_group_instance`; other keys and falsy values are ignored.

- [ ] **Step 1: Write the failing tests**

`case_handler/tests/test_case_shapes.py`:

```python
from types import SimpleNamespace

from django.contrib.auth.models import User
from django.test import TestCase

from case_handler.case_utils.case_creator import CaseCreator, unexpected_case_shape
from mail_feeder.models import Mail
from url_process.models import URL
from django.utils import timezone

OBJ = SimpleNamespace  # stands in for a model instance (truthy, has attributes)


def _file(hash_pk=1):
    return OBJ(pk=10, linked_hash_id=hash_pk)


class UnexpectedCaseShapeTests(TestCase):
    def test_allowed_shapes_return_none(self):
        h = OBJ(pk=1)
        for artifacts in (
            {},
            {"mail_instance": OBJ()},
            {"file_instance": _file()},
            {"file_instance": _file(1), "hash_instance": h},          # the 97 prod cases
            {"url_instance": OBJ()},
            {"ip_instance": OBJ(), "url_instance": OBJ(), "hash_instance": OBJ(pk=2)},
            {"observable_group_instance": OBJ()},
        ):
            self.assertIsNone(unexpected_case_shape(artifacts), artifacts)

    def test_non_artifact_keys_and_falsy_values_are_ignored(self):
        h = OBJ(pk=1)
        self.assertIsNone(unexpected_case_shape({
            "allow_listed": True, "allow_reason": "x",
            "file_instance": _file(1), "hash_instance": h,
            "mail_instance": None, "url_instance": None, "ip_instance": None,
        }))

    def test_unexpected_shapes_are_described(self):
        self.assertEqual(unexpected_case_shape({"mail_instance": OBJ(), "url_instance": OBJ()}), "mail+url")
        self.assertEqual(unexpected_case_shape({"file_instance": _file(1), "hash_instance": OBJ(pk=99)}), "file+hash")
        self.assertEqual(unexpected_case_shape({"file_instance": _file(), "url_instance": OBJ()}), "file+url")
        self.assertEqual(unexpected_case_shape({"observable_group_instance": OBJ(), "url_instance": OBJ()}), "group+url")


class CreateCaseWarnsTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user("u", "u@x.io", "pw")

    def test_mail_plus_url_warns_but_still_creates_the_case(self):
        mail = Mail.objects.create(subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id="m1")
        url = URL.objects.create(address="http://a.test/")
        with self.assertLogs("case_handler.case_utils.case_creator", "WARNING") as logs:
            case = CaseCreator(self.user).create_case(mail_instance=mail, url_instance=url)
        self.assertIsNotNone(case)
        self.assertIn("mail+url", logs.output[0])
        self.assertIn(str(case.id), logs.output[0])

    def test_url_alone_does_not_warn(self):
        url = URL.objects.create(address="http://b.test/")
        with self.assertNoLogs("case_handler.case_utils.case_creator", "WARNING"):
            self.assertIsNotNone(CaseCreator(self.user).create_case(url_instance=url))
```

- [ ] **Step 2: Run to verify they fail**

Run: `ww test backend case_handler.tests.test_case_shapes`
Expected: ERROR `ImportError: cannot import name 'unexpected_case_shape'`.

- [ ] **Step 3: Implement**

In `case_handler/case_utils/case_creator.py`, below `logger = logging.getLogger(__name__)` add:

```python
_ARTIFACT_KEYS = (
    "mail_instance", "file_instance", "ip_instance", "url_instance",
    "hash_instance", "observable_group_instance",
)


def _describe_shape(present: set) -> str:
    names = [("group" if k == "observable_group_instance" else k.removesuffix("_instance")) for k in present]
    return "+".join(sorted(names))


def unexpected_case_shape(artifacts: dict) -> str | None:
    """None when the artifacts form an allowed case shape, else a short description.

    Allowed: mail alone; file alone or with its own hash (``file.linked_hash``);
    any of ip/url/hash with no mail or file; an observable group alone.
    Keys other than the artifact keys, and falsy values, are ignored."""
    present = {k for k in _ARTIFACT_KEYS if artifacts.get(k)}
    if not present:
        return None
    if "observable_group_instance" in present:
        return None if present == {"observable_group_instance"} else _describe_shape(present)
    if "mail_instance" in present:
        return None if present == {"mail_instance"} else _describe_shape(present)
    if "file_instance" in present:
        extra = present - {"file_instance"}
        if not extra:
            return None
        own_hash = getattr(artifacts["file_instance"], "linked_hash_id", None)
        hash_inst = artifacts.get("hash_instance")
        if extra == {"hash_instance"} and own_hash is not None and getattr(hash_inst, "pk", None) == own_hash:
            return None
        return _describe_shape(present)
    return None  # ip / url / hash only
```

In `create_case`, directly after `group = kwargs.pop('observable_group_instance', None)` add:

```python
        shape = unexpected_case_shape({**kwargs, "observable_group_instance": group})
```

and after the final successful `case.save()` (the second one, inside the `try`, before `return case`) add:

```python
            if shape:
                logger.warning("Case %s has an unexpected shape: %s", case.id, shape)
```

- [ ] **Step 4: Run to verify they pass**

Run: `ww test backend case_handler`
Expected: PASS (new tests plus the whole `case_handler` suite).

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/case_handler/case_utils/case_creator.py Suspicious/Suspicious/case_handler/tests/test_case_shapes.py
git commit -m "feat(case-handler): warn on unexpected case shapes in CaseCreator"
```

---

### Task 2: Constraints, helper and migrations

Superseded: the `cortex_job` / `AnalyzerReport` pieces of this task were dropped (check deferred, see the spec Rollout); ignore them below.

**Files:**
- Create: `common/constraints.py`
- Modify: `case_handler/models.py` (Meta of `Case`, `CaseHasFileOrMail`, `CaseHasNonFileIocs`, `CaseArtifact`, `ObservableGroupArtifact`)
- Modify: `cortex_job/models.py` (Meta of `AnalyzerReport`)
- Modify: `settings/models.py` (add `Meta.constraints` to `AllowListDomain`, `DenyListDomain`, `AllowListIp`, `AllowListFile`, `CampaignDomainAllowList`)
- Create: `common/tests/test_integrity_constraints.py`
- Create (generated): one migration each in `case_handler`, `settings`, `cortex_job`

**Interfaces:**
- Produces: `exactly_one_not_null(*fields: str) -> django.db.models.Q` in `common.constraints`: true when exactly one of the named fields is not NULL.

- [ ] **Step 1: Write the failing tests**

`common/tests/test_integrity_constraints.py`:

```python
from contextlib import contextmanager

from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone

from case_handler.models import (
    Case, CaseArtifact, CaseHasFileOrMail, CaseHasNonFileIocs,
    ObservableGroup, ObservableGroupArtifact,
)
from cortex_job.models import Analyzer, AnalyzerReport
from domain_process.models import Domain
from hash_process.models import Hash
from ip_process.models import IP
from mail_feeder.models import Mail
from settings.models import (
    AllowListDomain, AllowListFile, AllowListIp, CampaignDomainAllowList, DenyListDomain,
)
from url_process.models import URL


@contextmanager
def rejected():
    """The block must raise IntegrityError (a savepoint keeps the test DB usable)."""
    try:
        with transaction.atomic():
            yield
    except IntegrityError:
        return
    raise AssertionError("expected IntegrityError, none raised")


class IntegrityConstraintTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("u", "u@x.io", "pw")
        cls.case = Case.objects.create(description="d", reporter=cls.user)
        cls.url = URL.objects.create(address="http://a.test/")
        cls.ip = IP.objects.create(address="1.2.3.4")
        cls.hash = Hash.objects.create(value="a" * 64)
        cls.domain = Domain.objects.create(value="a.test")
        cls.analyzer = Analyzer.objects.create(name="A", analyzer_cortex_id="a1")
        cls.mail = Mail.objects.create(
            subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id="m1",
        )

    # --- one-target rules -------------------------------------------------
    def _report(self, **targets):
        return AnalyzerReport.objects.create(
            cortex_job_id="j", type="url", status="Success", analyzer=self.analyzer,
            level="info", confidence=1, score=1,
            report_summary={}, report_taxonomy={}, report_full={}, **targets,
        )

    def test_analyzer_report_needs_exactly_one_target(self):
        self._report(url=self.url)
        with rejected():
            self._report()
        with rejected():
            self._report(url=self.url, ip=self.ip)

    def test_case_artifact_needs_exactly_one_target(self):
        CaseArtifact.objects.create(case=self.case, artifact_type="url", url=self.url)
        with rejected():
            CaseArtifact.objects.create(case=self.case, artifact_type="url")
        with rejected():
            CaseArtifact.objects.create(case=self.case, artifact_type="url", url=self.url, ip=self.ip)

    def test_observable_group_artifact_needs_exactly_one_target(self):
        group = ObservableGroup.objects.create()
        ObservableGroupArtifact.objects.create(group=group, artifact_type="URL", url=self.url)
        with rejected():
            ObservableGroupArtifact.objects.create(group=group, artifact_type="URL")

    def test_case_has_file_or_mail_needs_exactly_one_target(self):
        CaseHasFileOrMail.objects.create(case=self.case, mail=self.mail)
        with rejected():
            CaseHasFileOrMail.objects.create(case=self.case)

    def test_case_has_non_file_iocs_needs_exactly_one_target(self):
        CaseHasNonFileIocs.objects.create(case=self.case, hash=self.hash)   # hash-only IOC is valid
        CaseHasNonFileIocs.objects.create(case=self.case, url=self.url)
        with rejected():
            CaseHasNonFileIocs.objects.create(case=self.case)
        with rejected():
            CaseHasNonFileIocs.objects.create(case=self.case, url=self.url, ip=self.ip)

    # --- Case roads ---------------------------------------------------------
    def test_roadless_and_group_only_cases_stay_valid(self):
        Case.objects.create(description="legacy, no road", reporter=self.user)
        group = ObservableGroup.objects.create()
        Case.objects.create(description="group", reporter=self.user, observable_group=group)

    def test_file_plus_hash_style_case_stays_valid(self):
        mail_bundle = CaseHasFileOrMail.objects.create(case=self.case, mail=self.mail)
        ioc_bundle = CaseHasNonFileIocs.objects.create(case=self.case, hash=self.hash)
        Case.objects.create(
            description="two roads", reporter=self.user,
            fileOrMail=mail_bundle, nonFileIocs=ioc_bundle,
        )

    def test_group_case_cannot_also_have_another_road(self):
        group = ObservableGroup.objects.create()
        bundle = CaseHasNonFileIocs.objects.create(case=self.case, url=self.url)
        with rejected():
            Case.objects.create(
                description="bad", reporter=self.user, observable_group=group, nonFileIocs=bundle,
            )

    # --- allow / deny uniqueness -------------------------------------------
    def test_allow_deny_lists_reject_duplicates(self):
        for model, field, value in (
            (AllowListDomain, "domain", self.domain),
            (DenyListDomain, "domain", self.domain),
            (CampaignDomainAllowList, "domain", self.domain),
            (AllowListIp, "ip", self.ip),
            (AllowListFile, "linked_file_hash", self.hash),
        ):
            model.objects.create(user=self.user, **{field: value})
            with rejected():
                model.objects.create(user=self.user, **{field: value})

    def test_bulk_create_ignore_conflicts_still_skips_duplicates(self):
        AllowListIp.objects.create(user=self.user, ip=self.ip)
        AllowListIp.objects.bulk_create(
            [AllowListIp(user=self.user, ip=self.ip)], ignore_conflicts=True,
        )
        self.assertEqual(AllowListIp.objects.filter(ip=self.ip).count(), 1)
```

- [ ] **Step 2: Run to verify they fail**

Run: `ww test backend common.tests.test_integrity_constraints`
Expected: FAIL (the `rejected()` blocks raise `AssertionError: expected IntegrityError, none raised`).

- [ ] **Step 3: Implement**

`common/constraints.py`:

```python
from django.db.models import Q


def exactly_one_not_null(*fields: str) -> Q:
    """Q that holds when exactly one of ``fields`` is not NULL."""
    terms = []
    for field in fields:
        term = Q(**{f"{field}__isnull": False})
        for other in fields:
            if other != field:
                term &= Q(**{f"{other}__isnull": True})
        terms.append(term)
    result = terms[0]
    for term in terms[1:]:
        result |= term
    return result
```

`case_handler/models.py`: add `from common.constraints import exactly_one_not_null` to the imports, then extend each `Meta`:

```python
# Case.Meta (keep ordering and indexes)
        constraints = [
            models.CheckConstraint(
                condition=models.Q(observable_group__isnull=True)
                | (models.Q(fileOrMail__isnull=True) & models.Q(nonFileIocs__isnull=True)),
                name="case_group_excludes_other_roads_chk",
            ),
        ]
# CaseHasFileOrMail.Meta
        constraints = [models.CheckConstraint(
            condition=exactly_one_not_null("file", "mail"), name="casehasfileormail_one_target_chk")]
# CaseHasNonFileIocs.Meta
        constraints = [models.CheckConstraint(
            condition=exactly_one_not_null("url", "ip", "hash"), name="casehasnonfileiocs_one_target_chk")]
# CaseArtifact.Meta
        constraints = [models.CheckConstraint(
            condition=exactly_one_not_null("file", "hash", "url", "ip", "mail"), name="caseartifact_one_target_chk")]
# ObservableGroupArtifact.Meta (keep ordering and indexes)
        constraints = [models.CheckConstraint(
            condition=exactly_one_not_null("url", "ip", "hash", "domain"), name="observablegroupartifact_one_target_chk")]
```

`settings/models.py`: add to each of the five models a `Meta`:

```python
# AllowListDomain
    class Meta:
        constraints = [models.UniqueConstraint(fields=["domain"], name="uniq_allowlistdomain_domain")]
# DenyListDomain
    class Meta:
        constraints = [models.UniqueConstraint(fields=["domain"], name="uniq_denylistdomain_domain")]
# CampaignDomainAllowList
    class Meta:
        constraints = [models.UniqueConstraint(fields=["domain"], name="uniq_campaigndomainallowlist_domain")]
# AllowListIp
    class Meta:
        constraints = [models.UniqueConstraint(fields=["ip"], name="uniq_allowlistip_ip")]
# AllowListFile
    class Meta:
        constraints = [models.UniqueConstraint(fields=["linked_file_hash"], name="uniq_allowlistfile_hash")]
```

Edit the three models files below, then generate one migration per app .

`cortex_job/models.py` imports `from common.constraints import exactly_one_not_null`; add to `AnalyzerReport.Meta`:

```python
        constraints = [models.CheckConstraint(
            condition=exactly_one_not_null(
                "url", "domain", "mail", "hash", "file", "ip", "mail_body", "mail_header",
            ),
            name="analyzerreport_one_target_chk",
        )]
```

Command (from `deployment/`):

```bash
docker compose --env-file .env run --rm --no-deps -w /app -v $PWD/../Suspicious/Suspicious:/app suspicious python manage.py makemigrations case_handler settings cortex_job -n integrity_constraints
```

- [ ] **Step 4: Run to verify they pass, then fix fixtures**

Run: `ww test backend common.tests.test_integrity_constraints`
Expected: PASS.

Before the suite, audit every writer of the constrained models and confirm each sets exactly one target:

```bash
grep -rnE "AnalyzerReport\(|AnalyzerReport.objects.(create|get_or_create|update_or_create|bulk_create)|CaseArtifact(\(|.objects)|ObservableGroupArtifact(\(|.objects)|CaseHasFileOrMail\(|CaseHasNonFileIocs\(" Suspicious/Suspicious --include=*.py | grep -v "tests\|migrations"
```

List what you checked in the task report. Then run the whole suite: `ww test backend`. Any other test that now fails created a row that breaks a rule (for example an `AnalyzerReport` with no target, a `CaseHasFileOrMail` with neither file nor mail, or a duplicate allow-list entry). Fix the fixture so it creates a valid row; do **not** loosen a constraint. Record each fixture fixed in the task report.

Also run `makemigrations --check --dry-run` (expect "No changes detected") and review the SQL: `python manage.py sqlmigrate case_handler <n>` and the `cortex_job` one (expect `ALTER TABLE ... ADD CONSTRAINT ... CHECK`).

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/common/constraints.py Suspicious/Suspicious/common/tests/test_integrity_constraints.py Suspicious/Suspicious/case_handler/models.py Suspicious/Suspicious/case_handler/migrations Suspicious/Suspicious/settings/models.py Suspicious/Suspicious/settings/migrations Suspicious/Suspicious/cortex_job/models.py Suspicious/Suspicious/cortex_job/migrations
# plus any test file whose fixture was corrected
git commit -m "feat(models): enforce one-target and group-isolation rules with check constraints"
```

---

### Task 3: Dev verification and docs

**Files:**
- Modify: `docs/components/backend/case_handler.md` (document the allowed case shapes and the constraints)
- Modify: `docs/components/backend/models-guide.md` (section 5 rows: mark the constraints done)

- [ ] **Step 1: Apply the migrations to the dev database and inspect them**

From `deployment/`:

```bash
docker compose --env-file .env run --rm --no-deps -w /app -v $PWD/../Suspicious/Suspicious:/app suspicious python manage.py migrate --no-input
docker compose --env-file .env exec -T db_suspicious mariadb -uroot -pmeridian_dev_root_pw db_suspicious -e "SELECT table_name, constraint_name FROM information_schema.table_constraints WHERE constraint_type='CHECK' AND constraint_name LIKE '%\\_chk' ORDER BY 1; SELECT table_name, constraint_name FROM information_schema.table_constraints WHERE constraint_name LIKE 'uniq\\_allow%' OR constraint_name LIKE 'uniq\\_deny%' OR constraint_name LIKE 'uniq\\_campaign%';"
```

Expected: the migrations apply with no error (dev has the one file + hash case, which is valid); the query lists the five CHECK constraints (`case_group_excludes_other_roads_chk`, `casehasfileormail_one_target_chk`, `casehasnonfileiocs_one_target_chk`, `caseartifact_one_target_chk`, `observablegroupartifact_one_target_chk`) and the five unique constraints.

- [ ] **Step 2: Prove a violating write is rejected on MariaDB**

```bash
docker compose --env-file .env exec -T db_suspicious mariadb -uroot -pmeridian_dev_root_pw db_suspicious -e "INSERT INTO case_handler_caseartifact (case_id, artifact_type, creation_date, last_update) VALUES ((SELECT MIN(id) FROM case_handler_case), 'url', NOW(), NOW());"
```

Expected: `ERROR 4025 ... CONSTRAINT caseartifact_one_target_chk failed`. (If the insert succeeds, delete that row and report it.)

- [ ] **Step 3: Docs**

In `docs/components/backend/case_handler.md` add a short "Case shapes and integrity rules" section: the four allowed shapes (mail; file with optionally its own hash; ip/url/hash IOCs; observable group), that `CaseCreator` logs `Case <id> has an unexpected shape: <shape>` for anything else but still creates the case, and the list of constraints (names and what they enforce). In `models-guide.md` section 5, change the verdicts of the `CheckConstraint` and allow/deny unique rows to "Done 2026-10-08" and note that the file + hash two-road case is intentional, so no "exactly one road" constraint exists.

- [ ] **Step 4: Full suite on the final tree**

Run: `ww test backend`
Expected: PASS. Then `rm -f Suspicious/Suspicious/gunicorn.conf.py` and `git status` shows only the docs files.

- [ ] **Step 5: Commit**

```bash
git add docs/components/backend/case_handler.md docs/components/backend/models-guide.md
git commit -m "docs(backend): case shapes and integrity constraints"
```

---

## Prod rollout notes (not part of the code tasks)

1. `make backup-db`.
2. Rehearse on a restored copy: time `migrate case_handler` and `migrate settings`. (The `AnalyzerReport` check is deferred: ADD CHECK is a table copy there.)
3. Deploy; watch `docker compose logs suspicious | grep "unexpected shape"` for a few days. Any hit is a submission path that builds an unexpected case.
4. Back out a constraint with `python manage.py migrate <app> <previous migration>`; no data is touched.
