# Display Reporter Note + Submission Context — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Durably preserve the IOC/URL/file submission `context` in a new
`Case.reporter_context` field and surface both it and the mail `reporterNote` on
the investigation detail page.

**Architecture:** New additive `Case.reporter_context` field (migration 0020) set
at submission via an explicit `create_case` parameter and never overwritten by
`finalise`. `InvestigationDetailsSerializer` exposes `reporter_context` plus a
`reporter_note` method field read from the linked Mail. `InvestigationPage`
renders a "Reporter's context" panel showing `reporter_note ?? reporter_context`.

**Tech Stack:** Django 5 + DRF (backend, in-container tests), React 19 + MUI v9 +
TanStack Query + Vitest (frontend, `pnpm`).

## Global Constraints

- **Spec:** `docs/specs/2026-07-06-display-reporter-context-design.md`.
- **Field name verbatim:** `Case.reporter_context` (`TextField`, `blank=True,
  default=""`). API also exposes `reporter_note` (method field from
  `Mail.reporterNote`).
- **`create_case` gains an explicit `reporter_context=""` parameter** — it is NOT
  a kwarg (kwargs route to `_create_related_model`, which expects model instances).
- **`finalise` must stay untouched** — it must never write `reporter_context`.
- **Panel value = `reporter_note || reporter_context`**, hidden when both empty.
- **Backend container test recipe** (baked `/app`, app root `/app/Suspicious`):
  ```bash
  cd deployment
  docker compose cp ../Suspicious/Suspicious/<path> suspicious:/app/Suspicious/<path>
  docker compose exec -T suspicious python manage.py test <targets> --keepdb -v1
  ```
  Migrations: `makemigrations case_handler` in the container, copy the generated
  file back. Latest `case_handler` migration is
  `0019_case_challenge_proposed_result_case_challenge_reason` → new one is `0020`.
- **Frontend** (`suspicious-ui/`): `pnpm test` (Vitest, browser runner — run once,
  don't launch parallel vitest processes; it is port-sensitive). `pnpm lint`.
- **Backend lint:** `ruff check Suspicious/` before each backend commit.
- **TDD:** red → green → commit per task.

---

### Task 1: `Case.reporter_context` field, migration, and submission wiring

**Files:**
- Modify: `Suspicious/Suspicious/case_handler/models.py`
- Create: `Suspicious/Suspicious/case_handler/migrations/0020_case_reporter_context.py`
- Modify: `Suspicious/Suspicious/case_handler/case_utils/case_creator.py`
- Modify: `Suspicious/Suspicious/case_handler/case_utils/case_handler.py`
- Test: `Suspicious/Suspicious/case_handler/tests/test_reporter_context.py`

**Interfaces:**
- Produces: `Case.reporter_context: str` (default `""`);
  `CaseCreator.create_case(description=None, reporter_context="", **kwargs)` stores
  it on the created Case.

- [ ] **Step 1: Write the failing tests**

```python
# case_handler/tests/test_reporter_context.py
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from case_handler.case_utils.case_creator import CaseCreator


class ReporterContextTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="rc_u", password="x")

    def test_default_blank(self):
        case = Case.objects.create(description="", reporter=self.user)
        self.assertEqual(case.reporter_context, "")

    def test_create_case_stores_reporter_context(self):
        case = CaseCreator(self.user).create_case(
            description="d", reporter_context="user said: looks like phishing"
        )
        case.refresh_from_db()
        self.assertEqual(case.reporter_context, "user said: looks like phishing")

    def test_finalise_does_not_overwrite_reporter_context(self):
        from cortex_job.cortex_utils.reconciliation import finalise
        case = CaseCreator(self.user).create_case(
            description="original", reporter_context="keep me"
        )
        with patch(
            "cortex_job.cortex_utils.reconciliation.CortexAnalyzerReports.get_report"
        ):
            finalise(case)
        case.refresh_from_db()
        self.assertEqual(case.reporter_context, "keep me")   # untouched
        self.assertNotEqual(case.description, "original")     # finalise rewrote it
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd deployment
docker compose cp ../Suspicious/Suspicious/case_handler/tests/test_reporter_context.py suspicious:/app/Suspicious/case_handler/tests/test_reporter_context.py
docker compose exec -T suspicious python manage.py test case_handler.tests.test_reporter_context --keepdb -v1
```
Expected: FAIL — `Case` has no `reporter_context` / `create_case()` got an
unexpected keyword argument.

- [ ] **Step 3: Add the field + migration**

`case_handler/models.py`, on `Case` near `challenge_reason`:
```python
    reporter_context = models.TextField(
        blank=True, default="", verbose_name="Reporter Context",
    )
```
Generate + copy back the migration:
```bash
docker compose exec -T suspicious python manage.py makemigrations case_handler
docker compose exec -T suspicious cat /app/Suspicious/case_handler/migrations/0020_case_reporter_context.py > ../Suspicious/Suspicious/case_handler/migrations/0020_case_reporter_context.py
```
(If Django auto-names it differently, copy that exact filename back and adjust the
`git add`.)

- [ ] **Step 4: Add the `create_case` param + wire the submit path**

`case_handler/case_utils/case_creator.py` — add the explicit parameter and set it
in the `Case(...)` constructor:
```python
    def create_case(self, description=None, reporter_context="", **kwargs):
        ...
        case = Case(
            description=description or casestr,
            reporter_context=reporter_context,
            creation_date=timezone.now(),
            analysis_done=False,
            results="Inconclusive",
            status="On Going",
            reporter=self.user
        )
```
(Leave the rest of the method — the `kwargs` loop and `_create_related_model` —
unchanged. `reporter_context` is a real column, so it persists on `case.save()`.)

`case_handler/case_utils/case_handler.py` (the `create` method, around line 189-197):
pass the reporter's context (already computed into the local `description`) as the
new parameter:
```python
        ...
        if self.other_form.is_valid():
            description = self.other_form.cleaned_data.get("context") or description
        try:
            case = CaseCreator(self.request.user).create_case(
                description=description, reporter_context=description, **ctx
            )
```
(At creation the reporter's `context` and `description` are the same value; passing
`reporter_context=description` captures it before `finalise` later rewrites
`description`.)

- [ ] **Step 5: Run to verify it passes**

```bash
for f in case_handler/models.py \
         case_handler/migrations/0020_case_reporter_context.py \
         case_handler/case_utils/case_creator.py \
         case_handler/case_utils/case_handler.py; do
  docker compose cp ../Suspicious/Suspicious/$f suspicious:/app/Suspicious/$f
done
docker compose exec -T suspicious python manage.py test case_handler cortex_job --keepdb -v1
```
Expected: PASS (new tests + existing case_handler/cortex_job suites green). Then
`ruff check Suspicious/Suspicious/case_handler/`.

- [ ] **Step 6: Commit**

```bash
git add Suspicious/Suspicious/case_handler/models.py \
        Suspicious/Suspicious/case_handler/migrations/0020_case_reporter_context.py \
        Suspicious/Suspicious/case_handler/case_utils/case_creator.py \
        Suspicious/Suspicious/case_handler/case_utils/case_handler.py \
        Suspicious/Suspicious/case_handler/tests/test_reporter_context.py
git commit -m "feat(case): durable reporter_context, preserved across finalise"
```

---

### Task 2: Expose `reporter_context` + `reporter_note` on the investigation detail

**Files:**
- Modify: `Suspicious/Suspicious/api/serializers/investigations.py` (`InvestigationDetailsSerializer`)
- Test: `Suspicious/Suspicious/api/tests/test_investigation_reporter_context.py`

**Interfaces:**
- Consumes: `Case.reporter_context` (Task 1), `Mail.reporterNote`.
- Produces: `GET /investigations/{id}/` includes `reporter_context: str` and
  `reporter_note: str`.

- [ ] **Step 1: Write the failing test**

```python
# api/tests/test_investigation_reporter_context.py
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from api.serializers.investigations import InvestigationDetailsSerializer


class InvestigationReporterContextTest(TestCase):
    def test_exposes_reporter_context(self):
        user = get_user_model().objects.create_user(username="irc", password="x")
        case = Case.objects.create(
            description="", reporter=user, reporter_context="please check this URL",
        )
        data = InvestigationDetailsSerializer(case).data
        self.assertEqual(data["reporter_context"], "please check this URL")
        self.assertEqual(data["reporter_note"], "")   # not a mail case

    def test_reporter_note_from_mail(self):
        from mail_feeder.models import Mail
        from case_handler.models import CaseHasFileOrMail
        from django.utils import timezone
        user = get_user_model().objects.create_user(username="irc2", password="x")
        mail = Mail.objects.create(
            subject="s", reportedBy="r", date=timezone.now(), to="t", mail_id="m1",
            reporterNote="forwarded phishing",
        )
        case = Case.objects.create(description="", reporter=user)
        fm = CaseHasFileOrMail.objects.create(case=case, mail=mail)
        case.fileOrMail = fm
        case.save(update_fields=["fileOrMail"])
        data = InvestigationDetailsSerializer(case).data
        self.assertEqual(data["reporter_note"], "forwarded phishing")
```

(Confirm `Mail` required fields via a quick introspection if the fixture errors —
`subject/reportedBy/date/to/mail_id` are the non-blank ones; `reporterNote` is
`blank=True`.)

- [ ] **Step 2: Run to verify it fails**

```bash
docker compose cp ../Suspicious/Suspicious/api/tests/test_investigation_reporter_context.py suspicious:/app/Suspicious/api/tests/test_investigation_reporter_context.py
docker compose exec -T suspicious python manage.py test api.tests.test_investigation_reporter_context --keepdb -v1
```
Expected: FAIL — `KeyError: 'reporter_context'`.

- [ ] **Step 3: Add the fields**

`api/serializers/investigations.py`, `InvestigationDetailsSerializer`:
- Add the method field declaration next to the others:
  ```python
      reporter_note = serializers.SerializerMethodField()
  ```
- Extend `Meta.fields` (append to the existing list — do not remove entries):
  ```python
      class Meta(InvestigationRowSerializer.Meta):
          fields = InvestigationRowSerializer.Meta.fields + [
              "analyzer_reports", "case_infos", "raw",
              "challenge_proposed_result", "challenge_reason",
              "reporter_context", "reporter_note",
          ]
  ```
- Add the method:
  ```python
      def get_reporter_note(self, obj: Case) -> str:
          fom = getattr(obj, "fileOrMail", None)
          mail = getattr(fom, "mail", None) if fom else None
          return getattr(mail, "reporterNote", "") or ""
  ```
`reporter_context` is a plain `Case` field, serialized automatically once named in
`Meta.fields`.

- [ ] **Step 4: Run to verify it passes**

```bash
docker compose cp ../Suspicious/Suspicious/api/serializers/investigations.py suspicious:/app/Suspicious/api/serializers/investigations.py
docker compose exec -T suspicious python manage.py test api.tests.test_investigation_reporter_context api --keepdb -v1
```
Expected: PASS (new test + full `api` suite green). Then
`ruff check Suspicious/Suspicious/api/serializers/investigations.py`.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/api/serializers/investigations.py \
        Suspicious/Suspicious/api/tests/test_investigation_reporter_context.py
git commit -m "feat(api): expose reporter_context + reporter_note on investigation detail"
```

---

### Task 3: Investigation-page "Reporter's context" panel

**Files:**
- Modify: `suspicious-ui/src/features/investigation/api.ts` (type)
- Modify: `suspicious-ui/src/pages/InvestigationPage.tsx` (panel)
- Test: `suspicious-ui/src/pages/__tests__/InvestigationPage.test.tsx`

**Interfaces:**
- Consumes: `reporter_context` + `reporter_note` from the investigation detail
  response (Task 2).

- [ ] **Step 1: Write the failing test**

Add to `suspicious-ui/src/pages/__tests__/InvestigationPage.test.tsx`, mirroring
the existing challenge-panel tests' harness (they mock `getInvestigationDetails`
via `mockGetDetails.mockResolvedValue(...)`, click the row, then assert on drawer
content). Add:
- a test where the mocked details include `reporter_note: "forwarded phishing"` and
  asserts the panel shows `/reporter's context/i` and `forwarded phishing`;
- a test where the mocked details include `reporter_context: "please check"` (no
  note) and asserts `please check` is shown;
- rely on the default `mockDetails` (no reporter fields) to assert
  `screen.queryByText(/reporter's context/i)` is absent.

Use the same reason-panel assertion style already added for the challenge panel
(a specific substring, not an ambiguous regex that could match row text — e.g.
assert the exact context string, which won't collide with the artifact rows).

- [ ] **Step 2: Run to verify it fails**

```bash
cd /home/tbhang/suspicious/suspicious-ui
pnpm test -- src/pages/__tests__/InvestigationPage.test.tsx
```
Expected: FAIL — no "Reporter's context" panel rendered.

- [ ] **Step 3: Add the type + panel**

`suspicious-ui/src/features/investigation/api.ts` — add to `InvestigationDetails`:
```ts
  reporter_context?: string;
  reporter_note?: string;
```

`suspicious-ui/src/pages/InvestigationPage.tsx` — directly below the existing
"Reporter's challenge" panel (the `detailsQuery.data?.challenge_proposed_result`
block), add:
```tsx
{(detailsQuery.data?.reporter_note || detailsQuery.data?.reporter_context) ? (
  <Box sx={{ px: 2.25, py: 2 }}>
    <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.08em", color: "text.disabled", mb: 0.75 }}>
      Reporter's context
    </Typography>
    <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: "pre-wrap" }}>
      {detailsQuery.data.reporter_note || detailsQuery.data.reporter_context}
    </Typography>
  </Box>
) : null}
```
(Matches the challenge panel's label/value `sx` idiom; `whiteSpace: "pre-wrap"`
keeps line breaks in a pasted note.)

- [ ] **Step 4: Run to verify it passes**

```bash
pnpm test -- src/pages/__tests__/InvestigationPage.test.tsx
pnpm lint
```
Expected: PASS + lint clean.

- [ ] **Step 5: Commit**

```bash
git add suspicious-ui/src/features/investigation/api.ts \
        suspicious-ui/src/pages/InvestigationPage.tsx \
        suspicious-ui/src/pages/__tests__/InvestigationPage.test.tsx
git commit -m "feat(ui): show reporter's context/note on the investigation page"
```

---

### Task 4: Full verification

**Files:** none (verification only).

- [ ] **Step 1: Full backend suite + ruff**

```bash
cd /home/tbhang/suspicious/deployment
docker compose exec -T suspicious python manage.py test --keepdb -v1
cd .. && ruff check Suspicious/
```
Expected: OK (0 failures), ruff clean.

- [ ] **Step 2: Full frontend suite + lint**

```bash
cd suspicious-ui
pnpm test
pnpm lint
```
Expected: all green (single run — do not spawn parallel vitest).

- [ ] **Step 3: Live spot-check (optional)**

Rebuild + recreate (`docker compose build suspicious && docker compose up -d
--force-recreate suspicious suspicious_celery`), then via the API submit an IOC
with a `context`, fetch `GET /investigations/{id}/`, and confirm the response
carries `reporter_context`. Clean up the test row.

- [ ] **Step 4: Commit (if any tune)**

Only if Step 3 surfaced a fix; otherwise nothing to commit.

---

## Self-Review

**Spec coverage:**
- Durable `Case.reporter_context` field + migration → Task 1. ✓
- Set at submission via explicit `create_case` param (not kwarg) → Task 1. ✓
- `finalise` never overwrites it (regression test) → Task 1. ✓
- API exposes `reporter_context` + `reporter_note` (from Mail) → Task 2. ✓
- Investigation-page panel (`note || context`, hidden when empty) → Task 3. ✓
- Mail body out of scope → not in any task. ✓
- Additive migration, no backfill → Task 1 + stated. ✓

**Type consistency:** `reporter_context` (Case field / TS) and `reporter_note`
(method field / TS) named identically across model, `create_case`, serializer,
`InvestigationDetails` type, and the panel. `create_case(description=None,
reporter_context="", **kwargs)` signature used in Task 1 tests and Task 1 wiring.

**Placeholder scan:** none. Task 3's test body is described against the existing
harness (which the implementer must read) rather than pasted verbatim, because it
must reuse that file's `mockDetails`/`renderInvestigation` setup — with the exact
assertion strings given.

**Open confirmations for the implementer:** the migration auto-name (Task 1); that
`InvestigationDetailsSerializer.Meta.fields` currently ends with the challenge
fields to append after (Task 2); the exact line of the challenge panel to place the
new panel below (Task 3).
