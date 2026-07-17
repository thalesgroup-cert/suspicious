# Challenge with Proposed Verdict — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user challenging a case verdict say what they think it should be
(binary Safe/Dangerous) + an optional reason; store it, notify CERT/TheHive with
the proposal, and show it to the analyst.

**Architecture:** Two new `Case` fields (migration 0019) hold the proposal. The
in-app challenge endpoint (`SubmissionChallengeView`) validates a small body,
stores the fields, and routes through a refactored `challenge.py` service so the
in-app path finally notifies CERT/TheHive (with the proposal) like the email
path does. The submission detail serializer exposes the fields; the UI gains a
dialog form and an analyst display panel.

**Tech Stack:** Django 5 + DRF (backend), React 19 + MUI v9 + TanStack Query +
Vitest/testing-library (frontend). Backend tests run in-container; frontend via
pnpm.

## Global Constraints

- **Spec:** `docs/specs/2026-07-05-challenge-proposed-verdict-design.md`.
- **Proposed verdict values are exactly `"Safe"` and `"Dangerous"`** (reuse the
  `Result` string set). Reason optional, max 2000 chars.
- **Field names (verbatim, used across model/serializer/view/UI):**
  `challenge_proposed_result`, `challenge_reason`.
- **Backend container test recipe** (baked `/app`, app root `/app/Suspicious`):
  ```bash
  cd deployment
  docker compose cp ../Suspicious/Suspicious/<path> suspicious:/app/Suspicious/<path>
  docker compose exec -T suspicious python manage.py test <targets> --keepdb -v1
  ```
  Migrations: `makemigrations` in the container, copy the generated file back to
  the host. Latest `case_handler` migration is `0018_alter_case_results` → new one
  is `0019`.
- **Frontend** (`suspicious-ui/`): `pnpm test` (Vitest). Lint: `pnpm lint`.
- **Backend lint:** `ruff check Suspicious/` must pass before each backend commit.
- **TDD:** red → green → commit per task.

---

### Task 1: Case fields + migration

**Files:**
- Modify: `Suspicious/Suspicious/case_handler/models.py`
- Create: `Suspicious/Suspicious/case_handler/migrations/0019_case_challenge_fields.py`
- Test: `Suspicious/Suspicious/case_handler/tests/test_challenge_fields.py`

**Interfaces:**
- Produces: `Case.challenge_proposed_result: str` (choices Safe/Dangerous, default
  `""`), `Case.challenge_reason: str` (default `""`); `ProposedVerdict` TextChoices.

- [ ] **Step 1: Write the failing test**

```python
# case_handler/tests/test_challenge_fields.py
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case


class ChallengeFieldsTest(TestCase):
    def test_defaults_blank(self):
        user = get_user_model().objects.create_user(username="cf_u", password="x")
        case = Case.objects.create(description="", reporter=user)
        self.assertEqual(case.challenge_proposed_result, "")
        self.assertEqual(case.challenge_reason, "")

    def test_stores_proposal(self):
        user = get_user_model().objects.create_user(username="cf_u2", password="x")
        case = Case.objects.create(
            description="", reporter=user,
            challenge_proposed_result="Dangerous", challenge_reason="looks like phishing",
        )
        case.refresh_from_db()
        self.assertEqual(case.challenge_proposed_result, "Dangerous")
        self.assertEqual(case.challenge_reason, "looks like phishing")
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd deployment
docker compose cp ../Suspicious/Suspicious/case_handler/tests/test_challenge_fields.py suspicious:/app/Suspicious/case_handler/tests/test_challenge_fields.py
docker compose exec -T suspicious python manage.py test case_handler.tests.test_challenge_fields --keepdb -v1
```
Expected: FAIL — `Case` has no `challenge_proposed_result` (FieldError / unexpected kwarg).

- [ ] **Step 3: Add the choices enum + fields**

In `case_handler/models.py`, near the existing `Result` TextChoices, add:
```python
class ProposedVerdict(models.TextChoices):
    SAFE = "Safe", _("Safe")
    DANGEROUS = "Dangerous", _("Dangerous")
```
On the `Case` model, near `kpi_counted`, add:
```python
    challenge_proposed_result = models.CharField(
        max_length=20, choices=ProposedVerdict.choices, blank=True, default="",
        verbose_name="Challenge Proposed Result",
    )
    challenge_reason = models.TextField(
        blank=True, default="", verbose_name="Challenge Reason",
    )
```
(`_` is already imported as `from django.utils.translation import gettext_lazy as _` — confirm; if not, use the existing translation import in the file.)

Generate the migration:
```bash
docker compose exec -T suspicious python manage.py makemigrations case_handler
docker compose exec -T suspicious cat /app/Suspicious/case_handler/migrations/0019_case_challenge_fields.py > ../Suspicious/Suspicious/case_handler/migrations/0019_case_challenge_fields.py
```
(If Django names it differently, use the generated name and copy that file back.)

- [ ] **Step 4: Run to verify it passes**

```bash
for f in case_handler/models.py case_handler/migrations/0019_case_challenge_fields.py; do
  docker compose cp ../Suspicious/Suspicious/$f suspicious:/app/Suspicious/$f
done
docker compose exec -T suspicious python manage.py test case_handler.tests.test_challenge_fields --keepdb -v1
```
Expected: PASS. Then `ruff check Suspicious/Suspicious/case_handler/models.py`.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/case_handler/models.py \
        Suspicious/Suspicious/case_handler/migrations/0019_case_challenge_fields.py \
        Suspicious/Suspicious/case_handler/tests/test_challenge_fields.py
git commit -m "feat(challenge): Case.challenge_proposed_result + challenge_reason"
```

---

### Task 2: Challenge request serializer

**Files:**
- Modify: `Suspicious/Suspicious/api/serializers/challenge.py`
- Test: `Suspicious/Suspicious/api/tests/test_challenge_serializer.py`

**Interfaces:**
- Produces: `SubmissionChallengeSerializer` with fields `proposed_result`
  (required, ChoiceField `["Safe","Dangerous"]`) and `reason` (optional,
  `CharField`, default `""`, max 2000).

- [ ] **Step 1: Write the failing test**

```python
# api/tests/test_challenge_serializer.py
from django.test import SimpleTestCase
from api.serializers.challenge import SubmissionChallengeSerializer


class SubmissionChallengeSerializerTest(SimpleTestCase):
    def test_valid_minimal(self):
        s = SubmissionChallengeSerializer(data={"proposed_result": "Safe"})
        self.assertTrue(s.is_valid(), s.errors)
        self.assertEqual(s.validated_data["proposed_result"], "Safe")
        self.assertEqual(s.validated_data.get("reason", ""), "")

    def test_valid_with_reason(self):
        s = SubmissionChallengeSerializer(
            data={"proposed_result": "Dangerous", "reason": "phishing"}
        )
        self.assertTrue(s.is_valid(), s.errors)
        self.assertEqual(s.validated_data["reason"], "phishing")

    def test_proposed_result_required(self):
        s = SubmissionChallengeSerializer(data={"reason": "x"})
        self.assertFalse(s.is_valid())
        self.assertIn("proposed_result", s.errors)

    def test_proposed_result_limited(self):
        s = SubmissionChallengeSerializer(data={"proposed_result": "Suspicious"})
        self.assertFalse(s.is_valid())
        self.assertIn("proposed_result", s.errors)

    def test_reason_max_length(self):
        s = SubmissionChallengeSerializer(
            data={"proposed_result": "Safe", "reason": "x" * 2001}
        )
        self.assertFalse(s.is_valid())
        self.assertIn("reason", s.errors)
```

- [ ] **Step 2: Run to verify it fails**

```bash
docker compose cp ../Suspicious/Suspicious/api/tests/test_challenge_serializer.py suspicious:/app/Suspicious/api/tests/test_challenge_serializer.py
docker compose exec -T suspicious python manage.py test api.tests.test_challenge_serializer --keepdb -v1
```
Expected: FAIL — `ImportError: cannot import name 'SubmissionChallengeSerializer'`.

- [ ] **Step 3: Add the serializer**

Append to `api/serializers/challenge.py`:
```python
class SubmissionChallengeSerializer(serializers.Serializer):
    proposed_result = serializers.ChoiceField(choices=["Safe", "Dangerous"])
    reason = serializers.CharField(
        required=False, allow_blank=True, default="",
        trim_whitespace=True, max_length=2000,
    )
```

- [ ] **Step 4: Run to verify it passes**

```bash
docker compose cp ../Suspicious/Suspicious/api/serializers/challenge.py suspicious:/app/Suspicious/api/serializers/challenge.py
docker compose exec -T suspicious python manage.py test api.tests.test_challenge_serializer --keepdb -v1
```
Expected: PASS. Then `ruff check Suspicious/Suspicious/api/serializers/challenge.py`.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/api/serializers/challenge.py \
        Suspicious/Suspicious/api/tests/test_challenge_serializer.py
git commit -m "feat(challenge): SubmissionChallengeSerializer (proposed_result + reason)"
```

---

### Task 3: Notify/stats refactor in the challenge service

**Files:**
- Modify: `Suspicious/Suspicious/tasp/services/challenge.py`
- Test: `Suspicious/Suspicious/tasp/tests/test_challenge_service.py`

**Interfaces:**
- Consumes: `CaseChallengeService` (existing).
- Produces: module function `notify_and_record_challenge(case, logger) -> None`
  that runs stats + notify without re-validating; `run_case_challenge` keeps its
  behavior. The notification header includes the proposal when present.

- [ ] **Step 1: Write the failing test**

```python
# tasp/tests/test_challenge_service.py
import logging
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from tasp.services.challenge import notify_and_record_challenge


class NotifyAndRecordTest(TestCase):
    @patch("tasp.services.challenge.CaseChallengeService.notify")
    @patch("tasp.services.challenge.CaseChallengeService.update_user_stats")
    def test_runs_stats_and_notify_without_validate(self, m_stats, m_notify):
        user = get_user_model().objects.create_user(username="ncs", password="x")
        # Already-challenged case must NOT raise (no validate() here).
        case = Case.objects.create(
            description="", reporter=user, is_challenged=True,
            challenge_proposed_result="Safe",
        )
        notify_and_record_challenge(case, logging.getLogger("t"))
        m_stats.assert_called_once()
        m_notify.assert_called_once()
```

- [ ] **Step 2: Run to verify it fails**

```bash
docker compose cp ../Suspicious/Suspicious/tasp/tests/test_challenge_service.py suspicious:/app/Suspicious/tasp/tests/test_challenge_service.py
docker compose exec -T suspicious python manage.py test tasp.tests.test_challenge_service --keepdb -v1
```
Expected: FAIL — `ImportError: cannot import name 'notify_and_record_challenge'`.

- [ ] **Step 3: Refactor the service**

In `tasp/services/challenge.py`:

(a) Add the module function (after `run_case_challenge`):
```python
def notify_and_record_challenge(case, logger) -> None:
    """Stats + CERT/TheHive notification for an already-marked challenge.
    Unlike run_case_challenge, does NOT validate/mark — the caller (in-app
    view) has already marked the case, including the proposed verdict."""
    service = CaseChallengeService(case, logger)
    service.update_user_stats()
    service.notify()
```

(b) In `CaseChallengeService.notify`, include the proposal in the header when
set. Change the `mail_header` line to:
```python
        mail_header = f"Case ID {self.case.id} challenged by {self.case.reporter.username}"
        proposed = getattr(self.case, "challenge_proposed_result", "")
        if proposed:
            mail_header += f" — reporter says it should be {proposed}"
            reason = getattr(self.case, "challenge_reason", "")
            if reason:
                mail_header += f" (reason: {reason})"
```
Leave the rest of `notify` unchanged.

- [ ] **Step 4: Run to verify it passes**

```bash
docker compose cp ../Suspicious/Suspicious/tasp/services/challenge.py suspicious:/app/Suspicious/tasp/services/challenge.py
docker compose exec -T suspicious python manage.py test tasp.tests.test_challenge_service --keepdb -v1
```
Expected: PASS. Then `ruff check Suspicious/Suspicious/tasp/services/challenge.py`.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/tasp/services/challenge.py \
        Suspicious/Suspicious/tasp/tests/test_challenge_service.py
git commit -m "refactor(challenge): notify_and_record_challenge + proposal in header"
```

---

### Task 4: Wire the proposal into `SubmissionChallengeView`

**Files:**
- Modify: `Suspicious/Suspicious/api/views/submissions.py` (`SubmissionChallengeView.post`)
- Test: `Suspicious/Suspicious/api/tests/test_submission_challenge_view.py`

**Interfaces:**
- Consumes: `SubmissionChallengeSerializer` (Task 2),
  `notify_and_record_challenge` (Task 3), the two `Case` fields (Task 1).
- Produces: `POST /api/submissions/{id}/challenge/` accepts
  `{proposed_result, reason?}`, stores them, marks challenged, notifies CERT.

- [ ] **Step 1: Write the failing test**

```python
# api/tests/test_submission_challenge_view.py
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APITestCase
from case_handler.models import Case
from case_handler.lifecycle import LifecycleState


class SubmissionChallengeViewTest(APITestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="scv", password="x")
        self.client.force_authenticate(self.user)

    def _case(self):
        return Case.objects.create(
            description="", reporter=self.user, is_challengeable=True,
            lifecycle_state=LifecycleState.FINALIZED, status="Done", results="Safe",
        )

    @patch("api.views.submissions.notify_and_record_challenge")
    def test_stores_proposal_marks_and_notifies(self, m_notify):
        case = self._case()
        url = reverse("submission-challenge", args=[case.id])
        r = self.client.post(url, {"proposed_result": "Dangerous", "reason": "phish"}, format="json")
        self.assertEqual(r.status_code, 200, r.content)
        case.refresh_from_db()
        self.assertTrue(case.is_challenged)
        self.assertEqual(case.challenge_proposed_result, "Dangerous")
        self.assertEqual(case.challenge_reason, "phish")
        self.assertEqual(case.lifecycle_state, LifecycleState.CONTESTED)
        m_notify.assert_called_once()

    @patch("api.views.submissions.notify_and_record_challenge")
    def test_missing_proposed_result_is_400_and_no_change(self, m_notify):
        case = self._case()
        url = reverse("submission-challenge", args=[case.id])
        r = self.client.post(url, {"reason": "x"}, format="json")
        self.assertEqual(r.status_code, 400)
        case.refresh_from_db()
        self.assertFalse(case.is_challenged)
        m_notify.assert_not_called()
```

(Confirm the URL name via `Suspicious/Suspicious/api/urls.py` — it is
`submission-challenge`. If `CanChallengeSubmission` requires the reporter to own
the case, the case is created with `reporter=self.user`, so it passes.)

- [ ] **Step 2: Run to verify it fails**

```bash
docker compose cp ../Suspicious/Suspicious/api/tests/test_submission_challenge_view.py suspicious:/app/Suspicious/api/tests/test_submission_challenge_view.py
docker compose exec -T suspicious python manage.py test api.tests.test_submission_challenge_view --keepdb -v1
```
Expected: FAIL — proposal not stored / notify not called (view ignores body).

- [ ] **Step 3: Update the view**

In `api/views/submissions.py`, add imports at top:
```python
from api.serializers.challenge import SubmissionChallengeSerializer
from tasp.services.challenge import notify_and_record_challenge
import logging
```
(Use the module's existing logger if one is defined; otherwise
`logger = logging.getLogger(__name__)`.)

Rewrite `SubmissionChallengeView.post` body — validate first, then the existing
guards, then store + mark + transition + notify:
```python
    def post(self, request, submission_id: int):
        obj = self.get_object(submission_id)

        serializer = SubmissionChallengeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if obj.is_challenged:
            raise ValidationError({"detail": "Submission already challenged."})
        if not obj.is_challengeable:
            raise ValidationError({"detail": "Submission cannot be challenged."})

        from case_handler.lifecycle import LifecycleState, transition

        obj.is_challenged = True
        obj.challenge_proposed_result = serializer.validated_data["proposed_result"]
        obj.challenge_reason = serializer.validated_data.get("reason", "")
        obj.save(update_fields=[
            "is_challenged", "challenge_proposed_result", "challenge_reason", "last_update",
        ])
        if obj.lifecycle_state == LifecycleState.FINALIZED:
            transition(obj, LifecycleState.CONTESTED)
        else:
            obj.status = "Challenged"
            obj.save(update_fields=["status"])

        try:
            notify_and_record_challenge(obj, logger)
        except Exception:
            logger.exception("Challenge notify failed for case %s", obj.id)

        return Response({"detail": "Challenge submitted."}, status=status.HTTP_200_OK)
```

- [ ] **Step 4: Run to verify it passes**

```bash
docker compose cp ../Suspicious/Suspicious/api/views/submissions.py suspicious:/app/Suspicious/api/views/submissions.py
docker compose exec -T suspicious python manage.py test api.tests.test_submission_challenge_view api --keepdb -v1
```
Expected: PASS (new tests + existing api suite green). Then
`ruff check Suspicious/Suspicious/api/views/submissions.py`.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/api/views/submissions.py \
        Suspicious/Suspicious/api/tests/test_submission_challenge_view.py
git commit -m "feat(challenge): store proposed verdict + reason and notify CERT on in-app challenge"
```

---

### Task 5: Expose the proposal in the submission detail serializer

**Files:**
- Modify: `Suspicious/Suspicious/api/serializers/submissions.py` (`SubmissionDetailsSerializer.Meta.fields`)
- Test: `Suspicious/Suspicious/api/tests/test_submission_detail_challenge.py`

**Interfaces:**
- Produces: the submission detail response includes `challenge_proposed_result`
  and `challenge_reason`.

- [ ] **Step 1: Write the failing test**

```python
# api/tests/test_submission_detail_challenge.py
from django.contrib.auth import get_user_model
from django.test import TestCase
from case_handler.models import Case
from api.serializers.submissions import SubmissionDetailsSerializer


class DetailChallengeFieldsTest(TestCase):
    def test_detail_exposes_challenge_proposal(self):
        user = get_user_model().objects.create_user(username="dcf", password="x")
        case = Case.objects.create(
            description="", reporter=user, is_challenged=True,
            challenge_proposed_result="Dangerous", challenge_reason="phish",
        )
        data = SubmissionDetailsSerializer(case).data
        self.assertEqual(data["challenge_proposed_result"], "Dangerous")
        self.assertEqual(data["challenge_reason"], "phish")
```

- [ ] **Step 2: Run to verify it fails**

```bash
docker compose cp ../Suspicious/Suspicious/api/tests/test_submission_detail_challenge.py suspicious:/app/Suspicious/api/tests/test_submission_detail_challenge.py
docker compose exec -T suspicious python manage.py test api.tests.test_submission_detail_challenge --keepdb -v1
```
Expected: FAIL — `KeyError: 'challenge_proposed_result'`.

- [ ] **Step 3: Add the fields**

In `api/serializers/submissions.py`, in `SubmissionDetailsSerializer.Meta`
(class at line ~297), extend `fields`:
```python
    class Meta(SubmissionRowSerializer.Meta):
        fields = SubmissionRowSerializer.Meta.fields + [
            # ... existing detail-only fields ...
            "challenge_proposed_result",
            "challenge_reason",
        ]
```
(Append the two names to the existing `fields` list — do not remove the current
entries. They are plain `Case` model Char/Text fields, so `ModelSerializer`
serializes them automatically.)

- [ ] **Step 4: Run to verify it passes**

```bash
docker compose cp ../Suspicious/Suspicious/api/serializers/submissions.py suspicious:/app/Suspicious/api/serializers/submissions.py
docker compose exec -T suspicious python manage.py test api.tests.test_submission_detail_challenge api --keepdb -v1
```
Expected: PASS. Then `ruff check Suspicious/Suspicious/api/serializers/submissions.py`.

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/api/serializers/submissions.py \
        Suspicious/Suspicious/api/tests/test_submission_detail_challenge.py
git commit -m "feat(challenge): expose proposed verdict + reason in submission detail"
```

---

### Task 6: Frontend — challenge dialog form + API

**Files:**
- Modify: `suspicious-ui/src/features/submissions/api.ts` (`challengeSubmission`)
- Modify: `suspicious-ui/src/pages/SubmissionsPage.tsx` (dialog + mutation)
- Test: `suspicious-ui/src/pages/__tests__/SubmissionsPage.test.tsx`

**Interfaces:**
- Consumes: `POST /submissions/{id}/challenge/` with `{proposed_result, reason}`.
- Produces: dialog requires a Safe/Dangerous choice before submit; sends the body.

- [ ] **Step 1: Write the failing test**

Add to `suspicious-ui/src/pages/__tests__/SubmissionsPage.test.tsx` a test that
opens the challenge dialog, asserts Confirm is disabled until a verdict is
chosen, picks "Dangerous", submits, and asserts `challengeSubmission` was called
with `(id, { proposed_result: "Dangerous", reason: "" })`. Mirror the existing
mock setup in that file (`challengeSubmission: vi.fn()`); use
`@testing-library/react` `render`, `screen`, `fireEvent`/`userEvent`, and
`waitFor`. Example assertion core:
```ts
expect(challengeSubmission).toHaveBeenCalledWith(
  expect.any(Number),
  { proposed_result: "Dangerous", reason: "" },
);
```
(Match the file's existing render harness — QueryClientProvider wrapper, router,
and the row that exposes the Challenge button when `is_challengeable`.)

- [ ] **Step 2: Run to verify it fails**

```bash
cd suspicious-ui
pnpm test -- src/pages/__tests__/SubmissionsPage.test.tsx
```
Expected: FAIL — dialog has no verdict control / `challengeSubmission` called with
a bare id.

- [ ] **Step 3: Update the API helper + dialog**

`suspicious-ui/src/features/submissions/api.ts` — change `challengeSubmission`:
```ts
export async function challengeSubmission(
  id: number,
  body: { proposed_result: "Safe" | "Dangerous"; reason?: string },
): Promise<{ detail: string }> {
  const res = await api.post(`/submissions/${id}/challenge/`, body);
  return res.data;
}
```

`suspicious-ui/src/pages/SubmissionsPage.tsx`:
- Add local state near `challengeId`:
  ```tsx
  const [proposedResult, setProposedResult] = React.useState<"Safe" | "Dangerous" | null>(null);
  const [challengeReason, setChallengeReason] = React.useState("");
  ```
- Change the mutation `mutationFn` to accept the body:
  ```tsx
  mutationFn: async (vars: { id: number; proposed_result: "Safe" | "Dangerous"; reason: string }) =>
    challengeSubmission(vars.id, { proposed_result: vars.proposed_result, reason: vars.reason }),
  ```
  Keep `onMutate` optimistic update keyed on `vars.id` (adjust to read
  `vars.id`). In `onSuccess`, also reset: `setProposedResult(null); setChallengeReason("");`.
- In the dialog (`open={challengeId !== null}`), replace the static body/Confirm:
  - Add a `ToggleButtonGroup` (`value={proposedResult}`, exclusive,
    `onChange={(_, v) => v && setProposedResult(v)}`) with two `ToggleButton`s
    `value="Safe"` / `value="Dangerous"`, labelled "What should the verdict be?".
  - Add a multiline `TextField` "Why? (optional)" bound to `challengeReason`.
  - Confirm button: `disabled={challengeMutation.isPending || challengeId === null || proposedResult === null}`,
    `onClick={() => { if (challengeId && proposedResult) challengeMutation.mutate({ id: challengeId, proposed_result: proposedResult, reason: challengeReason }); }}`.
  - Reset `proposedResult`/`challengeReason` in the dialog `onClose` too.
  - Import `ToggleButton`, `ToggleButtonGroup`, `TextField` from `@mui/material`.

- [ ] **Step 4: Run to verify it passes**

```bash
pnpm test -- src/pages/__tests__/SubmissionsPage.test.tsx
pnpm lint
```
Expected: PASS + lint clean.

- [ ] **Step 5: Commit**

```bash
git add suspicious-ui/src/features/submissions/api.ts \
        suspicious-ui/src/pages/SubmissionsPage.tsx \
        suspicious-ui/src/pages/__tests__/SubmissionsPage.test.tsx
git commit -m "feat(ui): challenge dialog asks for proposed verdict + reason"
```

---

### Task 7: Frontend — analyst display panel + full verify

**Files:**
- Modify: `suspicious-ui/src/features/investigation/api.ts` (types — add the two fields)
- Modify: `suspicious-ui/src/pages/InvestigationPage.tsx` (display panel)
- Test: `suspicious-ui/src/pages/__tests__/InvestigationPage.test.tsx`

**Interfaces:**
- Consumes: `challenge_proposed_result` + `challenge_reason` from the submission
  detail response (Task 5).

- [ ] **Step 1: Write the failing test**

Add to `suspicious-ui/src/pages/__tests__/InvestigationPage.test.tsx`: with a
challenged case fixture that has `challenge_proposed_result: "Dangerous"` and
`challenge_reason: "phish"`, assert the page shows the proposed verdict and the
reason text (e.g. `expect(screen.getByText(/reporter/i)).toBeInTheDocument()` and
the "Dangerous"/"phish" strings). Also add a case WITHOUT the fields and assert
the panel is absent. Extend the existing fixture object used in that file (it
already has `is_challenged` / `is_challengeable`).

- [ ] **Step 2: Run to verify it fails**

```bash
cd suspicious-ui
pnpm test -- src/pages/__tests__/InvestigationPage.test.tsx
```
Expected: FAIL — no proposal panel rendered.

- [ ] **Step 3: Add the type + panel**

- In `suspicious-ui/src/features/investigation/api.ts`, add to the submission
  detail TypeScript type: `challenge_proposed_result?: "Safe" | "Dangerous" | "";`
  and `challenge_reason?: string;`.
- In `InvestigationPage.tsx`, where challenge state is shown, render a small
  panel only when `data.challenge_proposed_result` is truthy:
  ```tsx
  {data.challenge_proposed_result ? (
    <Box /* small SoftCard/section */>
      <Typography variant="subtitle2">Reporter's challenge</Typography>
      <Typography variant="body2">
        Proposed verdict: <strong>{data.challenge_proposed_result}</strong>
      </Typography>
      {data.challenge_reason ? (
        <Typography variant="body2">Reason: {data.challenge_reason}</Typography>
      ) : null}
    </Box>
  ) : null}
  ```
  Follow the page's existing card/section styling (SoftCard or the local panel
  pattern) rather than a bare `Box` if one is established.

- [ ] **Step 4: Run to verify it passes + full frontend suite**

```bash
pnpm test -- src/pages/__tests__/InvestigationPage.test.tsx
pnpm test
pnpm lint
```
Expected: all PASS, lint clean.

- [ ] **Step 5: Backend full suite + commit**

```bash
cd ../deployment
docker compose exec -T suspicious python manage.py test --keepdb -v1
cd ..
ruff check Suspicious/
git add suspicious-ui/src/features/investigation/api.ts \
        suspicious-ui/src/pages/InvestigationPage.tsx \
        suspicious-ui/src/pages/__tests__/InvestigationPage.test.tsx
git commit -m "feat(ui): show reporter's proposed verdict + reason on challenged case"
```
Expected: full backend suite OK, ruff clean, frontend green.

---

## Self-Review

**Spec coverage:**
- Storage (2 Case fields + 0019) → Task 1. ✓
- Serializer (proposed_result required Safe/Dangerous, reason optional ≤2000) → Task 2. ✓
- Notify/stats refactor + proposal in notification → Task 3. ✓
- View stores fields + marks + transitions + notifies → Task 4. ✓
- Detail serializer exposes fields → Task 5. ✓
- Dialog form (required verdict, optional reason) + API body → Task 6. ✓
- Analyst display panel → Task 7. ✓
- Backward-compat note (body now required; only our UI calls it) → Task 4 + Task 6 shipped together. ✓

**Type consistency:** `challenge_proposed_result` / `challenge_reason` and the
`"Safe"`/`"Dangerous"` value set used identically across model (T1), serializer
(T2), service header (T3), view (T4), detail serializer (T5), and UI (T6/T7).
`notify_and_record_challenge(case, logger)` defined in T3, consumed in T4.
`challengeSubmission(id, {proposed_result, reason})` defined in T6, consumed in T6.

**Placeholder scan:** none. Two frontend steps (T6/T7 test bodies) describe the
assertions in prose plus the key `expect(...)` because they must match each
file's existing render harness — the implementer mirrors the harness already in
that test file rather than a guessed one.

**Open confirmations for the implementer:** the `_` translation import in
`models.py` (T1); the exact URL name `submission-challenge` (T4, verify in
`api/urls.py`); whether `SubmissionDetailsSerializer` already lists explicit
fields to append to (T5); the established card/panel component on
`InvestigationPage` (T7).
