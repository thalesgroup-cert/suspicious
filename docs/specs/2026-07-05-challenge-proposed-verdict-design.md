# Challenge with Proposed Verdict — Design

**Status:** Design approved, pending spec review
**Date:** 2026-07-05
**Branch:** feature/frontweb

## Context

When a case is finalised, the reporter can **challenge** the verdict. Today a
challenge is a binary "I disagree" flag — it captures nothing about *what the
user thinks the result should be* or *why*. Two entry points exist:

- **In-app** (`POST /api/submissions/{id}/challenge/`, `SubmissionChallengeView`,
  `IsAuthenticated + CanChallengeSubmission`): flips `Case.is_challenged`,
  transitions `FINALIZED → CONTESTED`. **Does not notify CERT.**
- **Email token link** (`GET /api/cases/{id}/challenge/<token>/`,
  `CaseChallengeTokenView`, `AllowAny`): one-click auto-challenge that runs
  `CaseChallengeService.run_case_challenge` → validate → mark → stats → **notify
  CERT/TheHive**.

The in-app path silently diverges from the token path: it neither notifies CERT
nor updates challenge stats. This feature closes that gap for the in-app path.

## Goal

Let a challenging user say **what they think the verdict should be** (binary
Safe/Dangerous) and **why** (optional), store it on the case, show it to the
analyst, and include it in the CERT/TheHive challenge notification.

## Scope

**In:** the in-app challenge path (dialog + API + storage + notify + analyst
display). **Out:** the email-token path stays one-click (no form) for now —
capturing input there needs a public token-form landing page, deferred.

## Decisions (user-approved)

| Decision | Choice |
|---|---|
| Entry point | In-app dialog only. |
| Proposed verdict | Binary **Safe / Dangerous**, required. |
| Reason | Free text, **optional**. |
| Notification | In-app challenge now notifies CERT/TheHive with the proposal (unifies the divergence). |
| Analyst display | Show proposed verdict + reason on the challenged case. |

## Design

### 1. Storage — two `Case` fields (migration 0019)

`case_handler/models.py`:

```python
class ProposedVerdict(models.TextChoices):
    SAFE = "Safe", _("Safe")
    DANGEROUS = "Dangerous", _("Dangerous")

# on Case:
challenge_proposed_result = models.CharField(
    max_length=20, choices=ProposedVerdict.choices, blank=True, default="",
    verbose_name="Challenge Proposed Result",
)
challenge_reason = models.TextField(
    blank=True, default="", verbose_name="Challenge Reason",
)
```

Values reuse the `Result` string set (`"Safe"`, `"Dangerous"`) so they compare
directly with `case.results`. Migration `0019_case_challenge_fields` is a plain
additive `AddField` pair — no backfill.

### 2. API — accept the proposal on the in-app challenge

New serializer `api/serializers/challenge.py`:

```python
class SubmissionChallengeSerializer(serializers.Serializer):
    proposed_result = serializers.ChoiceField(choices=["Safe", "Dangerous"])
    reason = serializers.CharField(required=False, allow_blank=True, default="",
                                   trim_whitespace=True, max_length=2000)
```

`SubmissionChallengeView.post` (`api/views/submissions.py`):

- Validate the body with `SubmissionChallengeSerializer`
  (`is_valid(raise_exception=True)`) — `proposed_result` required and one of the
  two; empty/invalid → 400.
- Keep the existing guards (`is_challenged` → 400 "already challenged";
  `not is_challengeable` → 400 "cannot be challenged").
- In one save, set `is_challenged=True`, `challenge_proposed_result`,
  `challenge_reason`, then `FINALIZED → CONTESTED` via `transition` (unchanged).
- **Notify + stats:** call the shared `CaseChallengeService` so CERT/TheHive is
  notified and challenge stats update — matching the token path. To avoid the
  service's `validate()` re-rejecting the already-marked case, factor the
  notify+stats steps so the view can invoke them after it has marked the case
  (see §5). The notification message includes the proposed verdict and reason.

Backward compatibility: the endpoint previously accepted an empty body. It now
**requires** `proposed_result`. The only caller is our own UI (updated in §3),
so this is an internal contract change, not a public break.

### 3. Frontend — challenge dialog becomes a form

`suspicious-ui/src/pages/SubmissionsPage.tsx` (the existing challenge
confirm-dialog, gated by `challengeId`):

- **"What should the verdict be?"** — required MUI `ToggleButtonGroup`
  (`Safe` | `Dangerous`), local state `proposedResult`.
- **"Why? (optional)"** — multiline `TextField`, local state `reason`.
- **Submit** disabled until `proposedResult` is set.
- On submit: `challengeMutation.mutate({ id, proposed_result, reason })`.

`suspicious-ui/src/features/submissions/api.ts`:

```ts
export async function challengeSubmission(
  id: number,
  body: { proposed_result: "Safe" | "Dangerous"; reason?: string },
): Promise<{ detail: string }> {
  const res = await api.post(`/submissions/${id}/challenge/`, body);
  return res.data;
}
```

Update `challengeMutation` (`mutationFn` takes `{id, proposed_result, reason}`),
reset the two local fields in `onSuccess`/on close. The optimistic update
(`is_challenged: true, is_challengeable: false`) is unchanged.

### 4. Analyst display

Show the reporter's proposal on the challenged case in
`suspicious-ui/src/pages/InvestigationPage.tsx`: when the case is challenged and
`challenge_proposed_result` is set, render a small "Reporter's challenge" panel —
proposed verdict chip + reason text. Requires the case/submission detail
serializer to expose `challenge_proposed_result` + `challenge_reason` (add to the
relevant DRF serializer's fields).

### 5. Notify/stats refactor (to reuse from both paths)

`tasp/services/challenge.py`: `run_case_challenge` currently bundles
validate → mark → stats → notify. Split so the view can drive the steps it needs
without re-validating an already-marked case, e.g. expose
`notify_and_record_challenge(case, logger)` that runs `update_user_stats()` +
`notify()`. `run_case_challenge` (token path) keeps its existing behavior by
calling the same pieces. The in-app view marks the case itself (with the new
fields), then calls `notify_and_record_challenge`. The `ChallengeToTheHiveService`
message gains the proposed verdict + reason (passed through / appended to the
existing `mail_header`/body).

## Data flow (in-app challenge, after)

```
UI dialog (verdict + reason)
  └─ POST /submissions/{id}/challenge/ {proposed_result, reason}
       ├─ serializer validates
       ├─ guards (is_challenged / is_challengeable)
       ├─ case: is_challenged=True, challenge_proposed_result, challenge_reason
       │        + transition FINALIZED → CONTESTED
       └─ notify_and_record_challenge(case)  → CERT/TheHive (incl. proposal) + stats
InvestigationPage → shows proposed verdict + reason to the analyst
```

## Error handling

- Invalid/missing `proposed_result` → 400 (serializer). Already-challenged /
  not-challengeable → 400 (existing guards, unchanged).
- Notification failures are logged and swallowed by the existing `notify()`
  path — a failed CERT email must not roll back the challenge.

## Testing

- **Serializer:** `proposed_result` required + limited to Safe/Dangerous; reason
  optional/blank OK; over-long reason rejected.
- **View:** valid POST stores both fields, marks challenged, transitions to
  CONTESTED, and invokes notify+stats (mock the notifier, assert called with the
  proposal); missing `proposed_result` → 400 and case unchanged; already
  challenged → 400.
- **Detail serializer:** exposes the two new fields.
- **Frontend (Vitest):** Submit disabled until a verdict is chosen; submitting
  sends `{proposed_result, reason}`; the InvestigationPage panel renders the
  proposal when present and is absent otherwise.

## Rollout

One additive migration (0019), no backfill. Internal API contract change
(body now required) consumed only by our own UI, shipped together.

## Self-review notes

- Placeholder scan: none.
- Consistency: `challenge_proposed_result` / `challenge_reason` names and the
  `Safe`/`Dangerous` value set are used identically across model, serializer,
  view, detail serializer, and UI.
- Scope: single plan; backend (model/migration/serializer/view/service) +
  frontend (dialog/api/display) + tests.
- Ambiguity: proposed verdict is exactly `{"Safe","Dangerous"}`; reason optional,
  max 2000 chars.
