# Display Reporter Note + Submission Context — Design

**Status:** Design approved, pending spec review
**Date:** 2026-07-06
**Branch:** feature/frontweb

## Context

The reporter's submission context and mail note are stored but not shown to the
analyst on the investigation page:

- **IOC/URL/file submissions** carry a `context` free-text field. The submit view
  folds it into `Case.description` (`case_handler.py:189-195`). But
  `finalise()` **overwrites** `Case.description` with the analyzer summary
  (`reconciliation.py` — `case.description = _describe(...)`), so on any finalised
  case the original context is already gone. It is never surfaced (the
  investigation `info` field shows the artifact value, falling back to
  `description` only when empty — `investigations.py:get_case_info_value`).
- **Mail submissions** carry the reporter's note in `Mail.reporterNote`
  (`mail_feeder/models.py:37`, set at `gsubmission.py:56`). This IS durable, but
  it is not exposed by any investigation serializer, so it is never displayed.

## Goal

Preserve the IOC/URL/file submission context durably and surface both it and the
mail reporter note on the investigation detail page.

## Scope

**In:** a durable `Case.reporter_context` field for IOC/URL/file submissions; API
exposure of that field and the mail `reporterNote`; an investigation-page panel.
**Out (YAGNI):** the mail *body* text — large, and already visible as the rendered
eml→png preview (`mail_preview_url`). No change to the email-token challenge path
or the submit request contract (the `context` input already exists).

## Decisions (user-approved)

| Decision | Choice |
|---|---|
| Preserve submission context | New durable `Case.reporter_context` field, set at submission, never overwritten by finalise. |
| Mail note | Keep using the existing `Mail.reporterNote`; expose it. |
| Display | One "Reporter's context" panel on `InvestigationPage`, below the existing "Reporter's challenge" panel; shows `reporter_note` for mail cases, `reporter_context` otherwise; hidden when both empty. |
| Mail body | Out of scope. |

## Design

### 1. Storage — `Case.reporter_context` (migration 0020)

`case_handler/models.py`, on `Case` (near `challenge_reason`):

```python
reporter_context = models.TextField(
    blank=True, default="", verbose_name="Reporter Context",
)
```

Migration `0020_case_reporter_context` — additive `AddField`, no backfill.
`finalise()` is untouched, so it never writes this field.

### 2. Set it at submission (IOC/URL/file path)

`CaseCreator.create_case` does **not** `setattr` arbitrary kwargs — it routes each
kwarg through `_create_related_model` (expects model instances). So
`reporter_context` needs an **explicit parameter**, not a kwarg:

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
        reporter=self.user,
    )
    ...
```

(The allow-listed `break` path still constructs the `Case` first, so
`reporter_context` is set there too — fine.)

`case_handler.py` (`create` method): the raw `context` is already computed into
the local `description` before creation. Capture it for the new field and pass it:

```python
        reporter_context = description  # the reporter's `context` input, pre-finalise
        ...
        case = CaseCreator(self.request.user).create_case(
            description=description, reporter_context=reporter_context, **ctx
        )
```

Mail submissions go through a different creator (`CaseCreatorService`,
`gsubmission.py`) and already persist `Mail.reporterNote` — no change there.

### 3. API — expose on the investigation detail

`api/serializers/investigations.py`, `InvestigationDetailsSerializer`:

- Add `"reporter_context"` to `Meta.fields` (plain `Case` model field, serialized
  automatically).
- Add a `reporter_note` SerializerMethodField:

```python
    reporter_note = serializers.SerializerMethodField()

    def get_reporter_note(self, obj: Case) -> str:
        fom = getattr(obj, "fileOrMail", None)
        mail = getattr(fom, "mail", None) if fom else None
        return getattr(mail, "reporterNote", "") or ""
```

and add `"reporter_note"` to `Meta.fields`.

### 4. UI — "Reporter's context" panel

`suspicious-ui/src/features/investigation/api.ts` — add to `InvestigationDetails`:
`reporter_context?: string;` and `reporter_note?: string;`.

`suspicious-ui/src/pages/InvestigationPage.tsx` — directly below the existing
"Reporter's challenge" panel, render a panel only when either value is present:

```tsx
{(detailsQuery.data?.reporter_note || detailsQuery.data?.reporter_context) ? (
  <Box sx={{ px: 2.25, py: 2 }}>
    <Typography sx={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase",
      letterSpacing: "0.08em", color: "text.disabled", mb: 0.75 }}>
      Reporter's context
    </Typography>
    <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: "pre-wrap" }}>
      {detailsQuery.data.reporter_note || detailsQuery.data.reporter_context}
    </Typography>
  </Box>
) : null}
```

Follow the exact label/value `sx` idiom of the sibling panels (challenge / artifact
sections). `whiteSpace: "pre-wrap"` preserves line breaks in a pasted note.

## Data flow

```
IOC/URL/file submit ─ context ─▶ Case.reporter_context (durable)
mail submit ───────── reporter_note ─▶ Mail.reporterNote (durable, existing)
                                     │
GET /investigations/{id}/ ──────────┤ reporter_context (Case field)
  InvestigationDetailsSerializer     └ reporter_note (from linked Mail)
                                     │
InvestigationPage ─────────────────▶ "Reporter's context" panel (note ?? context)
```

## Error handling

- `get_reporter_note` null-safe via `getattr` chains → `""` for non-mail cases.
- No new failure modes; all reads.

## Testing

- **`create_case`:** passing `reporter_context="ctx"` stores it on the Case;
  default is `""`.
- **finalise regression:** a case created with `reporter_context` set, then
  finalised, still has the field intact (only `description` changes).
- **Serializer:** a mail case exposes `reporter_note`; an IOC case created with a
  context exposes `reporter_context`; a bare case exposes both as `""`.
- **Frontend (Vitest):** the panel renders the note/context when present and is
  absent when both are empty; mail case shows the note, IOC case shows the context.

## Rollout

One additive migration (0020), no backfill. Existing finalised cases have empty
`reporter_context` (their original context was already overwritten pre-feature) —
acceptable; new submissions populate it going forward.

## Self-review notes

- Placeholder scan: none.
- Consistency: `reporter_context` (Case field) and `reporter_note` (Mail-sourced)
  names used identically across model, creator, serializer, TS type, and UI.
- Scope: single plan; one migration + creator + serializer + UI.
- Ambiguity: `create_case` gains an explicit `reporter_context` param (NOT a
  kwarg — kwargs are routed to `_create_related_model`). Panel value =
  `reporter_note || reporter_context`.
