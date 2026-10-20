# SOAR and API integration

How to submit indicators to Suspicious from a script or a SOAR playbook, wait for the verdict, and get a result ready to paste into a ticket. Every call is a plain HTTPS request with a token; the full request and response schemas are in the [REST API reference](../reference/rest-api.md) and, on a running instance, at `/api/docs/` (Swagger) and `/api/schema/` (OpenAPI).

In the examples, `$HOST` is your Suspicious URL and `$TOKEN` is the token from the next section.

## 1. Get a token

Two ways:

- **Long-lived key for an automation (recommended).** In the Django admin, open **Profiles → API Keys → Add**, pick the user the automation runs as and an expiry (30 days up to 2 years). The raw token is shown once, so copy it immediately. Deleting the API key revokes the token.
- **Login (interactive scripts).** `POST /api/auth/login/` with `{"username": "...", "password": "..."}` returns `{"token": "...", "expiry": "...", "user": {...}}`. These tokens last **10 hours**, and login is limited to **5 attempts per minute**.

Send the token on every request:

```bash
curl -H "Authorization: Token $TOKEN" "$HOST/api/auth/me/"
```

`/api/auth/me/` returns the account and its groups; use it to check the token works.

## 2. Submit

All submissions create a case and return immediately; the analysis runs in the background.

| What | Request |
|---|---|
| A URL | `POST /api/submit/url/` with `{"url": "https://example.test/x", "context": "optional note"}` |
| An IP or a hash | `POST /api/submit/other/` with `{"value": "203.0.113.7"}` |
| A file or an `.eml` | `POST /api/submit/file/` as multipart with a `file` field |
| A list of indicators | `POST /api/submit/indicators/` with `{"indicators": "one per line"}`. At most **100** per submission; the list becomes one case with a verdict per indicator |

```bash
curl -X POST -H "Authorization: Token $TOKEN" -H "Content-Type: application/json" \
  -d '{"url": "https://example.test/login", "context": "reported by SOC ticket 1234"}' \
  "$HOST/api/submit/url/"
```

Response (HTTP 201 Created):

```json
{"status": "success", "accepted": true, "submission_type": "url", "result_type": "case",
 "case_id": 4521, "id": 4521, "message": "Submission accepted."}
```

Add `"external_ref": "your-reference"` to any submit call (a form field for a file) to make the call safe to repeat: submitting the same reference again returns the original case, with HTTP 200 and `"reused": true`, before anything is stored or analysed. The reference is scoped to your account, accepts letters, digits and `. _ : @ / + = # -` (255 characters at most), and should be unique per artifact. It is echoed in the response, in `/api/submissions/` rows and in the ticket, and `GET /api/submissions/?external_ref=...` finds the case again.

If the indicator is on an allow list, no case is created: the answer is HTTP 200 with `accepted: true`, `case_id: null` and the message "Submission accepted (allowlisted, no case created)." Validation problems return HTTP 400 with `{"status": "error", "code": "...", "detail": "..."}`.

## 3. Wait for the verdict

The lightest way to wait, and it works for the account that submitted the case, is the compact verdict:

```bash
curl -H "Authorization: Token $TOKEN" "$HOST/api/submissions/4521/verdict/"
```

Poll until `"done": true`. Until then `result` is `null` (the case holds a placeholder verdict while it is analysed). Once done it carries `result`, `score`, `confidence`, `ai_classification`, `analysis_health` and `observables` (a verdict per indicator). A challenged case counts as done. An account sees the cases it submitted; an investigator sees every case.

For the full case, poll `/api/investigations/<id>/` until its `status` is `DONE` (statuses: `NEW`, `IN_PROGRESS`, `DONE`, `CHALLENGED`):

```bash
curl -H "Authorization: Token $TOKEN" "$HOST/api/investigations/4521/"
```

The useful fields are `status`, `result` (`SAFE`, `INCONCLUSIVE`, `SUSPICIOUS`, `DANGEROUS`, `ALLOW_LISTED`, `FAILURE`), `case_infos` (score, confidence, `verdict_explanation`), `threat_classification` (what kind of threat, when known) and `analysis_health` (how many analyzers failed or are still running; a non-zero `failed` means the verdict has lower confidence). Poll every 10 to 30 seconds; how long a case takes depends on the analyzers that run for it.

This endpoint is for **investigator** accounts (the CERT and Admin groups). An account that is not an investigator can read only its own submissions at `/api/submissions/<id>/`.

## 4. Get a ticket-ready result

```bash
curl -H "Authorization: Token $TOKEN" "$HOST/api/submissions/4521/ticket/"
```

returns one flat payload meant to be copied into a ticket:

- `title`, `verdict` (`result`, `score`, `confidence`, `severity`, `tlp`, `pap`, `ai_classification`, `rationale`),
- `threat_classification` and `analysis_health`,
- `observables`: each indicator with its own verdict and a link to its evidence,
- `analyzer_summary` (reports per verdict, analyzers that ran),
- `recommended_action`.

To create or update the matching **TheHive** alert from that payload, send `POST` to the same URL. It answers `{"status": "created" or "updated", "alert_id": "...", "alert_url": "..."}`. It needs the TheHive connector to be enabled and configured (409 otherwise), and it records who pushed in the alert and in the audit log.

## 5. Look up what is already known

```bash
curl -H "Authorization: Token $TOKEN" "$HOST/api/lookup/?type=url&value=hxxps://evil[.]example/login"
```

returns the verdict Suspicious already holds for a `url`, `ip`, `domain` or `hash`, without creating a case: `{"known": true, "verdict": "malicious", "score": 9.0, "confidence": 0.8, "last_analyzed": "..."}`. `"known": false` means nothing is on file, so submit it. Defanged input is accepted. Verdicts are `malicious`, `suspicious`, `safe` or `inconclusive`. Investigator accounts only.

## 6. Human-readable report

`GET /api/cases/4521/report/` returns the case report as HTML (with screenshots), and `GET /api/cases/4521/report.md` returns the same verdict, explanation and per-indicator evidence as Markdown, for a ticket, a wiki page or a chat message. Both are downloads. In the web UI they are the **Full report** and **Markdown** buttons on a case. Text taken from outside (indicators, analyzer evidence, the reporter's words) is escaped in the Markdown, so it cannot create links or headings.

## Cortex XSOAR

A ready-made integration pack lives in the repository at `integrations/xsoar/Packs/Suspicious`. It wraps the calls above as playbook commands: submit with built-in polling (a playbook task that waits for the verdict), `suspicious-get-verdict`, `-get-ticket`, `-get-report`, `-challenge`, and the `url`, `ip`, `domain` and `file` reputation commands that return DBot scores. Setup, the account each command needs and playbook recipes are in the pack's README.

For the other direction, Suspicious opens an XSOAR incident for each finalised case at or above a verdict you choose (default `Suspicious`) through the `xsoar` connector. Enable and configure it in Settings, Connectors; the setup is in the connectors README. Cases a playbook submitted through the pack are not pushed back.

## Limits and good practice

- **Rate limit:** 3000 requests per hour per user. Polling every 15 seconds uses 240 an hour per open case; every 60 seconds, 60.
- **Use one account per automation,** so its activity is visible and its key can be revoked on its own.
- **Idempotency:** submitting the same indicator again reuses the earlier analysis where possible but still creates a new case. Send an `external_ref` to get the original case back instead.
- **Errors:** 401 means a missing or expired token, 403 a missing permission (not an investigator), 429 the rate limit.
