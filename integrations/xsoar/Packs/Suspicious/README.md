# Suspicious

Connects Cortex XSOAR to [Suspicious](https://github.com/thalesgroup-cert/suspicious), Thales CERT's phishing and threat-analysis platform. A playbook sends an artifact to Suspicious, waits for the verdict, and gets the verdict back as context and as a DBot score on the indicators.

## Setup

1. In Suspicious, open the Django admin, then **Profiles → API Keys → Add**. Pick the account this integration runs as and an expiry (30 days up to 2 years). Copy the token: it is shown once. Deleting the API key revokes it.
2. In XSOAR, add an instance of the **Suspicious** integration with your Suspicious URL and the token, then click **Test**.
3. The XSOAR tenant must reach Suspicious over HTTPS. On XSOAR 8 SaaS that means Suspicious is reachable from the internet (allow the tenant's egress addresses, which Palo Alto Networks gives per region), or the instance runs on an engine inside your network.

Needs a Suspicious release that includes the `external_ref` submit field, `GET /api/submissions/<id>/verdict/` and `GET /api/lookup/`.

## Which account

| Commands | Account needed |
|---|---|
| `suspicious-submit-*`, `suspicious-get-verdict`, `suspicious-get-report`, `suspicious-challenge` | Any account. It reads back the cases it submitted. |
| `url`, `ip`, `domain`, `file`, `suspicious-get-ticket` | An **investigator**: a member of the CERT, CISO or Admin group. |

Use one account per automation so its activity is visible and its key can be revoked on its own. An investigator account also lets the automation read cases that analysts submitted by hand.

## Playbook recipes

**Phishing report.** Get the original `.eml` into the War Room (the *Get Original Email* sub-playbook does this for EWS, Microsoft Graph Mail and Gmail), then:

```
!suspicious-submit-file entry_id=${File.EntryID} context="Reported by ${incident.reporteremailaddress}" polling=true
```

The command returns once Suspicious has a verdict. `Suspicious.Verdict.result` is `SAFE`, `INCONCLUSIVE`, `SUSPICIOUS`, `DANGEROUS`, `ALLOW_LISTED` or `FAILURE`. `Suspicious.Verdict.dbot_score` is the same verdict as 0 to 3, handy for a playbook condition such as `>= 2`. Every URL, IP, domain and hash Suspicious found in the email gets its own DBot score, so the incident's indicators update on their own. For a forwarded email, pick the inner `.eml` before submitting.

**Indicators from an incident.**

```
!suspicious-submit-indicators indicators=${URL.Data},${IP.Address} polling=true
```

One case, a verdict per indicator, at most 100 per call.

**Enrichment.** `!url`, `!ip`, `!domain` and `!file` return the verdict Suspicious already holds, without creating a case. A value Suspicious has never analysed comes back with DBot score 0 (unknown). Turn on **Submit unknown indicators from reputation commands** in the instance settings to submit such values for analysis, so a later enrichment finds them. It is off by default: enriching a large list would otherwise create a case per value.

**Disagree with a verdict.** `!suspicious-challenge case_id=42 proposed_result=Safe reason="Internal pen-test"` sends it to an analyst. Only the account that submitted the case can challenge it.

**Paste into a ticket.** `!suspicious-get-ticket case_id=42` returns the verdict, the rationale, the observables and a recommended action. `!suspicious-get-report case_id=42` attaches the full report as Markdown or HTML.

## Behaviour worth knowing

- **Resubmitting is safe.** Inside an incident each submission carries a reference built from the incident and the artifact. Running the same task again returns the earlier case (`Suspicious.Submission.reused` is `true`) instead of analysing it twice. Pass `force_new=true` to analyse again, or your own `external_ref` to choose the key.
- **Allow-listed artifacts** create no case. The command returns right away with `result` `ALLOW_LISTED` and DBot score 1.
- **Polling.** Submit commands ask for the verdict every 60 seconds and give up after 30 minutes. Each waiting case costs 60 requests an hour, and Suspicious allows 3000 an hour per account, so one account supports about 50 cases waiting at the same time.
- **A failed analysis is not a clean one.** `analysis_health.failed` counts analyzers that failed; a non-zero value means the verdict has lower confidence. A case whose analysis failed outright returns `FAILURE` with DBot score 0.
- **Emails need a raw file.** Suspicious analyses the original `.eml` or `.msg` (headers, authentication results, attachments). An incident that only holds parsed fields cannot be submitted as an email; submit its URLs and attachments instead, or retrieve the original message first.
- **Reporter.** Cases belong to the account behind the API key, not to the employee who reported the email. Put the reporter in `context` so analysts see it on the case.
