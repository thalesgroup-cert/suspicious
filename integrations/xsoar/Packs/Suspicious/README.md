# Suspicious

Connects Cortex XSOAR to [Suspicious](https://github.com/thalesgroup-cert/suspicious), Thales CERT's phishing and threat-analysis platform. A playbook sends an artifact to Suspicious, waits for the verdict, and gets it back as context and as a DBot score on the indicators.

This guide wires the pack into **Cortex XSOAR 6.14 (on-prem)**, starting with the case most teams start with: **submitting a reported phishing email (`.eml`)**. Submitting URLs, IPs, domains and hashes, and enriching indicators, work the same way and are covered at the end.

## How it fits together

```
XSOAR (your network)  ──HTTPS, through your proxy──▶  Suspicious
   playbook task                                       analyses the email
   "suspicious-submit-file"  ◀── verdict + scores ──
```

The pack runs inside XSOAR and calls out to Suspicious. Nothing needs to reach into your network, and XSOAR needs no open port for it.

## Before you start

You need, from the Suspicious team:

| Item | Example |
|---|---|
| Suspicious URL | `https://suspicious.example.com` |
| API token for a dedicated service account | shown once, so keep it safe |
| This pack | `Suspicious.zip` |

You need on your side:

- XSOAR admin rights (Settings and Marketplace).
- XSOAR can reach the Suspicious URL over HTTPS, through your proxy. Ask the Suspicious team to confirm the URL is reachable from your proxy's network.
- The reported email as a file in the incident (`.eml` or `.msg`, 25 MB by default). The *Get Original Email - Generic v2* sub-playbook retrieves it from EWS, Microsoft Graph Mail and Gmail. For an email forwarded as an attachment, use the inner message.

> **For the Suspicious administrator (one time, in the Django admin).** Create the service account with an email-style username, for example `xsoar@yourcompany.example`. Open its profile and switch **off** both `wants_acknowledgement` and `wants_results`, so Suspicious does not send its reporter emails to this account. Then create the key under **Profiles → API Keys → Add** (30 days to 2 years; the token is shown once). Add the account to the CERT, CISO or Admin group only if you also want the reputation commands (`url`, `ip`, `domain`, `file`) or `suspicious-get-ticket`.

## Step 1: Upload the pack

1. In XSOAR open **Marketplace**, click **Upload pack**, and select `Suspicious.zip`.
2. If XSOAR refuses it because the pack is not signed, open **Settings → About → Troubleshooting → Server Configuration → Add Server Configuration**, add the key `content.pack.verify` with the value `false`, save, and upload again. Palo Alto documents this key for custom packs; if your 6.14 does not accept it, check the *Content Pack Installation* page of the 6.14 Administrator Guide.
3. Check the pack appears under **Installed**.

## Step 2: Let XSOAR use your proxy

Skip this step if XSOAR already reaches the internet through a proxy for its other integrations.

1. Open **Settings → About → Troubleshooting → Server Configuration → Add Server Configuration** and add, with your proxy's address:
   - `https_proxy` = `http://proxy.yourcompany.example:3128`
   - `http_proxy` = the same
   - `no_proxy` = hosts that must bypass it, comma-separated (optional)

   Special characters in proxy credentials must be escaped.
2. **If the proxy inspects TLS** (it re-signs HTTPS with its own CA), the integration will fail with `certificate verify failed` until XSOAR trusts that CA. Palo Alto's page *Configure Python Docker Integrations to Trust Custom Certificates* describes it: put the proxy's CA certificate, in PEM format, in a file named `python-ssl-certs.pem` in `/var/lib/demisto` on the XSOAR server (or in the directory named by the `docker.custom_certs.dir` server configuration), then follow that page to enable it. The instance option **Trust any certificate** also works, but do not use it in production.
3. The pack's integration runs in the Docker image `demisto/python3:3.12.14.13919218`. XSOAR pulls it the first time the integration runs, so the XSOAR host needs access to Docker Hub (Docker's own proxy setting is separate from the server configuration above) or the image must already be loaded. For an air-gapped install see *Install a Content Pack Offline* in the Administrator Guide.

## Step 3: Add the integration instance

1. Open **Settings → Integrations → Servers & Services**, search for **Suspicious**, and click **Add instance**.
2. Fill in:

   | Field | Value |
   |---|---|
   | Server URL | the Suspicious URL, no trailing path |
   | API token | the token from the Suspicious team |
   | Use system proxy settings | **tick** it, so the instance uses the proxy from Step 2 |
   | Trust any certificate | leave off |
   | Source Reliability | `B - Usually reliable` (default) |
   | Submit unknown indicators from reputation commands | leave off for now |

3. Click **Test**. `Success` means the URL, the proxy path and the token all work. Then **Save & exit**.

## Step 4: Try it by hand first

Do this before touching any playbook. Open any incident, go to its **War Room**, and upload a test `.eml` (use **Upload file**, not the Playground). Copy the file's entry ID shown on the upload. Then run:

```
!suspicious-submit-file entry_id=<entry ID of the .eml> polling=false
```

The output shows a `Case` number. Now wait for the verdict:

```
!suspicious-get-verdict case_id=<that case number> polling=true
```

The command keeps checking (every 60 seconds, for up to 30 minutes) and prints the verdict when it is final: `Result` (`SAFE`, `INCONCLUSIVE`, `SUSPICIOUS`, `DANGEROUS`), a score, the classification, and one scored indicator for each URL, IP, domain and hash found in the email. In the incident's context, `Suspicious.Verdict.dbot_score` holds the verdict as 0 (unknown), 1 (good), 2 (suspicious) or 3 (bad).

Run the same `suspicious-submit-file` command again with `polling=false`: the answer is the same case and `Reused earlier case` is `true`. That is how a re-run playbook avoids analysing the same email twice.

## Step 5: Wire it into the phishing playbook

Do not edit a shipped playbook: XSOAR overwrites those on update. Open **Playbooks**, **duplicate** *Phishing - Generic v3* (or your own phishing playbook), and work in the copy.

1. Find the point where the original email file is available. The task that gets it (*Get Original Email - Generic v2*) leaves the `.eml` in the incident's `File` context.
2. After it, add a task of type **Command** (Suspicious integration) running `suspicious-submit-file` with:

   | Argument | Value |
   |---|---|
   | `entry_id` | the entry ID of the `.eml` or `.msg`. Run the playbook once and look in the incident context under `File`: use the entry whose `Extension` is `eml` or `msg` |
   | `polling` | `true` |
   | `context` | for example `XSOAR incident ${incident.id}`. Add the reporter from whichever incident field your type uses, so analysts see it on the case |
   | `external_ref` | leave empty. The pack builds one from the incident and the file, which is what makes a re-run safe |

   In the task's advanced settings, let it continue on error, so a Suspicious outage does not stop the whole playbook.
3. Add a **Condition** task after it on `Suspicious.Verdict.dbot_score`:
   - `3` (dangerous) and `2` (suspicious): go to your remediation branch, for example block the indicators and search and delete.
   - `1` (safe) and `0` (inconclusive or failed): go to your analyst-review branch.
4. Set the copy as the playbook for your phishing incident type and run it on a test incident.

The task stays running while Suspicious analyses the email (how long depends on the analyzers that run; the pack gives up after 30 minutes), then the playbook moves on with the verdict and a scored indicator for every URL, IP, domain and hash in the mail.

## Step 6: Go-live checklist

- [ ] Test succeeds on the instance, with **Use system proxy settings** ticked.
- [ ] A manual `.eml` run (Step 4) returns a verdict.
- [ ] A re-run returns the same case (`Reused earlier case` is `true`).
- [ ] The playbook copy ran on a test incident and took the branch you expected.
- [ ] The service account's two notification options are off (no Suspicious emails arrive at its address).
- [ ] The API key's expiry is in your calendar: when it lapses every call fails with `401`.

## When something goes wrong

| What you see | Cause and fix |
|---|---|
| Test: `401` or "token is missing, expired or revoked" | Wrong, expired or revoked token. Ask the Suspicious team for a new one. |
| Test: connection error or timeout | XSOAR cannot reach Suspicious. Check the `https_proxy` server configuration, that **Use system proxy settings** is ticked, and that the Suspicious URL is reachable from the proxy. |
| `certificate verify failed` | The proxy re-signs HTTPS. Trust its CA (Step 2.2). |
| Integration does not start or is stuck "pulling" | The XSOAR host cannot pull the Docker image (Step 2.3). |
| `403` on `url`, `ip`, `domain`, `file` or `suspicious-get-ticket` | These need an investigator account (CERT, CISO or Admin group). The submit and verdict commands do not. |
| `404` on `suspicious-get-verdict` | The case belongs to another account. Use the token that submitted it. |
| `429` | The 3000 requests an hour per account limit. Each waiting case uses 60 an hour. |
| Result `ALLOW_LISTED`, no case number | The artifact is on a Suspicious allow list. Nothing to wait for. |
| Result `FAILURE`, or `Analyzers failed` above 0 | The analysis failed or was partial, so confidence is lower. DBot score is 0. Tell the Suspicious team the case number. |
| Polling stopped after 30 minutes | The analysis is still running or stuck. `!suspicious-get-verdict case_id=...` later, or contact the Suspicious team with the case number. |

## What else the pack can do

| Need | Command |
|---|---|
| A URL | `!suspicious-submit-url url=hxxps://evil[.]example/login polling=true` |
| An IP or a hash | `!suspicious-submit-other value=203.0.113.7 polling=true` |
| Several indicators as one case (100 at most) | `!suspicious-submit-indicators indicators=${URL.Data},${IP.Address} polling=true` |
| What Suspicious already knows (no case created) | `!url`, `!ip`, `!domain`, `!file` (investigator account). Enable **Submit unknown indicators** on the instance to submit values it has never seen. |
| Paste into a ticket | `!suspicious-get-ticket case_id=42` (investigator) and `!suspicious-get-report case_id=42 format=markdown` |
| Dispute a verdict | `!suspicious-challenge case_id=42 proposed_result=Safe reason="Internal pen-test"`. Only the account that submitted the case can challenge it. |

Defanged input (`hxxp`, `[.]`) is accepted. Pass `force_new=true` to analyse something again inside the same incident.

## Behaviour worth knowing

- **Resubmitting is safe.** Inside an incident each submission carries a reference built from the incident and the artifact. Running the same task again returns the earlier case. Pass your own `external_ref` to choose the key; start it with `xsoar:` if Suspicious's XSOAR connector is also enabled, so the case is not pushed back as a second incident.
- **Polling cost.** Each waiting case uses 60 requests an hour, so one account supports about 50 cases waiting at once.
- **Emails need a raw file.** Suspicious analyses the original `.eml` or `.msg` (headers, authentication results, attachments). An incident that holds only parsed fields cannot be submitted as an email; submit its URLs and attachments, or retrieve the original message first.
- **Cases belong to the service account**, not to the employee who reported the email. Put the reporter in `context`.
- **The other direction** (cases reported in Suspicious opening incidents in XSOAR) is a separate Suspicious feature. It needs Suspicious to reach your XSOAR, which is not part of this setup.
