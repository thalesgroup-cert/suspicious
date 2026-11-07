# AI / ML Analyzers

`Analyzers/AIMailAnalyzer/` is the machine-learning email classifier. It runs as a model server,
`ai_inference`, that the `ai_model` connector calls. It is no longer a Cortex analyzer.

## How it works

- **Embeddings:** a Sentence Transformers model
  (`paraphrase-multilingual-mpnet-base-v2`) turns email text into vectors.
- **Classifier:** an ensemble of custom `ResNetMLP` networks (several 2-class
  models plus a 4-class danger model) predicts the verdict from the embeddings.
- **Similarity:** the connector's campaign detection stores each mail's campaign embedding in the
  ChromaDB collection `suspicious_mails` and compares new dangerous mails against it.

## Architecture: the ai_model connector and the inference server

```
 suspicious_celery (Celery worker)               ai_inference container
 ┌─────────────────────────────────┐  POST /v2   ┌──────────────────────────────┐
 │ ai_model connector              │ ──────────► │ inference_server/server.py   │
 │  read mail text (store/archive) │ Bearer token│  vectorizer + models in RAM  │
 │  write AiAssessment + case      │ ◄────────── │  weights from models/        │
 └─────────────────────────────────┘             └──────────────────────────────┘
        http://ai_inference:8090  (service name on suspicious_net)
```

- **Network.** The server is reachable as `http://ai_inference:8090` on `suspicious_net` only.
  Neither `deployment/compose_apps.yaml` nor `deployment/docker-compose.override.yml` publishes a
  host port. To call it by hand, run the call inside a container on that network (examples below).
- **Variant.** One variant is loaded, `personal` (`models/`, your own trained weights), and `/v2`
  classifies with it.
- **Weights.** Bind-mounted read-only, not baked into the image. The server
  re-checks them every `INFERENCE_RELOAD_CHECK_SECONDS` (30) and hot-swaps changed
  files; `POST /reload` does it immediately. A file that fails to load never replaces a
  working model, so the retrain pipeline can overwrite `models/*.pth` in place.
- **Readiness.** `GET /health` (and `GET /v2/health/ready`, same body) is `200` only when the
  vectorizer and the four required `personal` models are loaded (the optional `unwanted_*` may be
  absent); otherwise `503` with the per-file load error.

### Without the connector

An instance that does not enable `ai_model` has no AI vote. A mail case with a mail archive gets
`results_ai = Inconclusive`, and scoring treats the AI vote as missing (`ai_missing`), as it did
when the old Cortex AI job failed. `score_case` (`score_process/scoring/engine.py`) then finalises
such a mail as:

- `Dangerous` when the number of malicious analyzer results is at least one third of the scored
  ones, rounded down, and at least one (`n_malicious >= max(1, n_scored // 3)`), or when one of its
  domains or URLs is deny-listed;
- `Failure` when no analyzer result scored at all;
- otherwise `Inconclusive`, rule `analysis-incomplete`, whatever the analyzers' scores. Two later
  steps can still change it: an allow-list majority (a strict majority of analyzer weight is Safe or
  allow-listed, and every dissent is about an allow-listed target) makes it `Safe`, and an embedded
  indicator with a worse band raises it to `Suspicious` or `Dangerous`.

So an instance that upgrades and does not enable `ai_model` finalises most mails that the analyzer
count does not make `Dangerous` as `Inconclusive` instead of `Safe` or `Suspicious`. The submitter's
notification mail, the TheHive challenge text and the dashboards show that verdict. Campaign
detection, and with it the TheHive campaign alert, also needs the connector.

**Upgrade step:** enable `ai_model` (and set its `url` and `token`) as part of the upgrade, see
[Enabling the connector](#enabling-the-connector).

Historical Cortex AI reports on existing cases still display (the AI analyzer card) and are still
kept out of the weighted blend, so their score is not counted twice.
`integrations.cortex.analyzers.ai` in `settings.json` (`AI_Mail_Analyzer_1_4` in the example
settings) names the `Analyzer` row of the AI vote; without the key the name is `AI_Mail_Analyzer`:

- the connector puts its ledger row (`CaseAnalyzerJob`) on that analyzer, and creates the row if it
  does not exist;
- scoring takes the AI vote's weight from that analyzer, and leaves that analyzer's reports out of
  the other votes and out of the per-file weighted blend.

Keep the key on an upgraded instance: its row holds the AI weight set in Settings, and the
historical Cortex AI reports carry its name. The Cortex analyzer sync does not report that role as
missing from Cortex and leaves its row active.

### Deploying

```bash
# 1. put the trained weights where the container mounts them
ls Analyzers/AIMailAnalyzer/models/*_30_epochs_model.pth     # 5 files
# 2. build + start (the Makefile enables the `ai` compose profile)
cd deployment && make build && make up
# 3. check the server from inside its container (curl is in the image)
docker compose --env-file .env --profile ai exec ai_inference \
  curl -s http://127.0.0.1:8090/health
docker compose --env-file .env --profile ai exec ai_inference \
  sh -c 'curl -s -H "Authorization: Bearer $AI_INFERENCE_TOKEN" http://127.0.0.1:8090/v2/models/ai_mail'
# 4. check that the worker reaches it over suspicious_net
docker compose --env-file .env exec suspicious_celery python -c \
  "import urllib.request; print(urllib.request.urlopen('http://ai_inference:8090/v2/health/ready').read())"
```

Plain compose users add the profile: `docker compose --profile ai up -d`. Then enable the connector
(see [Enabling the connector](#enabling-the-connector)).

### Troubleshooting "inference does not work"

The connector's errors are in the delivery `error` of its rows
(`GET /api/connectors/ai_model/deliveries/`); campaign detection errors are in the worker log
(`suspicious_celery`).

| Symptom | Cause / fix |
|---|---|
| Delivery `error` `inference server unreachable: ...` | The worker cannot reach the server. Check that `ai_inference` is up on `suspicious_net` (it runs under the `ai` profile), that the connector `url` is `http://ai_inference:8090`, and run step 4 above. |
| Delivery `error` `inference server HTTP 503: vectorizer unavailable` | The inference image was built without the vectorizer weights (the build fetches them from Hugging Face; check the build log / proxy). The row fails at once, without retry. `/health` shows the exact error. |
| Delivery `error` `inference server HTTP 503` (no phrase after the status) | The server is still loading its vectorizer, or answered another 5xx. The call is retried; the row fails with this error only when the retries run out. Check `/health` and the `ai_inference` log. |
| Delivery `error` `inference server HTTP 503: models unavailable` | `Analyzers/AIMailAnalyzer/models/` is empty or has a corrupt/truncated `.pth`; `/health` lists which file and why. |
| Delivery `error` `inference server HTTP 503: token not configured` | `AI_INFERENCE_TOKEN` is not set on the server. Set it in `deployment/.env` and recreate `ai_inference`. |
| Delivery `error` `inference server rejected the token (HTTP 401)`, or `token rejected (HTTP 401)` in the `ai_model` health detail | Wrong token: the connector's `token` differs from the server's `AI_INFERENCE_TOKEN`. The connector's own empty `token` fails before any call, as `ValueError: token not configured`. |
| Verdicts never change after retraining | Weights were baked into an old image instead of mounted, or the mount is not `models/`. Check `/health`, then `POST /reload`. |
| Worker log warning `The chromadb connector is set to collection 'suspicious', but campaign detection stores mails in 'suspicious_mails' ...`, also in the `ai_model` health detail | The `chromadb` cleanup connector watches another collection, so old campaign documents are never removed. Set `integrations.chromadb.collection_name` to `suspicious_mails` in `settings.json` (see [Campaign detection](#campaign-detection)). |
| Worker log `Campaign detection for case <id> failed (<error class>), retrying.`, then `Campaign detection for case <id> failed: <error class>` | ChromaDB is down or the `campaign:detect` lock stayed busy. The task retries 3 times (30, 60, 120 s) and then gives up; the case keeps its verdict but joins no campaign. A case already in a campaign is announced on each try even while ChromaDB is down (worker log `Case <id>: campaign store down ...`). Check `chromadb`. |

## v2 API and the ai_model connector

The inference server's classify API is the token-protected `/v2`, next to the `/health` and
`/reload` routes. The `ai_model` connector uses it, so the AI verdict comes from the platform, with
no Cortex job.

| Route | Token | What it does |
|---|---|---|
| `GET /v2/health/live` | no | `{"live": true}` while the process is up. |
| `GET /v2/health/ready` | no | The same body as `/health`: `200` when the vectorizer and the `personal` models are loaded, otherwise `503`. |
| `GET /v2/models/ai_mail` | yes | Model metadata: the versions the server holds, with their `preprocessing` and `manifest_sha256`. Without a loaded bundle, `active` is `v0`, the legacy classifier. |
| `POST /v2/embed` | yes | Body `{"texts": [...], "profile": "classifier"}` or `"campaign"`, at most 32 texts, optional `"preprocessing"` (`legacy-first128` by default, `chunkmean-tokens-v1`, `chunkmean-words90-v1`; the `campaign` profile always uses the first 128 tokens). Returns `{"vectors": [...], "preprocessing_version": <the form actually used>, "embedding_version": "cmp-e1"}`. With the default form both profiles give the same vectors. `503` while the vectorizer is not loaded. The label sync uses it. |
| `POST /v2/models/ai_mail/classify` | yes | Body `{"mail_body": "...", "versions": ["active"]}`, optional `exclude_case_ids` (at most 1000, used by bundles only: those cases are left out of the neighbour vote; the `ai_model` connector always sends the classified case's own id). Returns the verdict under `results.active` (class, score, confidence, class and sub-class probabilities, contributing phrases, `tier`) plus the campaign embedding, its version and the latency. `tier` is `null` for version 0 and `legacy-first128` bundles. `400` for any other `versions`, `503` when models or vectorizer are not loaded. |
| `POST /v2/train`, `GET /v2/train/{job_id}`, `POST /v2/train/{job_id}/cancel` | yes | One training job at a time; see [Retraining](#retraining). |
| `POST /v2/reload` | yes | Body `{"active": {...} \| null, "shadow": {...} \| null}`. Loads a bundle; `active: null` goes back to the legacy weights. See [Model registry](#model-registry). |

### The token

The server reads `AI_INFERENCE_TOKEN` from its environment (`deployment/.env`, passed to the
`ai_inference` service by compose). The `/v2` routes that need a token fail closed: with the
variable unset or empty they answer `503 token not configured`, they never run unauthenticated. A
missing or wrong `Authorization: Bearer ...` header answers `401`. Generate one with
`openssl rand -hex 24`.

### Enabling the connector

1. Set `AI_INFERENCE_TOKEN` in `deployment/.env` and recreate `ai_inference`.
2. Put the same value in the connector's `token` (Settings, or `integrations.ai_model.token` in
   `settings.json`). `url` defaults to `http://ai_inference:8090` and `timeout_seconds` to 20.
3. Enable `ai_model` in Settings, or `PATCH /api/connectors/ai_model/` with `{"enabled": true}`. It
   is off by default.
4. Set `integrations.chromadb.collection_name` to `suspicious_mails` (see
   [Campaign detection](#campaign-detection)).

Only one connector may provide `mail_ai` at a time. Enabling a second answers `409`
(`<name> already provides mail_ai`); disable the first one before enabling the other.

With the connector enabled, the AI analyzer gets a ledger row (`CaseAnalyzerJob`) with a `provider-`
id instead of a Cortex job id. The Celery worker (`suspicious_celery`) reads the mail text from the
object store first: the mail's `.txt` and `.headers` objects, under `<mail_id>/` in the submission's
own bucket, or under `<submission_id>/<mail_id>/` in the feeder bucket (`storage.s3.feeder_bucket`)
when the submission came through the prefix layout. It starts there because the e-mail fetch task
deletes the working directory that holds the submission's archive shortly after the handoff, so a
retry would no longer find it. The archive on the shared volume (`mail_case_data` and
`mail_work_data`, mounted in both `suspicious` and `suspicious_celery`) is the fallback, used when
the store has no text for the mail. The worker then posts the body to `/v2/models/ai_mail/classify`
over `suspicious_net`, stores the answer as one `AiAssessment` per case (with the model version,
`v0` today), fills the case's AI result, score, confidence and category, closes the row and queues
the case's reconcile.

### Case view

With the connector enabled, the submission drawer and the investigation overview show an "AI model
assessment" section for a case that has an `AiAssessment`. It shows the class and sub-class, a
confidence tier chip with its meaning (High, Medium, Low), the runner-up class on tier Low, the
model version and how long ago it ran, the campaign reference and size when the case is in a
campaign, and the cross-check facts. The model reads the mail body text only, not the headers or
attachments. The facts are the decisive rule of the verdict, the counted sources with their
verdicts, and the allow or deny list hit; a warning reads "AI disagrees with the evidence" when the
AI class and the case verdict sit on opposite sides of Safe and Dangerous (the stored explanation
band, or the case's current result when there is no explanation, so an analyst override counts).
When the AI itself set the verdict (rule `ai-classifier-decisive`) the facts say "No independent
evidence beyond the AI" and the warning never shows. The cross-check is analyst material: a
reporter viewing their own submission gets no cross-check block (`cross_check` is `null`). No
numeric confidence is shown. Similar cases are listed only when the viewer may open them; the list
is empty today, because the version 0 server returns no similar cases.

The API field `ai_assessment` is `null`, and the older "AI classifier" caption stays, when the
connector is disabled or not registered, when the case has no assessment row or its model version is blank (for example a case analysed by the old
Cortex job), and when the serializer has no request. Version 0 has no tier, so the section says
"Confidence not calibrated". For an analyst the campaign line also gives the folder labels of the
other cases in the campaign, for example "Labelled by analysts: 3 Dangerous, 1 Safe" (a count of
cases per class, Dangerous, Unwanted, Safe in that order, from the active folder rows of the
[label ledger](#label-ledger); flagged and superseded rows do not count). A warning reads
"Campaign members disagree" when those labels hold both Dangerous and Safe, or when this case's AI
class is Dangerous and a sibling is labelled Safe, or the reverse; Unwanted never counts. A reporter
gets the reference and size only (`campaign` has no `labels` or `members_disagree` key). The AI analyzer card
still reads Cortex AI reports, so it stays empty for new cases.

### Campaign detection

Campaign detection runs from the connector. Its `case_finalised` hook only queues a Celery task,
`connectors.tasks.run_campaign_detection`, which reads the mail's text and headers the same way
(object store first, then the archive) and adds the mail to the ChromaDB collection
`suspicious_mails` that later detection compares new mails against. When the case's AI result is
`DANGEROUS` and at least three similar mails are found, it creates or joins a campaign (a
`DANGEROUS` mail from an allow-listed sender domain is skipped and not stored). A created or joined
campaign sends `campaign_updated`, so TheHive raises its campaign alert. Mails of one campaign are
placed one at a time under the `campaign:detect` lock.

The task does not run under the connector's circuit breaker, so a ChromaDB outage does not stop
classification. Any failure is retried up to 3 times, after 30, 60 and 120 s (`30 * 2**retries`),
and then logged at ERROR with the case id and the error class. An object store that answers
`access_denied` or `invalid` is not retried: that failure is logged at once. A case deleted before
the task runs is skipped with an INFO line, and headers that cannot be parsed are dropped (a WARNING
with the case id and the error class) and the mail is detected without them. These failures are in
the worker log (`suspicious_celery`), not in the connector's deliveries.

**Collection cleanup.** The `chromadb` connector deletes items older than 15 days by default (its
`threshold_days` config), once a day, from the collection named by its `collection_name` config,
default `suspicious`. Detection writes to `suspicious_mails`, so with the default the campaign
documents are never cleaned up. The key has no field in Settings: set it in `settings.json`:

```json
"integrations": { "chromadb": { "collection_name": "suspicious_mails" } }
```

The cleanup and the `ai_model` mismatch check both read `collection_name` from the `chromadb`
connector's configuration, and a configuration saved for that connector in the database wins over
`settings.json`.

While the `chromadb` connector is enabled and watches another collection, the `ai_model` health
check adds a sentence saying so, and the detection task logs the same sentence as a warning, once
per worker process.

### Replaying a Cortex-built campaign: `ai_model_campaign_replay`

```bash
docker compose --env-file .env exec suspicious python manage.py ai_model_campaign_replay <campaign_ref>
```

Campaigns built before the cutover came from the Cortex AI path. The command replays one of them
through the connector's detection and compares the members, so you can check that the connector
would have built the same campaign. Run it on a few campaigns before you rely on the connector for
your campaign history.

- **Input.** It rebuilds each mail from its Cortex AI report (the newest successful one), so the
  members' Cortex AI reports must still exist. It works on historical campaigns only: a campaign the
  connector built has no Cortex AI reports to replay. It stops with an error when fewer than 3
  members have a usable report.
- **What it replays,** in case id order: the stored members, plus every case between the lowest and
  highest stored member id that has a successful `DANGEROUS` Cortex AI report and is in no campaign.
  A mail the connector would add then shows up as an extra case id.
- **What it does not cover:** similar mails outside that id range, mails that belong to other
  campaigns, and campaign-less mails whose Cortex AI report was purged.
- **What it checks: membership only.** It compares the members of the campaign the last stored
  member ends in with the stored members. A missing or extra case id fails the command; otherwise it
  prints `MATCH`. The `campaign_updated` payload also depends on the case that triggered detection,
  and id order only approximates the original finalisation order. An allow-list changed since the
  campaign formed can show up as an extra or missing case.
- **What it changes: nothing.** It runs in a transaction that it rolls back, compares the mails in
  an in-process Chroma that is deleted at the end (the Chroma server is never contacted), and sends
  no event. It takes the live `campaign:detect` lock briefly for each replayed `DANGEROUS` case, as
  live detection does. It deletes the campaign's member rows inside the transaction, so it holds
  their row locks for the whole replay: run it off-peak on a very large campaign. A replay on the
  newest campaign can make live detection retry briefly while those locks are held: run it off-peak
  or expect retries.

### Label ledger

The label ledger (`ai_model.models.LabelRecord`) collects labelled mails for retraining (Plan E).
It is append-only: a row is never changed except its `status`, `flag_reason` and the resolution
fields (`resolved_by`, `resolved_at`, `resolution_note`).

**What a row holds.** The normalised Message-ID (whitespace and angle brackets stripped,
lower-cased; an id without `@`, with whitespace inside it, or above 998 characters counts as
none) and its SHA-256, the matched
case (null when no case matched), the source and a source reference, the label and its class, the
trust level, when it was observed, the status and the flag reason. A folder row also holds the
classifier and campaign embeddings with their `preprocessing_version` and `embedding_version`, and
a small snapshot: the sender domain, the subject length, the case's allow and deny list hits and its
AI result and model version at that moment. The ledger never stores the mail text, the subject or
the sender address.

| Source | Written by | Trust | Label |
|---|---|---|---|
| `imap_folder` | the label sync and the backfill command | `folder` | the known folder name; class Safe, Unwanted or Dangerous |
| `analyst_verdict` | an analyst verdict on an investigation, while `ai_model` is enabled | `verdict` | the verdict (Safe, Dangerous, Suspicious or Inconclusive) |
| `challenge` | a reporter's challenge with a proposed verdict, while `ai_model` is enabled | `proposal` | the proposal (Safe or Dangerous) |

Only a `folder` row with status `active` is trainable. A verdict row with the same class as the
case's active one adds nothing; a different class supersedes it. A new challenge proposal supersedes
the case's earlier one. A failed ledger write is logged with the case id and the exception class,
and never fails the verdict or the challenge.

**Folders and their classes.** The class comes from the digit prefix of the folder name, from the
training notebook (`Analyzers/AIMailAnalyzer/train_models.ipynb`):

| Folder | Class |
|---|---|
| `0_LEGIT_INTERNAL_COMMUNICATION`, `0_LEGIT_EXTERNAL_COMMUNICATION` | Safe |
| `1_SPAM`, `1_NEWSLETTER` | Unwanted |
| `2_CLASSIC_PHISHING`, `2_CLONE_PHISHING`, `2_BLACKMAILING_PHISHING`, `2_WHALING_PHISHING` | Dangerous |

The name is taken from the last segment of the mailbox path, split on `.` and `/`, so
`INBOX.2_CLASSIC_PHISHING` and `Review/0_LEGIT_EXTERNAL_COMMUNICATION` work: the row's label is the
known name, and the configured path is what the IMAP `SELECT` gets (and what `source_ref` keeps). A
folder outside the list is never read. A configured name whose last segment is not one of these
eight is skipped with a warning in the worker log. When none of the configured names is known, the
sync fails before connecting with `LabelSyncIncomplete` (not retried), giving the count and the
names in `ascii()` form, so a typo does not show as a successful sync.

**Configuration.** The sync uses these fields of the `ai_model` connector (Settings, or
`integrations.ai_model` in `settings.json`):

| Field | Default | Meaning |
|---|---|---|
| `imap_host` | empty | IMAP server of the review mailbox. Empty: the sync does nothing. |
| `imap_port` | `993` | |
| `imap_user` | empty | |
| `imap_password` | empty | A secret field (Vault), never logged. |
| `imap_use_ssl` | `true` | IMAPS with the certificate verified against the system CA store of the Celery worker container. `false` is plain IMAP with no STARTTLS, so the password travels in clear: for dev or greenmail only. |
| `imap_folders` | the eight folders above | Comma-separated folder names. |

A mailbox behind an internal CA: `ssl.create_default_context()` reads the container's system CA
store (or the file named by `SSL_CERT_FILE`). The `rootcafile.pem` that compose mounts at
`/etc/private/` is not read by it. Without the CA the run fails with `ImapTlsFailed` (the exception
class name only, not retried).

**The label sync.** The connector declares a `label-sync` schedule of 86400 s, which Celery beat
runs as `connectors.tasks.run_connector_sync` while the connector is enabled, so about every 24
hours. The interval is counted from when beat started: recreating the `suspicious_celery_beat`
container starts the countdown again. There is no run-now button or API route for a connector
sync. To run one at once, use the backfill command with `--folders`, or queue the task:
`docker compose --env-file .env exec suspicious python manage.py shell -c "from connectors.tasks
import run_connector_sync; run_connector_sync.delay('ai_model')"`. The outcome is a delivery with
event `sync` in `GET /api/connectors/ai_model/deliveries/`. The mailbox is opened
read-only: each folder is selected with `readonly=True` and mails are fetched with `BODY.PEEK[]`,
so nothing is marked read, moved, flagged or deleted. Sizes are asked first with `RFC822.SIZE`, and
a mail above 25 MB is skipped without being downloaded. The labelled mail is the first
`message/rfc822` attachment of the review mail; a review mail without one, or one that cannot be
parsed, is skipped and counted (`LabelSyncState.skipped`).

Each run examines at most 500 UIDs per folder (skipped and already recorded ones included), in
chunks of 25 mails. A chunk is embedded through `/v2/embed` (both profiles, 32 texts per call),
then its rows and the folder checkpoint (`LabelSyncState.last_uid`) commit in one transaction, so
the next run resumes after the last committed chunk. The run stops between chunks, or between embed
calls (that chunk is then not committed), once 300 s have passed; Celery's soft limit is 540 s,
and a chunk of 25 keeps the fetch, match and embed of one chunk far below it. A large mailbox
therefore takes several runs, unless the backfill command reads it. When the folder's
`UIDVALIDITY` changes, the folder is read again from the start; mails already recorded add no row.
A mail seen again in the same folder adds no row.

Each mail is matched to a case by its Message-ID. Without one, the match is on the sender address,
the UTC day of the Date header and the subject; exactly one case must match. When neither matches,
the Message-IDs of mails forwarded inside it are tried. When several cases carry the same
Message-ID (a re-submission, or the same mail reported twice), the newest case wins. An unmatched
row is still recorded, with no case; the sync does not match it again later, the backfill command
does (see below).

Failures: a folder that cannot be selected or searched is skipped with a warning. An embed the
server refuses for a chunk (a 4xx, an answer that does not fit the batch, versions changing within
the chunk) skips that folder without moving its checkpoint; once the other folders ran, the sync
raises `LabelSyncIncomplete` and the delivery is recorded failed, without a retry. A failed login
(`ImapLoginFailed`) or TLS handshake (`ImapTlsFailed`) fails the run without a retry. An embed that
fails on setup also fails the run without a retry: a rejected token (401, 403), a wrong url (404),
a proxy, timeout or rate-limit answer (407, 408, 429), and a 503 saying the token, models or
vectorizer are missing. A lost IMAP connection, an unreachable embed endpoint, another 5xx and the
503 of a vectorizer still loading fail the run, and the delivery is retried (up to 3 attempts).

**Precedence and flags.** The folder row is the label of record; verdict and proposal rows are
provenance. A hard conflict is a Dangerous folder label against a Safe analyst verdict, or a Safe
folder label against a Dangerous one; Unwanted, Suspicious and Inconclusive never conflict, and a
proposal never flags. Whichever arrives first, the folder row gets status `flagged`
(`flag_reason = folder_verdict_mismatch`) and is not trainable until the flag is resolved.
`ai_model.ledger.resolve_flag(record, user, note, keep=...)` resolves it (keep makes the row active
again, otherwise it is superseded); it has no API or screen yet, that comes with the Settings card
(Plan G). `ai_model.ledger.ledger_summary()` gives the counts per source and class, the flagged count
and the trainable count, over the rows not superseded.

**Backfill: `ai_model_backfill_labels`.**

```bash
docker compose --env-file .env exec suspicious python manage.py ai_model_backfill_labels [--folders] [--dry-run]
```

It needs the `ai_model` connector enabled. It does three things, then a fourth with `--folders`:

- A verdict row for every case an analyst last updated (`last_update_by` set) whose result is a
  label class and that has no verdict row yet (in any status), dated at the case's `last_update`.
  History from before the ledger cannot tell an analyst's edit from a later re-score: "Redo
  analysis" keeps `last_update_by`. So the backfill records the case's current class under its last
  editor, and it never touches a case that already has a verdict row, so a redone case cannot
  supersede a verdict recorded live.
- A proposal row for every challenged case with a Safe or Dangerous proposal.
- A late case match for folder rows that matched no case: each such row with a Message-ID is
  matched again, and its case is set when one is found (only from no case to a case). In the same
  transaction the row gets the conflict check of the live path: a Dangerous row matched to a case
  whose active verdict is Safe, or the reverse, is flagged and stops being trainable.
- `--folders` also runs the sync over every configured folder with no 500-UID cap and no time
  budget, and needs `imap_host`.

`--dry-run` writes nothing and prints the counts it would create or re-match; it does not read the
folders. It prints counts only. A rerun adds nothing for what is already recorded.

**Limits.**

- A mail the server refuses to fetch (a `NO` or `BAD` for that one UID) is skipped, and the
  checkpoint moves past it: it is not retried.
- Plain mode (`imap_use_ssl` false) is for dev or greenmail only.
- A verdict or proposal row for a case whose mail has no Message-ID is keyed per case. It meets
  folder rows only through the matched case.
- A folder row of a mail without a Message-ID that matched no case is never checked against a
  verdict.
- When the same Message-ID is on two cases, the cases are not checked against each other: a verdict
  is compared with its own case's folder rows and with the folder rows that matched no case.
- A flag survives a later verdict change until it is resolved.
- A mail moved to another folder adds a row for the new folder and supersedes its earlier rows,
  active or flagged; the new row is checked for conflicts again.
- A mail copied into two folders takes the label of the folder read last. A `UIDVALIDITY` reset of
  the other folder reads it there again, and the label flips.

### When classification fails

- **Where to look.** When the task fails a row, the reason is recorded in the row's
  `ConnectorDelivery` entry (event `analyze`, status `failed`, field `error`), listed by
  `GET /api/connectors/ai_model/deliveries/`.
- **Server unreachable, timeout or 5xx.** The task retries twice, after a wait of 5 s plus up to 3 s
  of jitter and then 10 s plus up to 3 s. `timeout_seconds` (20 s) is the socket timeout of the HTTP
  call: it applies to each connect and each read, not to the whole call. A server that accepts the
  connection and then hangs closes the row as `Failure` after roughly 75 to 81 seconds (three
  attempts of 20 s plus the two waits). A server that sends bytes slowly can take longer, because
  the read timeout starts again after each chunk. A stopped or refusing server fails each attempt at
  once, so the row closes after the two waits alone, about 15 to 21 seconds (6.0 s and 11.3 s in a
  live drill). The case gets `results_ai = Inconclusive` and still finalises.
- **Repeated failures** open the connector's circuit breaker. `GET /api/connectors/` does not report
  it: the breaker lives in the Celery worker process. Its effect shows on the rows. While it is
  open, new rows fail at once without calling the server, and their delivery `error` starts with
  `CircuitBreakerError:` followed by the breaker's own message.
- **A rejected token (`401` or `403`)**, a wrong url (`404`), a proxy, timeout or rate-limit answer
  (`407`, `408`, `429`), and a `503` that says the token or models are missing or the vectorizer
  failed to load, fail the row at once, without retries. They are setup errors that every case would
  hit, so they show as a `Failure` row and count against the breaker. They are never turned into a
  quiet `Inconclusive` success. The `503` that says the vectorizer is still loading (the server
  restarting) is retried like any other `5xx`; a restart that outlasts the two waits still ends as a
  `Failure` row.
- **A refusal of one mail (`400`, `413`, `422`)** gives no model version, so the row closes as
  `Failure` without retries and without counting against the breaker. No `AiAssessment` is stored,
  and the delivery `error` starts with `no model_version`. A mail with no readable text, in the
  store or in the archive, ends the same way. The case gets `results_ai = Inconclusive`, unless an
  earlier row of the same case succeeded: then the case keeps that row's assessment and AI fields.
- **Object store down.** If the store errors (not "not found") and the archive cannot stand in, the
  row closes as `Failure`. An `access_denied` or `invalid` error fails it at once, without retries;
  `unavailable` and any other error are first retried twice like a server outage. The delivery
  `error` reads `object store unavailable: <label>`, where the label is the store's error code (for
  example `unavailable` or `access_denied`) or, for any other error such as a configuration problem,
  the exception class name. It is not turned into an `Inconclusive` success.

## Retraining

`python manage.py ai_model_retrain` trains a new model version from the
[label ledger](#label-ledger) on the `ai_inference` server and registers it as a `candidate`. It never
changes the active model: shadow runs and promotion come in a later release (Plan F).

### What is trained

- **Input.** The active `imap_folder` rows of the ledger (at most 8000), each with its classifier
  embedding in `chunkmean-tokens-v1` (the mean of up to 8 encoder passes over token-sized chunks of
  the body) and its first-128-token campaign embedding (`cmp-e1`). Trainable rows still embedded in
  another form are left out and counted (`left out N` in `ai_model_retrain`, `excluded_rows` in the
  candidate's manifest summary); run `python manage.py ai_model_reembed_ledger` to bring them in. A
  row whose mail can no longer be fetched stays out until it is fixed. The export refuses when no
  row is left or a head class falls under 8 rows.
- **Recipe.** The five `ResNetMLP` heads of version 0 (`safe_suspicious`, `spam_dangerous`, `safe`,
  `unwanted`, `dangerous`), trained with class weights and no oversampling (30 epochs), plus a 5-NN
  vote over the training embeddings. Each of the two components is smoothed and calibrated by its
  own temperature; the main probabilities are their mean.
- **Groups.** Near-duplicates (cosine 0.95 or more on the campaign embedding) and campaign members
  never straddle a train/test fold or a calibration half. Campaign members are rows within the
  campaign distance of each other, plus the rows of cases linked to the same campaign
  (`CampaignMember`), which the export sends as a `ties` array however far apart they embed.

### The gate

Three repeats (seeds 0, 1, 2) of 5 grouped folds give held-out predictions for the candidate and for
the baseline, which is the active version's recipe retrained on the same folds (version 0's recipe
with SMOTE and random oversampling when `v0` is active). The six checks:

| # | Check | Passes when |
|---|---|---|
| 1 | `dangerous_called_safe` | the share of Dangerous mails called Safe is at most the baseline's plus 0.01 |
| 2 | `macro_f1` | macro-F1 is at least the baseline's minus 0.02 |
| 3 | `calibration_error` | the binned calibration error (15 bins) is below 0.12 |
| 4 | `head_samples` | every head has at least 8 mails in every class; when it fails, the job fails and nothing is trained |
| 5 | `high_tier_precision` | the High tier is at least 0.90 precise, measured cross-half: the cutoff is chosen on one calibration half and scored on the other; it also fails below 5% of rows or when no cutoff reaches 0.95 |
| 6 | `campaign_dangerous_called_safe` | on folds split on campaign groups, check 1 holds |

The version's manifest records `eligible` (all six passed) and every check's value, threshold and
detail. A candidate that failed a check is still registered, with `eligible: false`.

The stored tier cutoffs: Medium at 0.60, High at `max(0.85, t)`, where `t` is the smallest
probability whose held-out rows at or above it are 0.95 precise. When no probability reaches 0.95,
High is 1.01 (unreachable).

### Tiers and scores of a retrained version

For a retrained version (`chunkmean-tokens-v1` or `chunkmean-words90-v1`), classify returns the
calibrated probabilities. The class is the most probable one when its probability is at least 0.5,
else `INCONCLUSIVE`. `score` and `confidence` use version 0's mapping (Safe 0 to 5, Unwanted 5 to
6.5, Dangerous 6.5 to 10, linear in the probability). `tier` is `high` at or above the High cutoff,
`medium` at or above the Medium cutoff, else `low`, from the top probability. `contributing_phrases`
is empty: the server does not compute them for these versions. Version 0, and a bundle in
`legacy-first128`, answer as before with `tier` `null`, shown as "Confidence not calibrated". Fitting
a temperature for version 0 is not done yet.

Calibrated confidences are lower than version 0's. `tools/confidence_shift.py --dataset <npz>`
prints the `confidence_ai` distribution of both on held-out predictions. On the 505-mail dataset
(3 seeds pooled, 1515 rows):

| | p10 | p25 | median | p75 | p90 | Inconclusive |
|---|---|---|---|---|---|---|
| version 0's recipe, retrained per fold, uncalibrated | 90 | 99 | 100 | 100 | 100 | 1 (0.1%) |
| retrain recipe, calibrated | 58 | 75 | 87 | 90 | 92 | 69 (4.6%) |

The first row comes from retraining version 0's recipe and scoring the held-out folds, not from
the shipped version 0 weights, which have seen these 505 mails; live version 0 confidences differ.

The scoring engine compares `confidence_ai` with the base confidence and applies `CONF_FLOOR`, so a
promoted version can change which signal decides a verdict. Replay recent cases before promoting.

### Running it

```bash
docker compose --env-file .env exec suspicious python manage.py ai_model_retrain --wait
docker compose --env-file .env exec suspicious python manage.py ai_model_retrain --status
docker compose --env-file .env exec suspicious python manage.py ai_model_retrain --cancel
```

| Option | Effect |
|---|---|
| (none) | Export the ledger, start a job and return. A Celery task polls the job at least 30 s apart. |
| `--wait [--timeout S]` | Start, then poll until the job ends or `S` seconds pass (default 6 h); the job keeps running after a timeout. |
| `--status` | Counts and the latest jobs, with each failed job's reason (filtered). |
| `--cancel` | Cancel the running job. |

The connector must be enabled. A job still running after 6 hours is cancelled and failed. A failed
or cancelled job registers nothing and its uploaded files are deleted.

**Schedule.** Connector fields `retrain_enabled` (default false) and `retrain_interval_days`
(default 30). The daily beat entry `ai-model-retrain-check` starts a retrain when both allow it and
the newest version is older than the interval. A failed or refused scheduled retrain pauses the
check for 7 days.

### Storage and the hosts allow-list

Django exports the dataset to the `ai-datasets` bucket and gives the server presigned URLs: a GET
for the dataset (15 minutes) and one PUT per bundle file under
`ai-models/<version_id>/<job_id>/` (4 h 15 min, because the upload happens when training ends). The
server holds no storage credentials. It fetches and uploads only to hosts listed in
`AI_BUNDLE_HOSTS` (comma-separated `host:port`, compared as strings; compose sets `rustfs:9000`;
empty refuses every URL), over http or https, without following redirects, with a 200 MB download
cap. URLs are never logged: the server keeps `httpx` and `httpcore` at WARNING and redacts query
strings.

### Bundle layout

| File | Content |
|---|---|
| `heads/<head>.npz` | five heads, one float32 array per state-dict key (no pickle, never read with `torch.load`) |
| `calibration.json` | `temperature` (`{"hierarchy", "knn"}`, each between 0.2 and 30), `tier_cutoffs` (`high`, `medium`), `held_out_groups` |
| `knn_index.npz` | `embeddings`, `label_ids`, `case_ids` of the training rows |
| `campaign_profile.json` | the campaign settings the version was trained with |
| `manifest.json` | version id, recipe, preprocessing version, encoder id and hash, ledger and campaign digests, gate report, parent version, trainer revision, SHA-256 of every other file |

The SHA-256 of `manifest.json` is stored in the registry (`ModelVersion.manifest_sha256`) and checked
before the manifest is parsed. A bundle is refused on any hash mismatch, a missing or extra file, a
name that is not a plain file name, a file above 50 MB or a total above 100 MB, an unknown
preprocessing version, an `input_dim` other than the encoder's 768, or a manifest naming another
encoder (the server hashes its own encoder files).

**The encoder is pinned.** `inference_server/Dockerfile` downloads the encoder weights from one
Hugging Face commit, `ARG ENCODER_REVISION=4328cf26390c98c5e3c738b4460a05b95f4911f5` (the files
the images built since November 2026 hold; `model.safetensors` SHA-256 `b5722100…`). The encoder
hash covers every file in the vectorizer directory, so a different pin changes it and every
registered bundle is then refused at reload until it is retrained. To move the pin: build with
`--build-arg ENCODER_REVISION=<sha>` (or change the default), retrain, and expect the old bundles
to stop loading; version 0 (`active: null`) is not affected.

### Limits

- **Resources.** The job runs in a separate process (`inference_server.training_worker`) with
  `AI_TRAIN_THREADS` torch threads (default 2), so classify keeps answering. It is stopped after
  `AI_TRAIN_MAX_SECONDS` (default 4 hours). The `ai_inference` memory limit is
  `AI_INFERENCE_MEM_LIMIT` (default 8g); memory during training has not been measured: record
  `docker stats ai_inference` during the first run.
- **Same UID.** The worker runs as the same user as the server. It receives no token and no storage
  key and only reads validated params and the dataset through a pickle-free reader, but it is not a
  boundary against code running inside it.
- **Latency.** A retrained version embeds up to 8 chunks plus the campaign pass per mail: 844 ms
  median and 1187 ms maximum on 10 bodies of 40 to 1500 words, against 3094 ms median for version
  0's classify with its contributing-phrases pass (measured on a 28-CPU dev host).
- **Text form (Ruling E3).** Live classify reads the parsed `.txt` body; the ledger embeds the plain
  part or reduced HTML of the message. `python manage.py ai_model_text_gap` measures the gap on
  cases that have both. It has not been run against a review mailbox yet, so the decision is
  pending.

### Operational remarks

- Check 4 needs 8 mails per head class. The 505-mail dataset has 10 in `1_NEWSLETTER`, so a ledger
  short of newsletters fails every candidate at check 4.
- Check 5 is measured cross-half, while the stored High cutoff is chosen on all held-out
  predictions. The stored High tier can therefore be empty (cutoff 1.01) or below 0.95 precision
  while check 5 passes.
- The 505 mails form 145 independent groups (near-duplicate and campaign groups merged).
  `tools/learning_curve.py` found the gate metrics flat within noise between 109 and 145 groups,
  and the 8-per-class floor not met below about 60% of the groups. Nothing above 145 groups was
  measured. Mails from new campaigns and rare classes help more than more mails of known campaigns.

## Model registry

`ai_model.models.ModelVersion` lists the model versions; `ModelEvent` records every status change
with the user and a note. Both are read-only in the Django admin. Status changes go through
`ai_model/registry.py` only.

| Status | Meaning |
|---|---|
| `candidate` | a finished retrain, not serving |
| `shadow` | reserved for shadow runs (Plan F) |
| `active` | the version that classifies; exactly one (a unique column plus locking reads) |
| `previous` | the version active before the current one; one only |
| `discarded` | set aside; an older `previous` becomes `discarded` when a new version goes active |
| `failed` | the job or its registration failed |

Version 0 (`v0`) is a row without a bundle, created by the first retrain when no version is active: the server runs the legacy
weights from `models/` when told `active: null`, so rolling back to version 0 needs no file.
`registry.reload_payload(version)` builds the `/v2/reload` body (presigned GETs, 15 minutes). Plan E
has no command that activates a version or reloads the server.

## Source

| Module | Role |
|---|---|
| `inference_server/server.py` | FastAPI model server (`/health`, `/reload`; mounts `/v2`) |
| `inference_server/v2.py`, `auth.py` | Token-protected `/v2` router and its bearer check |
| `mail_analysis.py` | Classification maths, taxonomy, explainability (needs numpy/torch) |
| `mail_archive.py` | Safe mail-archive extraction (stdlib only), re-exported by `mail_analysis.py` |
| `ResNetMLP.py` | The neural network definition |
| `inference_server/training_job.py`, `training_worker.py`, `bundles.py` | `/v2/train` job controller, its worker process, `/v2/reload` and bundle classify |
| `training/` | Recipe, groups, gate, bundle format and the dataset reader |
| `tools/dataset_to_npz.py`, `learning_curve.py`, `confidence_shift.py` | Offline evaluation tools; not imported by the server |

The connector lives in the backend: `Suspicious/Suspicious/connectors/contrib/ai_model/`
(`connector.py`, `client.py`, `campaigns.py`, `mailtext.py`, `imap_sync.py`), the ledger in
`Suspicious/Suspicious/ai_model/` (`models.py`, `ledger.py`, `messageid.py`, `taxonomy.py`), and the
replay and backfill commands in `Suspicious/Suspicious/ai_model/management/commands/`.

### Tests

```bash
cd Analyzers/AIMailAnalyzer
pip install -r requirements-inference.txt pytest httpx
python -m pytest tests -v
```

The server tests are skipped where torch is absent. They use real `ResNetMLP` checkpoints written to
a temp dir and a fake sentence-transformer.

These modules are auto-documented in the
[Python Code Reference](../reference/index.md).
