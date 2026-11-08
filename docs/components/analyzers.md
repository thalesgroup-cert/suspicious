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
| `POST /v2/models/ai_mail/classify` | yes | Body `{"mail_body": "...", "versions": ["active"]}` (`["active", "shadow"]` and `["shadow"]` are also accepted, see [Shadow](#shadow-promotion-and-rollback)), optional `exclude_case_ids` (at most 1000, used by bundles only: those cases are left out of the neighbour vote; the `ai_model` connector always sends the classified case's own id). Returns the verdict under `results.active` (class, score, confidence, class and sub-class probabilities, contributing phrases, `tier`) plus the campaign embedding, its version and the latency. `tier` is `null` for version 0 and `legacy-first128` bundles. `400` for any other `versions`, `409` for `["shadow"]` while no shadow is loaded, `503` when models or vectorizer are not loaded. |
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
again, otherwise it is superseded); the Settings card lists flagged labels and resolves them
(`POST /api/ai-model/flags/<id>/resolve/`, see [The Settings card](#the-settings-card)).
`ai_model.ledger.ledger_summary()` gives the counts per source and class, the flagged count
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
changes the active model: a candidate becomes live only through [shadow, promotion and rollback](#shadow-promotion-and-rollback).

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
promoted version can change which signal decides a verdict. Run `ai_model_engine_replay` on the shadow before the first promotion (see the [runbook](#operator-runbook)).

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
| `shadow` | scored beside the active version on live mail, never used for a verdict; at most one (a unique `shadow_slot` column) |
| `active` | the version that classifies; exactly one (a unique column plus locking reads) |
| `previous` | the version active before the current one; one only |
| `discarded` | set aside; an older `previous` becomes `discarded` when a new version goes active |
| `failed` | the job or its registration failed |

Version 0 (`v0`) is a row without a bundle, created by the first retrain when no version is active: the server runs the legacy
weights from `models/` when told `active: null`, so rolling back to version 0 needs no file.
`registry.reload_payload(active, shadow)` builds the `/v2/reload` body (presigned GETs, 15 minutes).
Activating, shadowing, discarding and rolling back go through the
[`/api/ai-model/` endpoints](#shadow-promotion-and-rollback); there is no management command for them.

## Shadow, promotion and rollback

A candidate that passed the gate (`eligible: true`) is not used for any verdict. An admin starts it
as the **shadow**: from then on every new mail case is also scored by the candidate, the answer is
stored and compared, and the candidate can be promoted only after the checks below. Nothing here
runs on its own: no shadow starts and no version is promoted without an admin.

### What the shadow does

- **Dual classify.** While a shadow exists, the connector sends `versions: ["active", "shadow"]` in
  the one classify call. The server answers the active part first, then scores the shadow under its
  own deadline, `AI_SHADOW_TIMEOUT` seconds (default 8, set in `deployment/.env`; the connector's own
  timeout is 20 s). The response waits for it up to that deadline. `results.shadow` is the answer or
  `{"error": "<ClassName>"}`: `NoShadow`, `Timeout`, `Busy` (another shadow pass, often the
  seeding, held the shadow's slot for more than 1 s), `Skipped` (the active pass took longer than
  18 s minus `AI_SHADOW_TIMEOUT`, so 10 s by default, which keeps the whole call under the
  connector's 20 s) or the exception class. A shadow error is
  never an HTTP error when `active` was asked. The shadow runs under its own single slot, outside the
  live classify slots, so a slow shadow never makes a live pass wait; on a timeout the worker thread
  keeps running to its end and holds that shadow slot meanwhile. `["shadow"]` alone is used by the
  seeding and the replay; it waits up to 15 s for the shadow slot (then `503`), and answers `409`
  when no shadow is loaded.
- **Stored result.** When the case's AI job closes, in the same transaction and before the case is
  reconciled, the answer becomes one `ShadowResult` per (case, version) (class, score, confidence,
  probabilities, tier). A shadow error answer writes no row; a failure to store is logged by class
  and leaves the live analysis written, so a failing shadow only lowers the count. The row is dropped when its
  version is no longer the shadow. It never reaches `Case.*_ai`, `AiAssessment`, `score_ai`, the
  campaign collection or any event.
- **Would-be verdict.** After the live verdict, the scoring engine is run again on the same inputs
  with the shadow's answer as the AI vote, and the result, score, rule and flip are stored on the
  `ShadowResult`. The flip is `none`, `changed`, or `critical` (Safe to Dangerous or Dangerous to
  Safe only; Inconclusive and Suspicious changes are `changed`). With the kill switch
  `scoring.mail_embedded_categorical` off, the would-be fields stay empty.
- **Seeding.** When the shadow starts, a Celery task classifies the documents of the live campaign
  collection with the shadow (25 per chunk, at most 20 minutes of work per run, then it queues
  itself again) and stores `ShadowResult` rows with `origin = "seed"`. Seed rows are insert-only: an
  existing row, live or seed, is never touched. They feed the campaign dry run but do not count
  toward the 500 mails. If the server or the vector store is away, or the server does not hold the
  shadow yet, the task pauses and retries after 5 minutes. Each document is classified with its own
  case left out of the neighbour vote, and the task pauses 1 s after each classify so that live
  dual calls can take the shadow slot. Live shadow answers can still be `Busy` while seeding runs,
  so most live results, the ones that count toward the 500, accumulate after it. A run holds one Celery worker for up to about 31 minutes (20
  minutes of work, a 30-minute soft and a 31-minute hard time limit), so keep the worker's
  concurrency at 4 or more.
- **Campaign dry run.** On `case_finalised` the connector also queues a dry run for the shadow. It
  uses the live collection for geometry (the campaign embedding does not depend on the classifier)
  and the database for the candidate's classes: it queries the 60 nearest neighbours without a class
  filter, keeps those whose case the candidate called Dangerous, and applies the live threshold and
  member rules. It writes one `ShadowCampaignEffect` per case (`no_check`, `none`, `would_create`,
  `would_join`, with the member case ids) and nothing to the collection, `Campaign`,
  `CampaignMember` or the event bus. Neighbours beyond rank 60 are missed on the shadow side, where
  the live query uses 20 Dangerous ones. This replaces the separate shadow collection of the design
  spec: the proxy blocks deleting collections and the cleanup connector watches only the live name.
- **Alert delta.** Per case with a dry-run effect: `candidate_only` (the effect is `would_create` or
  `would_join` and the live case is in no campaign) and `active_only` (the live case is in a campaign
  and the effect is `none` or `no_check`). The unit is the case, not the campaign.

### The server follows the registry

The registry is the truth. The server keeps loaded models in memory only, so after a restart it
holds the legacy weights (`active: null`) and no shadow. `ai_model/serversync.py` compares the
registry with `GET /v2/models/ai_mail` (version ids) and pushes `POST /v2/reload` when they differ.
It runs after every pointer move, after a shadow start and a discard, and from the beat entry
`ai-model-server-sync` every 300 s, so a restarted server is brought back to the registry state
within five minutes. `/v2/reload` is all-or-nothing, so a reload refused (4xx) while a shadow is
wanted is retried once without the shadow: the active pointer never depends on the shadow bundle.
When that retry succeeds, the shadow gets a `shadow_refused` event, unless its latest event is already one (so a refusal
right after a recovery may go unrecorded), and the
server runs without it until the bundle loads or an admin discards it. After a shadow start the
shadow must load: if the server refuses it, the version goes back to `candidate` (`shadow_since`
cleared, a `shadow_refused` event) and the request fails. A discard syncs best effort: a failure is
only logged. If the server refuses a reload with a 4xx right after a promotion or rollback, even
without the shadow, the pointer move is reverted and the request fails; a promoted version whose revert finds the shadow slot taken by another version goes back to
`candidate`, not `shadow`. A transient failure (server down, timeout) keeps the new pointer and the
beat retries; so does a connector without a usable token or url. Until it succeeds the connector health check says "registry and server differ". Every
answer carries its version id, so nothing is mislabelled meanwhile.

### Promotion conditions

`promotion.can_promote` is the only place they live; `promote` re-checks them under row locks, so
whatever a client sends, an unmet condition refuses the promotion. The endpoint answers `409` with
the codes of the unmet conditions.

| Code | Condition |
|---|---|
| `not_shadow` | the version is the shadow |
| `too_young` | at least `shadow_min_days` (7, can be extended) since `shadow_since` |
| `too_few_results` | at least 500 live shadow results with a would-be verdict (seed rows and rows without a would-be verdict do not count, the same population as the flips and the agreement) |
| `unreviewed_flips` | every critical flip has a review |
| `unreviewed_campaigns` | every `candidate_only` and `active_only` case has a review |
| `recheck_missing`, `recheck_failed`, `recheck_stale` | a gate recheck that passed, finished after the minimum period was met and less than 7 days ago |
| `profile_window` | only when the candidate's campaign profile differs from the active one: dry-run effects spanning at least 15 days |
| `job_running` | no training or recheck job is running |

Reviews are append-only: a review is a `ShadowReview` row with a note, the latest one per item
counts, and a review of an item that no longer exists is refused. Only critical flips can be
reviewed; the other changes are listed but not required.

### Counters and warnings

A daily beat task (`ai-model-materialise-stats`) rebuilds `ModelVersionStats` for the last three
days from `AiAssessment` (scored, Dangerous, per `model_version`), `CampaignMember` (created,
joined) and the successful `ConnectorDelivery` rows. Two figures are proxies. `campaign_checks`
counts successful `ai_model` `case_finalised` deliveries, which queue the detection, so it can
overcount when the mail text was unreadable. `alerts` counts successful TheHive `campaign_updated`
deliveries, attributed through the case's assessment version. Counters lag by up to a day.

- **Purity** (shown per version): over 30 days, among the version's campaign members that carry an
  active label, the share labelled Dangerous. The warning needs at least 10 labelled members and a
  purity under 80%.
- **Age warning:** the version was registered (`ModelVersion.created_at`) more than 60 days ago.

### The Settings card

Settings, section "AI model" (`/settings/ai_model`). The Settings page admits Admin and CERT; this
section is listed only for a user in the `Admin` group and only while the `ai_model` connector is
enabled. For anyone else the section is absent and its URL redirects to the first section. The
connector gallery tile for `ai_model` carries a line pointing here, with a link for an Admin.

Five tabs:

- **Overview:** connector health, the circuit breaker state with a reset (only while open or
  half-open), the active version and its age (a warning past 60 days), labels by source and class,
  the schedule, and "Retrain now".
- **Candidate:** the newest candidate, its gate checks with value and threshold (failed checks
  first), the campaign held-out result and the tier cutoffs. "Start shadow" is unavailable when the
  candidate is not eligible or a shadow exists. Discard.
- **Shadow:** age and live results against the promotion minimums, agreement, verdict changes with
  review, campaign effects and the alert delta, the promotion conditions (met and unmet, in words),
  Promote, Extend, Recheck, Discard.
- **Versions:** history with counters and purity, and Rollback on the `previous` version.
- **Ledger:** label mix with its jump warning, flagged labels with resolve, and the review queue.

Retrain, promote, rollback, discard, resolve and the breaker reset each ask for confirmation. A
`409` is shown in words from its `codes`; the card shows only what the server confirmed. Every
version action sends the `version_id` it shows (and discard its expected status), so an action
from a stale screen is refused instead of acting on whatever the server holds now.

**Schedule rule.** `schedule.next_run` is not stored. It is the newest version's `created_at` plus
`retrain_interval_days` (default 30), or now when there is no version. The newest version counts candidate, shadow, active and previous
versions only; discarded and failed ones are ignored. It is `null` when the
connector is disabled, `retrain_enabled` is not true, or a job runs. After a failed scheduled job
(including a refused one) started within the last 7 days, the date is pushed to the end of that
7-day backoff, reported as `backoff_until`. The beat check runs once a day, so the card says
"about".

**Breaker publication.** `pybreaker` state lives in each process. Each process writes
`{state, since}` to the shared Django cache key `breaker:<name>` (`breaker:ai_model`) on every state
change, last writer wins, with no expiry; `status` reports that value, or `unknown` when the key is
absent or the cache fails. A reset (`POST /api/ai-model/breaker/reset/`) increments the integer at
`breaker-epoch:<name>`. Before a call, a process compares the epoch with the one it last applied
and closes its own breaker when it moved; it reads the cache at most once per 5 seconds per breaker,
so a reset lands within about 5 seconds. A cache outage never breaks a call (the check fails open).
A reset does not hide a server that is down: the breaker opens again after five failures
(`BREAKER_FAIL_MAX`). Each reset adds a `ModelEvent`.

**Label mix warning.** `GET /api/ai-model/ledger/` compares the Dangerous, Safe and Unwanted shares
of the active `imap_folder` rows now with the shares among the active `imap_folder` rows observed
more than 30 days ago. `jump` is `{class, from, to}` for the class that moved most, when it moved
by more than 15 percentage points and each window holds at least 50 rows; otherwise it is `null`.

**Review queue.** `disagreements`: mail cases finalised in the last 30 days whose latest AI class
is on the other side of the Safe/Dangerous axis from the case verdict and where the AI did not set
the band (the cross-check rule of the case view). `campaign_conflicts`: campaigns whose active
folder-labelled members include both Dangerous and Safe. Each list holds at most 200 rows before
paging and carries ids, classes and dates only, never mail text, subject or sender.

### Endpoints

Reads need the `Admin` or `CISO` group, writes the `Admin` group. A superuser without the `Admin`
group is refused. Lists take `?<prefix>_limit` (default 50, at most 100) and `?<prefix>_offset`.

| Route | Role | What it does |
|---|---|---|
| `GET /api/ai-model/status/` | Admin, CISO | active, previous and shadow summaries, whether a job is running, and the card header: `health` (`{ok, detail, checked_at}`, `detail` capped at 200 characters), `breaker`, `schedule`, `counts` (versions by status), `jobs` (the last five) and `ledger` |
| `GET /api/ai-model/versions/` | Admin, CISO | versions with counters, purity and the age warning (`limit`, `offset`) |
| `GET /api/ai-model/shadow/` | Admin, CISO | the shadow with agreement, flips (`flips_`), dry-run effects (`effects_`), the alert delta (`candidate_only_`, `active_only_`) and the unmet `conditions` |
| `GET /api/ai-model/reviews/` | Admin, CISO | the review log, optional `?version_id=` |
| `POST /api/ai-model/shadow/start/` | Admin | `{version_id, note}`: a gate-eligible candidate becomes the shadow, seeding is queued and the server is synced; `409` and back to `candidate` when the server refuses the bundle |
| `POST /api/ai-model/reviews/` | Admin | `{kind: "flip" or "campaign", case_id, note}` for the shadow |
| `POST /api/ai-model/recheck/` | Admin | start a gate recheck of the shadow; `202 {job_id}` |
| `POST /api/ai-model/extend/` | Admin | `{days}`: a new total for `shadow_min_days`, above the current one, at most 365 |
| `POST /api/ai-model/promote/` | Admin | promote the shadow (or `version_id`); `409` with `codes` when refused |
| `POST /api/ai-model/rollback/` | Admin | the `previous` version becomes active; `409 no_previous` without one. With `version_id` (the target the screen shows), `409 state_changed` and no change when the `previous` is another version |
| `POST /api/ai-model/discard/` | Admin | set aside a candidate, shadow or previous version, free the shadow slot and sync the server (best effort). With `expected_status`, `409 state_changed` and no change when the version is no longer in that status |
| `GET /api/ai-model/candidates/` | Admin, CISO | candidates and the shadow, newest first (`limit`, `offset`): `{version_id, status, created_at, trigger, rows, excluded_rows, eligible, gate}`. `gate` is a whitelisted copy of the manifest (`checks`, `candidate`, `baseline`, `campaign`, `tier_cutoffs`; numbers, booleans and strings up to 300 characters, nested at most 4 levels, lists cut at 50 items; any string or key containing `http` is dropped); the manifest, bundle prefix and URLs never leave the registry |
| `GET /api/ai-model/jobs/` | Admin, CISO | the retrain job history, newest first (`limit`, `offset`): `{job_id, kind, state, trigger, rows, excluded_rows, started_at, finished_at, error}`, `kind` is `recheck` for a gate recheck of the shadow (no candidate) and `retrain` otherwise, `error` capped at 200 characters |
| `GET /api/ai-model/ledger/` | Admin, CISO | `ledger_summary()` (`by_source`, `flagged`, `trainable`) plus `mix`, the label mix and its jump warning (see below) |
| `GET /api/ai-model/flags/` | Admin, CISO | flagged labels, newest first (`limit`, `offset`): `{id, case_id, label_class, source, flag_reason, observed_at}`; no message id, subject or sender |
| `GET /api/ai-model/queue/` | Admin, CISO | `disagreements` and `campaign_conflicts`, each `{count, results}` (rows: `{case_id, verdict, ai_class, date}` and `{campaign_ref, classes, date}`), paged with `disagreements_limit`/`disagreements_offset` and `conflicts_limit`/`conflicts_offset` |
| `POST /api/ai-model/retrain/` | Admin | `{note}`: start a manual retrain; `202 {job_id}`; `409` with a fixed message when a job runs or the retrain is refused |
| `POST /api/ai-model/flags/<id>/resolve/` | Admin | `{keep, note}` (note required, at most 2000 characters): `keep: true` makes the label active again, `false` supersedes it; `404` for an unknown label, `409` when it is not flagged; answers the label row |
| `POST /api/ai-model/breaker/reset/` | Admin | `{note}`: move the breaker's reset epoch; `202 {epoch}`; `503` when the shared cache is unavailable |

Every write adds a `ModelEvent` with the user. Its note is the request's note for shadow start,
promote, rollback and discard; `<days> days` plus the note for extend; `<kind> <case_id>` for a
review (the review text is on the `ShadowReview` row); the job id for a recheck start. A recheck
that finishes adds a `recheck` event without a user, noting the job id and the outcome. Stored results of earlier cases are never
recomputed by a promotion or a rollback.

### Operator runbook

1. **Check the setup.** The connector is enabled, `ai_inference` runs with `--profile ai`, and a
   candidate with `eligible: true` exists (`GET /api/ai-model/versions/`, or `ai_model_retrain
   --status`). Only one shadow can exist: discard an old one first.
2. **Start the shadow.** `POST /api/ai-model/shadow/start/` with the `version_id`. Seeding begins
   at once; the dry run table is useful from the first day.
3. **Wait and read the table.** `GET /api/ai-model/shadow/` shows live results, agreement (class
   and verdict), the flips, the dry-run effects, the alert delta and `conditions`. The minimum is 7
   days and 500 live results; at about 85 mails a day that is about a week.
4. **Review the flips.** For each critical flip and each alert-delta case, open the case, decide,
   and `POST /api/ai-model/reviews/` with `kind`, `case_id` and a note. A flip is reviewable only
   while it exists; the table says `reviewable` and `reviewed` per row.
5. **Run the engine replay and record the figures.** The first promotion waits for this reading,
   because a calibrated model reports lower confidence than version 0 and the engine compares
   `confidence_ai` with a floor.
   ```bash
   docker compose --env-file .env exec suspicious python manage.py ai_model_engine_replay <version_id> --limit 200 --since-days 30
   ```
   The command rebuilds the non-AI signals read-only and replays recent finalised mail cases with
   the live AI signal and with the shadow's. It prints the transition matrix, the number of changed
   and critical verdicts, the Inconclusive rate and the median confidence, before and after. It
   leaves out the embedded-evidence step in both passes, so the figures are a sensitivity study, not
   an oracle. It stops after 5 consecutive classify failures and counts skipped cases by exception
   class. Write the figures in the promotion note.
6. **Recheck.** `POST /api/ai-model/recheck/` after the minimum period is met. It runs the gate on
   the current ledger with the shadow's recipe and seed, writes no bundle and cannot promote
   anything. Its result is stored on the version as passed or failed with a time, and must be less
   than 7 days old at promotion. A recheck stored while the shadow is not in that state is refused.
   Poll it with `GET /api/ai-model/status/` (`job_running`).
7. **Extend if needed.** `POST /api/ai-model/extend/` with a larger total of days, for example when
   the table has too few results or a profile window is still open.
8. **Promote.** `POST /api/ai-model/promote/`. On `409`, the `codes` name what is missing. On
   success the shadow is active, the old active is `previous`, an older `previous` is `discarded`,
   and the server is reloaded.
9. **Roll back.** `POST /api/ai-model/rollback/` returns the `previous` version to active and reloads
   the server. The version rolled back from becomes `previous`. Mails scored since keep their stored
   version and results.
10. **After a server restart.** The restarted server serves version 0 until the beat entry syncs it
    (at most five minutes); to hurry it, run the task `ai_model.tasks.sync_server` from a Django
    shell. No registry change is needed.

**Dev-stack acceptance run (operator step, not part of the test suites).** On the dev stack from
`CLAUDE.md`, shadow a real candidate over a few days of replayed mail, then do one promote, one
rollback and one server restart (`docker compose --profile ai restart ai_inference`), checking after
each that `GET /v2/models/ai_mail` on the server lists the versions `GET /api/ai-model/status/`
reports. Record the dates and figures in the promotion note. This has not been run yet.

### Troubleshooting shadow and promotion

| Symptom | Likely cause and check |
|---|---|
| `shadow/start/` answers `409` | the version is not a `candidate`, did not pass the gate, or another version is the shadow (discard it first); or the server refused the bundle, the version is back to `candidate` with a `shadow_refused` event: check the `ai_inference` logs |
| A `shadow_refused` event on the running shadow | the server refused the shadow bundle on a reload and runs without it; the beat keeps trying. Check the `ai_inference` logs, or discard the shadow |
| No live results accumulate | the connector is off, the server does not hold the shadow (health says "registry and server differ"; check `GET /v2/models/ai_mail`), or the shadow keeps timing out, is `Busy` or `Skipped` (`results.shadow.error` is logged by class). `Busy` is expected while seeding runs: live results accumulate after it. For timeouts, check the server's load or raise `AI_SHADOW_TIMEOUT`; raising it shortens the window in which a slow active pass still gets a shadow (18 s minus the timeout), and above about 15 s slow mails get no shadow (`Skipped`) |
| `409` on promote with `too_few_results` | seed rows do not count; wait for live mail or extend |
| `409` on promote with `recheck_stale` | the recheck is older than 7 days or finished before the minimum period was met: run a new one |
| `409` on promote with `job_running` | a training or recheck job is running; wait for it |
| "The inference server refused the change; it was reverted" | the reload got a 4xx (bundle hash, encoder change, token); the pointer is back where it was. Check the `ai_inference` logs |
| Promoted, but the server still answers the old version | a transient reload failure; the registry is right and the beat entry retries every 5 minutes |
| Seeding stopped or keeps pausing | the log line names the class; a paused run requeues itself after 5 minutes. A missing token or url stops it (`ValueError`). When the server refuses the shadow bundle (a `shadow_refused` event), the sync returns without the shadow and seeding pauses every 5 minutes (`ProviderUnavailable`) until the bundle loads or the shadow is discarded |
| Engine replay prints few cases | the skipped reasons name the exception classes (`NoMailText`, `ShadowRefused`, ...) |
| Counters look low | they are rebuilt daily for the last three days; `campaign_checks` is a proxy |

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
`Suspicious/Suspicious/ai_model/` (`models.py`, `ledger.py`, `messageid.py`, `taxonomy.py`, `registry.py`, `promotion.py`, `serversync.py`, `shadow.py`, `stats.py`, `tasks.py`), the dry run in `connectors/contrib/ai_model/dryrun.py`, the endpoints in `api/views/ai_model.py`, and the
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
