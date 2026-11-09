# AI inference: set up, deploy and operate

This guide takes an operator from nothing to a running AI mail classifier, and then through its
day-two work: verification, the review-mailbox label sync, retraining, shadow, promotion and
rollback, upgrades, hardening and troubleshooting. Reference detail (every route, gate check and
failure mode) stays in [AI / ML Analyzers](../components/analyzers.md); this page is the order in
which to do things, with every command checked against the repository.

## 1. What the pieces are

| Piece | Where | Role |
|---|---|---|
| `ai_inference` | compose service, profile `ai`; code in `Analyzers/AIMailAnalyzer/inference_server/` | Persistent FastAPI model server (one uvicorn worker). Holds the sentence-transformer encoder (`paraphrase-multilingual-mpnet-base-v2`) and the classifier weights in memory, classifies, embeds, and runs retraining jobs. |
| `ai_model` connector | `Suspicious/Suspicious/connectors/contrib/ai_model/`; off by default | The `mail_ai` provider. A Celery task in `suspicious_celery` posts the mail text to the server and stores the answer. Also runs campaign detection and the review-mailbox label sync. |
| `ai_model` app | `Suspicious/Suspicious/ai_model/` | Label ledger, model registry (`ModelVersion`, `ModelEvent`), shadow results, retrain orchestration, server sync, `/api/ai-model/` backend. |
| Settings card | UI, `/settings/ai_model` | Admin-only card for the retrain, shadow, promote and rollback actions. Listed only while the connector is enabled. |
| RustFS | `rustfs` | Holds the training datasets (bucket `ai-datasets`) and model bundles (bucket `ai-models`), handed to the server as presigned URLs. |
| ChromaDB | `chromadb` | Collection `suspicious_mails`, used by campaign detection. |

There is no Cortex AI analyzer any more. Cortex still runs YARA, sandbox and metadata analyzers;
the AI verdict comes only from this stack.

### Flow

```
 mail case ──► suspicious_celery (ai_model connector)
                 1. read mail text: object store first, mail archive as fallback
                 2. POST /v2/models/ai_mail/classify  (Bearer AI_INFERENCE_TOKEN)
                        │  http://ai_inference:8090 on suspicious_net
                        ▼
              ai_inference: encoder + ResNetMLP heads (+ shadow, if one is loaded)
                        │
                 3. AiAssessment + case AI fields, CaseAnalyzerJob row "provider-..." closed
                 4. reconcile_case ──► final verdict ──► case_finalised
                 5. case_finalised ──► run_campaign_detection ──► ChromaDB suspicious_mails
                                                              └─► campaign_updated (TheHive)

 review mailbox (IMAP) ──► label sync (daily) ──► label ledger ──► ai_model_retrain
 ai_inference ◄── presigned dataset GET / bundle PUT ──► RustFS (ai-datasets, ai-models)
 candidate ──► gate ──► shadow ──► promote ──► /v2/reload on the server (rollback the same way)
```

## 2. Prerequisites

- **Stack:** the base deployment from [Installation](installation.md) works (`make init` done,
  `suspicious_net` created, `deployment/.env` and `Suspicious/settings.json` in place, RustFS,
  ChromaDB, Celery worker and beat running). `ai_inference` also needs the `storage` network, which
  compose attaches.
- **CPU only.** The image installs torch from the CPU wheel index and the server pins
  `device = torch.device("cpu")`. There is no GPU path.
- **Memory.** `ai_inference` has `mem_limit: ${AI_INFERENCE_MEM_LIMIT:-8g}`. The compose comment
  estimates about 0.8 GB for the idle server and about 4.5 GB at the peak of a training run; the
  estimate is not a measurement. The only measured figure is a peak of 1.58 GiB during a 165-row
  retrain on the dev stack ([acceptance run](../plans/2026-11-08-ai-model-f-acceptance-run.md)); a
  real ledger is larger, so record `docker stats ai_inference` during your first retrain. An OOM
  kill fails the job (`worker exited with code -9`).
- **CPU.** Classify keeps torch's default threads; a training job uses `AI_TRAIN_THREADS` (default
  2). Keep that below the host's CPU count, or live classification slows during training. The server
  allows `INFERENCE_MAX_CONCURRENCY` (default 2, an image-level default that compose does not set)
  concurrent classifications.
- **Celery concurrency.** Keep `CELERY_CONCURRENCY` at 4 or more (`deployment/.env.example`
  default is 4): shadow seeding holds one worker for up to about 31 minutes per run.
- **Disk.** The image carries torch and the encoder weights. Check the size with
  `docker images aimailanalyzer-inference` after the first build; no figure is recorded in the
  repository. `models/` is small (five `.pth` files). Bundles live in RustFS, so size the RustFS
  volume for them.
- **Internet, build time only.** `inference_server/Dockerfile` downloads `model.safetensors`,
  `config.json` and `1_Pooling/config.json` of the encoder from Hugging Face, pinned to commit
  `4328cf26390c98c5e3c738b4460a05b95f4911f5` (`ARG ENCODER_REVISION`), and pulls torch from
  `download.pytorch.org/whl/cpu`. Behind a proxy, set `HTTP_PROXY` and `HTTPS_PROXY` in
  `deployment/.env`; the override passes them as build args. At run time the image sets
  `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1`, so the container never needs the internet.
- **Do not move the encoder pin casually.** The encoder hash covers the vectorizer files, so a
  different revision makes every registered bundle unloadable until it is retrained (version 0 is
  unaffected). See [the pin](../components/analyzers.md#bundle-layout).

## 3. Model weights

The server needs two things on disk: the encoder (built into the image, section 2) and the
version 0 classifier weights, which you provide.

### 3.1 The `models/` directory

`Analyzers/AIMailAnalyzer/models/` is git-ignored and excluded from the Docker build context.
Compose bind-mounts it read-only at `/worker/AIMailAnalyzer/models` (path built from
`CUSTOM_ANALYZERS_PATH`, default `../Analyzers` in `.env.example`). Five files are expected
(`MODEL_SPECS` in `mail_analysis.py`):

```text
safe_suspicious_30_epochs_model.pth
spam_dangerous_30_epochs_model.pth
safe_30_epochs_model.pth
dangerous_30_epochs_model.pth
unwanted_30_epochs_model.pth        # optional: the server runs without it
```

`/health` is `200` only when the encoder and the four required files are loaded; otherwise `503`
naming the missing file and the load error. There is no public download for these weights. Produce
them from your own labelled mail:

- `Analyzers/AIMailAnalyzer/train_models.ipynb` (interactive; it saves under different file names
  and you must rename them to the list above), or
- `Analyzers/AIMailAnalyzer/train_test_models.py`, the scripted equivalent that writes the exact
  file names: `python train_test_models.py --csv mailbox_dataset.csv --out models`. Its image is
  `Analyzers/AIMailAnalyzer/Dockerfile.train` (a shell entrypoint; requirements in
  `requirements-train.txt`). The dataset layout is produced by `mailbox_to_csv.ipynb` and
  `build_test_dataset.py`; read those files for the expected columns, as they are not documented
  elsewhere.

Without these files the server never becomes ready and every classification fails with
`HTTP 503: models unavailable`. Copy a replacement set into the directory while the server runs:
it re-checks the files every `INFERENCE_RELOAD_CHECK_SECONDS` (30), hot-swaps changed ones, and a
file that fails to load never replaces a working model. `POST /reload` does it at once.

### 3.2 Bundles (retrained versions)

Retrained versions are not files in `models/`. They are bundles under
`ai-models/<version_id>/<job_id>/` in RustFS, registered in the database. Django presigns them and
pushes them to the server with `POST /v2/reload`. You do not place them by hand. Version 0 (the
`models/` weights) needs no bundle, which is why a rollback to it needs no file.

### 3.3 RustFS presigned URLs and `AI_BUNDLE_HOSTS`

The server holds no storage credentials. It fetches the dataset and uploads bundle files only
through presigned URLs, and only to hosts in `AI_BUNDLE_HOSTS` (comma-separated `host:port`,
compared as strings, no DNS resolution, http or https, no redirects, 200 MB download cap; empty
refuses every URL). The default is `rustfs:9000`.

Django presigns with the store's internal endpoint (`get_store()`, not the browser-facing
`public_endpoint`), so `AI_BUNDLE_HOSTS` must equal the `host:port` of `storage.s3.endpoint` in
`settings.json`. If your endpoint is not `rustfs:9000`, change both. Django creates the two buckets
on demand (`ensure_bucket`).

## 4. Deploying the server

### 4.1 Environment

Variables in `deployment/.env` (documented in `.env.example`, passed to the service by
`compose_apps.yaml`):

| Variable | Default | Meaning |
|---|---|---|
| `AI_INFERENCE_TOKEN` | empty | Bearer token of the `/v2` API. Empty makes every `/v2` route that needs a token answer `503 token not configured`. |
| `AI_BUNDLE_HOSTS` | `rustfs:9000` | Allowed presigned-URL hosts, section 3.3. |
| `AI_TRAIN_THREADS` | `2` | Threads of the training worker only. |
| `AI_SHADOW_TIMEOUT` | `8` | Seconds to wait for the shadow answer in a dual classify call. |
| `AI_INFERENCE_MEM_LIMIT` | `8g` | Container memory limit. |
| `AI_INFERENCE_VERSION` | `local` | Image tag: `aimailanalyzer-inference:${AI_INFERENCE_VERSION:-local}`. Not in `.env.example`; set it only to pin a tag. |
| `LOG_LEVEL` | `INFO` | Shared with the other services. |

`AI_TRAIN_MAX_SECONDS` (default 4 hours) and the `INFERENCE_*` variables exist in the server code
but compose does not pass them; changing them means editing the service in `compose_apps.yaml`.

### 4.2 Generate the token and put it in two places

```bash
openssl rand -hex 24
```

1. `deployment/.env`: `AI_INFERENCE_TOKEN=<value>`.
2. The connector's `token` (section 5).

The two values must be identical. A mismatch shows as `rejected the token (HTTP 401)`.

### 4.3 Build and start

The Makefile sets `COMPOSE := docker compose --env-file .env --profile ai`, so every `make` target
includes the `ai` profile:

```bash
cd deployment
make build     # builds all local images, including aimailanalyzer-inference
make up        # starts everything, including ai_inference
```

`make deploy` (alias `make upgrade`) also builds the image (`--profile ai build ai_inference`) and
starts `ai_inference` before the rolling restart of `suspicious`. With plain compose you must name
the profile:

```bash
docker compose --env-file .env --profile ai up -d --build ai_inference
```

Without `--profile ai`, compose does not start or build the service. That is deliberate (the CI
stack does not pull the torch image), and it is also the first thing to check when the connector
reports `unreachable`.

The build context is `${CUSTOM_ANALYZERS_PATH:-../Analyzers}/AIMailAnalyzer` with
`inference_server/Dockerfile`. The Dockerfile start period is 120 s, so a fresh container shows
`starting` while the encoder loads.

### 4.4 Networks

`ai_inference` sits on exactly two networks: `suspicious_network` (the external network named by
`NETWORK_NAME`, `suspicious_net` by default) and `storage`. It is not on the `data` network.
The service is reachable as `http://ai_inference:8090` from `suspicious_celery` and `suspicious`.
No compose file publishes a host port. `make network-check` (script `deployment/scripts/network-check.sh`)
asserts the network membership and that Celery reaches `ai_inference:8090` and `ai_inference`
reaches `rustfs:9000`.

### 4.5 Check the server

```bash
cd deployment
# readiness, from inside the container (curl is in the image)
docker compose --env-file .env --profile ai exec ai_inference curl -s http://127.0.0.1:8090/health
# token accepted, versions held
docker compose --env-file .env --profile ai exec ai_inference \
  sh -c 'curl -s -H "Authorization: Bearer $AI_INFERENCE_TOKEN" http://127.0.0.1:8090/v2/models/ai_mail'
# the worker reaches it over the network
docker compose --env-file .env exec suspicious_celery python -c \
  "import urllib.request; print(urllib.request.urlopen('http://ai_inference:8090/v2/health/ready').read())"
```

`/health` returns `{"ready": ..., "vectorizer": {...}, "variants": {"personal": {"models": {...}}}}`
with `200` when ready, otherwise `503` and the per-file `error`. `GET /v2/health/live` and
`GET /v2/health/ready` need no token; `/health` and `POST /reload` need none either, which is why
the server must never be published (section 11).

## 5. Enabling the `ai_model` connector

The connector is off by default (`enabled_by_default=False`). A fresh instance, or one upgraded
without this step, has no AI vote (see 5.5).

### 5.1 Configure

Config keys (`integrations.ai_model` in `settings.json`, or the Settings tile):

| Key | Default | Notes |
|---|---|---|
| `url` | `http://ai_inference:8090` | Required. Must be a valid http(s) URL. |
| `token` | none | Required secret; same value as `AI_INFERENCE_TOKEN`. |
| `timeout_seconds` | `20` | Socket timeout per connect and per read. |
| `imap_host`, `imap_port` (993), `imap_user`, `imap_password` (secret), `imap_use_ssl` (true), `imap_folders` | empty / defaults | Review-mailbox label sync, section 7. |
| `retrain_enabled` (false), `retrain_interval_days` (30) | | Scheduled retrain, section 8. |

Two ways to set the token, depending on how secrets are stored:

- **`settings.json`** (works without Vault):

  ```json
  "integrations": {
    "ai_model": { "url": "http://ai_inference:8090", "token": "<AI_INFERENCE_TOKEN>", "timeout_seconds": 20 }
  }
  ```

  The shipped example `docs/getting-started/examples/Suspicious-settings.example.json` already has
  this block with an empty token. A configuration saved from the UI in the database wins over
  `settings.json` for the non-secret fields. Recreate the Django and Celery containers after editing
  the file (`docker compose --env-file .env up -d --force-recreate --no-deps suspicious
  suspicious_celery suspicious_celery_beat`); a bind-mounted file edited by rename can leave a
  running container on the old inode.
- **Settings tile or `PUT /api/connectors/ai_model/config/`.** Secret fields are written to Vault.
  Without a configured Vault the call answers `409 secret store not configured`; use
  `settings.json` then.

### 5.2 Enable

In Settings, connector gallery, tile `ai_model`, or:

The API form is `PATCH /api/connectors/ai_model/` with the body `{"enabled": true}`, as an
authenticated Admin or CERT user.

Roles: the connector routes require the Admin or CERT role. Only one connector may provide
`mail_ai`; enabling a second answers `409 <name> already provides mail_ai`.

### 5.3 Test

`POST /api/connectors/ai_model/test/` runs the health check: it calls
`/v2/health/ready`, then `/v2/models/ai_mail` with the token, and reports one of `ready, token
accepted`, `unreachable: <ErrorClass>`, `not ready (HTTP n)`, `token rejected (HTTP 401)`. It also
appends a sentence when the `chromadb` connector watches another collection than
`suspicious_mails` and `registry and server differ` when the registry and the server disagree on
versions.

### 5.4 ChromaDB collection name

Campaign detection writes to the collection `suspicious_mails`. The `chromadb` cleanup connector
deletes old documents from the collection named by its `collection_name`, default `suspicious`.
Set it in `settings.json` (the key has no Settings field), as the shipped example and CONFIG.md do:

```json
"integrations": { "chromadb": { "collection_name": "suspicious_mails" } }
```

### 5.5 If the connector stays off

A mail case gets `results_ai = Inconclusive` and no AI vote (`ai_missing`). Scoring then finalises a
mail as `Dangerous` only when enough analyzers call it malicious (`n_malicious >= max(1,
n_scored // 3)`) or a domain or URL is deny-listed, as `Failure` when nothing scored, and otherwise
as `Inconclusive` with rule `analysis-incomplete`, unless an allow-list majority makes it `Safe` or
an embedded indicator raises it. Notification mails, the TheHive challenge text and the dashboards
show that verdict. Campaign detection and the TheHive campaign alert do not run. Details:
[Without the connector](../components/analyzers.md#without-the-connector).

## 6. Verifying end to end

1. **Server:** the three commands in 4.5 succeed.
2. **Connector health:** `POST /api/connectors/ai_model/test/` returns `ok: true`.
3. **Submit a test mail** (Submit page, or the feeder). Use a mail body that has not been analysed
   before.
4. **Delivery rows:** `GET /api/connectors/ai_model/deliveries/` (Admin or CERT; limit and offset
   paging). An `analyze` event with status success is the proof. A failure carries the reason in
   `error` (section 14).
5. **Assessment stored:**

   ```bash
   docker compose --env-file .env exec suspicious python manage.py shell -c \
     "from ai_model.models import AiAssessment as A; a=A.objects.order_by('-id').first(); print(a and (a.case_id, a.model_version, a.result, a.tier, a.latency_ms))"
   ```

   `model_version` is `v0` until a retrained version is promoted.
6. **Case view:** the submission drawer and the investigation overview show an "AI model
   assessment" section for the case.
7. **Server log:** `docker compose --env-file .env --profile ai logs --tail=50 ai_inference` shows
   the request.
8. **Campaign detection** (after the case finalises): the worker log, not the deliveries, holds its
   errors. `ai_model_campaign_replay <campaign_ref>` checks a historical campaign (section 9).

Failure drill from the Plan A acceptance: stop `ai_inference`, submit a mail; within about 75
seconds the row is `Failure`, `results_ai` is `Inconclusive`, the case still finalises, and after
repeated failures the circuit breaker opens.

## 7. Review-mailbox label sync

Retraining needs labelled mail. Analysts file mails into review IMAP folders; the connector reads
them into the label ledger.

- **Folders and classes.** The class comes from the digit prefix: `0_LEGIT_INTERNAL_COMMUNICATION`,
  `0_LEGIT_EXTERNAL_COMMUNICATION` (Safe); `1_SPAM`, `1_NEWSLETTER` (Unwanted);
  `2_CLASSIC_PHISHING`, `2_CLONE_PHISHING`, `2_BLACKMAILING_PHISHING`, `2_WHALING_PHISHING`
  (Dangerous). Only the last path segment (split on `.` and `/`) must be one of these eight names.
  `imap_folders` is a comma-separated list; the default is all eight.
- **Mailbox contents.** The labelled mail is the first `message/rfc822` attachment of each review
  mail, matched to a case by Message-ID (fallback: sender, UTC day, subject).
- **Config.** `imap_host` (empty means the sync does nothing), `imap_port`, `imap_user`,
  `imap_password`, `imap_use_ssl`. `imap_use_ssl: false` is plain IMAP with no STARTTLS: dev and
  greenmail only. TLS verifies against the Celery container's system CA store; the
  `rootcafile.pem` mounted at `/etc/private/` is not used, so a mailbox behind an internal CA
  fails with `ImapTlsFailed` until that CA is in the image or `SSL_CERT_FILE` points at it.
- **Schedule and limits.** A 86400 s schedule `label-sync` (about daily, counted from when
  `suspicious_celery_beat` started). Per run: at most 500 UIDs per folder, chunks of 25 mails, 300 s
  time budget, mails above 25 MB skipped. The mailbox is opened read-only (`BODY.PEEK[]`); nothing
  is marked, moved or deleted. A large mailbox therefore takes several runs.
- **Run now.** There is no run-now button. Either run the backfill with `--folders` (no UID cap or
  time budget), or queue the task:

  ```bash
  docker compose --env-file .env exec suspicious python manage.py ai_model_backfill_labels --folders
  docker compose --env-file .env exec suspicious python manage.py ai_model_backfill_labels --dry-run
  docker compose --env-file .env exec suspicious python manage.py shell -c \
    "from connectors.tasks import run_connector_sync; run_connector_sync.delay('ai_model')"
  ```

  The outcome is a delivery with event `sync`.
- **Embeddings come from the server.** The sync calls `POST /v2/embed`; if the server is down or the
  token is wrong, the sync fails, with the setup errors not retried.
- **Conflicts.** A Dangerous folder label against a Safe analyst verdict (or the reverse) flags the
  row `flagged`, which is not trainable until resolved on the Settings card (Ledger tab) or with
  `POST /api/ai-model/flags/<id>/resolve/`.

Full semantics and limits: [Label ledger](../components/analyzers.md#label-ledger).

## 8. Retraining, gate, shadow, promotion, rollback

Nothing changes the live model on its own. A retrain only creates a `candidate`; an Admin starts
the shadow and promotes.

### 8.1 Retrain

```bash
docker compose --env-file .env exec suspicious python manage.py ai_model_retrain --wait
docker compose --env-file .env exec suspicious python manage.py ai_model_retrain --status
docker compose --env-file .env exec suspicious python manage.py ai_model_retrain --cancel
```

Or "Retrain now" on the Settings card, or `POST /api/ai-model/retrain/` with `{"note": "..."}`.
Requirements: connector enabled, `ai_inference` running with the profile, `storage.s3.endpoint`
matching `AI_BUNDLE_HOSTS`, and enough ledger rows (the gate needs at least 8 mails in every class
of every head; a ledger short of newsletters fails every candidate at check 4). Trainable rows
embedded in an older form are left out; run `python manage.py ai_model_reembed_ledger` to bring
them in. One job runs at a time. Time limits: 6 hours on the Django side, `AI_TRAIN_MAX_SECONDS`
(4 hours) on the server.

Scheduled retrain: set `retrain_enabled: true` and `retrain_interval_days`. The daily beat entry
`ai-model-retrain-check` starts a retrain when the newest version is older than the interval; a
failed or refused scheduled run pauses the check for 7 days.

### 8.2 The gate

Six checks, three repeats of 5 grouped folds, against a baseline: Dangerous-called-Safe no worse than
baseline plus 0.01; macro-F1 within 0.02 of baseline; calibration error below 0.12; 8 mails per
class per head; High-tier precision at least 0.90 (cross-half); the campaign-grouped version of the
first check. The candidate is always registered; `eligible: false` means it cannot be shadowed.
Read the values on the Candidate tab. Full table: [The gate](../components/analyzers.md#the-gate).

### 8.3 Shadow, promote, rollback

1. `POST /api/ai-model/shadow/start/` `{version_id, note}` (or "Start shadow"). Every new mail is
   also scored by the candidate; answers are stored and compared, never used for a verdict. The
   server must load the bundle: if it refuses, the version returns to `candidate`.
2. Wait for the minimums: at least 7 days and 500 live results with a would-be verdict (seed rows
   do not count). `GET /api/ai-model/shadow/` lists agreement, flips, campaign effects and the unmet
   `conditions`.
3. Review every critical flip and every alert-delta case with `POST /api/ai-model/reviews/`.
4. Run the engine replay before the first promotion, and write the figures in the promotion note:

   ```bash
   docker compose --env-file .env exec suspicious python manage.py ai_model_engine_replay <version_id> --limit 200 --since-days 30
   ```

5. `POST /api/ai-model/recheck/` after the minimum period; it must pass and be under 7 days old.
6. `POST /api/ai-model/promote/`. On `409` the `codes` name what is missing.
7. `POST /api/ai-model/rollback/` makes the `previous` version active again (to `v0` if that is what
   it holds). Mails scored since keep their stored version and results.

Reads need the Admin or CISO group, writes the Admin group. The registry in the database is the
truth: the server keeps loaded models in memory only, so after a restart it serves `v0` until the
beat entry `ai-model-server-sync` (every 300 s) pushes the registry state, at most five minutes. To
hurry it, run the task `ai_model.tasks.sync_server` from a Django shell. Other beat entries:
`ai-model-materialise-stats` (daily).

The route table, tabs of the Settings card and the full runbook: [Shadow, promotion and
rollback](../components/analyzers.md#shadow-promotion-and-rollback) and
[Operator runbook](../components/analyzers.md#operator-runbook). The plan F acceptance run on the
dev stack (retrain, shadow, promote, rollback twice, server restart) is recorded in
[Plan F acceptance run](../plans/2026-11-08-ai-model-f-acceptance-run.md); it tested the machinery,
not model quality.

## 9. Campaign detection

With the connector enabled, each finalised mail queues `connectors.tasks.run_campaign_detection`,
which adds the mail to the ChromaDB collection `suspicious_mails`. When the case's AI result is
`DANGEROUS` and at least three similar mails are found, it creates or joins a campaign and sends
`campaign_updated` (the TheHive campaign alert). Detection does not run under the connector's circuit
breaker; failures retry 3 times (30, 60, 120 s) and are logged in the `suspicious_celery` log, not in
the deliveries. Set the `chromadb` connector's `collection_name` as in 5.4.

Campaigns built before the cutover came from the Cortex AI path. Check a few before relying on the
connector for campaign history:

```bash
docker compose --env-file .env exec suspicious python manage.py ai_model_campaign_replay <campaign_ref>
```

It needs the historical Cortex AI reports, changes nothing, and prints `MATCH` or the missing and
extra case ids.

## 10. Upgrading an existing instance

1. **Back up first** (section 13 and `make backup-db`).
2. **Pull, build, migrate:** `make deploy` builds `ai_inference`, runs migrations (the `ai_model` app
   tables included) and restarts. With a manual flow: `make build`, `make migrate`, `make up`.
3. **Place the weights** in `Analyzers/AIMailAnalyzer/models/` (section 3.1) before the first start.
   An upgraded instance that used the old `ai_inference` keeps its weights; check the directory.
4. **Set `AI_INFERENCE_TOKEN`** in `deployment/.env` and the connector token (section 4.2).
5. **Enable `ai_model`** (section 5) and set the `chromadb` `collection_name` (5.4).
6. **Keep `integrations.cortex.analyzers.ai` in `settings.json`.** The Cortex AI analyzer is gone,
   but this key names the `Analyzer` row of the AI vote (default `AI_Mail_Analyzer` when absent):
   the connector puts its ledger row on it, scoring takes the AI weight from it, and historical
   Cortex AI reports carry its name and stay out of the weighted blend so they are not counted twice.
7. **Remove stale pieces.** The old thin Cortex analyzer client and its image are no longer
   built by anything in the repository. Cortex's own analyzer catalog no longer lists an AI
   analyzer. If your Cortex still shows `AI_Mail_Analyzer`, or `docker images aimailanalyzer`
   shows an old self-contained image from before the thin client, it is a leftover: it does not call the server. The
   earlier stale-image incident (Cortex running an old self-contained analyzer for days while the
   server received no traffic) is the reason to check the request log of `ai_inference` rather
   than trust an AI result alone.
8. **Verify** with section 6, then replay a few historical campaigns (section 9).

## 11. Production hardening

- **No host port.** Keep `ai_inference` off the host. `/health` and `POST /reload` are
  unauthenticated by design; only the `/v2` routes check the token. Reach the server only from
  containers on `suspicious_net`. Do not add a `ports:` entry or a Traefik router for it.
- **Token.** Generate with `openssl rand -hex 24`. The server compares in constant time and fails
  closed when the variable is empty. Keep `.env` out of version control (it is git-ignored) and
  back it up with your other secrets.
- **Rotating the token.**
  1. Pick a quiet period. Between steps 2 and 3 classifications fail with 401 and count against the
     breaker.
  2. Set the new `AI_INFERENCE_TOKEN` in `deployment/.env`, then
     `docker compose --env-file .env --profile ai up -d --force-recreate --no-deps ai_inference`
     (or `make redeploy s=ai_inference`).
  3. Update the connector token (`settings.json` plus recreate of `suspicious`, `suspicious_celery`
     and `suspicious_celery_beat`, or the Settings tile when Vault is configured).
  4. `POST /api/connectors/ai_model/test/` must report `ready, token accepted`. If the breaker
     opened, reset it on the Settings card (Overview) or `POST /api/ai-model/breaker/reset/`.
  5. After a server recreate, expect `v0` for up to five minutes if a retrained version is active
     (section 8.3).
- **TLS.** The link between Celery and the server is plain http on a private bridge network and
  carries mail text and the bearer token. The shipped design relies on network isolation
  (`network-check` asserts membership). If your threat model requires encryption in transit, that
  is not provided by this repository; terminating TLS in front of `ai_inference` is untested, so
  validate it, including `AI_BUNDLE_HOSTS` and the connector `url`, before relying on it.
- **Resource limits.** Keep `mem_limit` (default 8g) and size it from `docker stats` during a real
  retrain. Keep `AI_TRAIN_THREADS` below the CPU count. The compose service sets no CPU limit; a
  future CPU limit needs its own server-thread setting, as the compose comment warns. The service
  has one uvicorn worker on purpose (job state lives in the process): never add `--workers`.
- **Training worker boundary.** The worker runs as the same user as the server but receives no
  token and no storage key; it is not a boundary against code execution inside it. Bundles are
  hash-pinned and read without pickle.
- **Image.** Runs as UID 10001, with `init: true` and `restart: unless-stopped`.
- **Hosts allow-list.** Keep `AI_BUNDLE_HOSTS` to the one object-store host.

## 12. Operating and monitoring

| What | How |
|---|---|
| Server up and ready | Container healthcheck (`make status`), `/health` (4.5) |
| Connector health | Settings tile, `POST /api/connectors/ai_model/test/`; Overview tab of the card |
| Per-mail outcomes | `GET /api/connectors/ai_model/deliveries/`, field `error` |
| Circuit breaker | The Overview tab of the card shows its state; `GET /api/connectors/` does not. Opens after five failures (`BREAKER_FAIL_MAX`); reset via the card or `POST /api/ai-model/breaker/reset/`; the published state updates only when a process makes a call |
| Registry vs server | Health detail `registry and server differ`; compare `GET /api/ai-model/status/` with `GET /v2/models/ai_mail` on the server |
| Model age | The card warns past 60 days; stats rebuilt daily |
| Retrain jobs | `ai_model_retrain --status`, `GET /api/ai-model/jobs/` |
| Labels | `GET /api/ai-model/ledger/` (counts, trainable, flagged, label-mix jump) and `/queue/` (disagreements, campaign conflicts) |
| Logs | `docker compose --env-file .env --profile ai logs -f ai_inference`; Celery: `make logs s=suspicious_celery`. Presigned URLs and query strings are redacted |
| Campaign detection | Celery log only |
| Tracing | Optional OpenTelemetry, see [Monitoring](../operations/monitoring.md) |

## 13. Backups

- **`Analyzers/AIMailAnalyzer/models/`**: git-ignored, with no public source. The version 0 weights
  and the baseline of the first retrain. Back it up with your other deployment files.
- **MariaDB** (`make backup-db`): the registry (`ModelVersion`, `ModelEvent`), the label ledger,
  `AiAssessment`, shadow results and retrain jobs.
- **RustFS buckets `ai-models`**: the bundles the registry points at. If they are lost, a
  reload of a retrained version fails and the registry cannot restore it; roll back to `v0` or
  retrain. `ai-datasets` holds transient exports and can be rebuilt from the ledger. Back up RustFS
  as in [Backups](../operations/backups.md).
- **ChromaDB** (`suspicious_mails`) is rebuildable as cases are processed.

## 14. Troubleshooting

The connector's errors are in the delivery `error` field; campaign detection errors are in the
Celery log. The longer table with more cases is [in the analyzers page](../components/analyzers.md#troubleshooting-inference-does-not-work).

| Symptom | Cause | Fix |
|---|---|---|
| Every mail case is `Inconclusive`, rule `analysis-incomplete` | `ai_model` is not enabled, or all calls fail | Enable it (5.2); check deliveries |
| Delivery `inference server unreachable: ...`, health `unreachable: <Error>` | Container not running, started without `--profile ai`, wrong `url`, not on `suspicious_net` | `make status`; start with the profile (4.3); `url` is `http://ai_inference:8090`; run the worker reach test (4.5); `make network-check` |
| `inference server rejected the token (HTTP 401)`, `token rejected (HTTP 401)` | Connector token differs from `AI_INFERENCE_TOKEN` | Align them; recreate the changed side; section 11 rotation |
| `HTTP 503: token not configured` | `AI_INFERENCE_TOKEN` empty on the server | Set it in `.env`; recreate `ai_inference` |
| connector error `ValueError: token not configured` | Connector `token` empty | Set it (5.1) |
| `HTTP 503: vectorizer unavailable` | Image built without the encoder weights (Hugging Face fetch failed behind a proxy) | Check build log and proxy; rebuild. `/health` names the error. `still loading` just means startup and is retried |
| `HTTP 503: models unavailable`, `/health` shows `ready: false` | `models/` empty, mount wrong, or a truncated `.pth` | Check the five files (3.1) and the bind mount; `POST /reload` after fixing |
| Server never becomes healthy after build | Cold encoder load takes time (start period 120 s) | Wait; read `/health` and the container log |
| `HTTP 404 ... has no /v2/... endpoint` | Old image, wrong `url` or a proxy | Rebuild the image; the stale image trap below |
| AI results look wrong or unchanged after an upgrade | A leftover `aimailanalyzer` image or Cortex analyzer from before the connector (an earlier incident: Cortex ran an old self-contained analyzer for days and the server received no traffic), or `aimailanalyzer-inference:local` not rebuilt | Section 10 step 7; rebuild with `make build`; confirm the request count in the `ai_inference` log rises per mail |
| Rows `Failure` with `CircuitBreakerError:` | Breaker open after five failures | Fix the cause first, then reset on the card or `POST /api/ai-model/breaker/reset/` |
| Row `Failure` after about 75 to 81 s | Server accepts the connection and hangs | Check server load and `INFERENCE_MAX_CONCURRENCY`, log, memory |
| `no model_version` on a row | The server refused one mail (400, 413, 422) or no readable text | Per-mail; no action unless frequent |
| `object store unavailable: <label>` | RustFS error while reading mail text | Check RustFS and `storage.s3` credentials |
| Verdicts do not change after copying new weights | Wrong mount, or file failed to load | `/health`, `POST /reload` |
| Retrain `Refused` or no rows | Connector off, no trainable rows, a head class under 8 rows, or a job already running | `ai_model_retrain --status`; section 8.1 |
| Retrain fails with `worker exited with code -9` | Out of memory | Raise `AI_INFERENCE_MEM_LIMIT`; record `docker stats` |
| Training or reload fails fetching or uploading | URL host not in `AI_BUNDLE_HOSTS`, or `storage.s3.endpoint` is not `rustfs:9000` | Align them (3.3); the error text omits the URL |
| `409` on `/v2/train`, `/v2/reload` | Another training job or reload is running on the server | Wait; check `GET /api/ai-model/jobs/` |
| Reload refused: "The inference server refused the change; it was reverted" | 4xx on reload: bundle hash, encoder change, token | Read the `ai_inference` log. After an `ENCODER_REVISION` change, old bundles are refused until retrained |
| `shadow/start/` answers `409` | Not a `candidate`, not eligible, another shadow, or the server refused the bundle (`shadow_refused`) | Discard the old shadow; read the server log |
| No shadow results accumulate | Connector off, server lacks the shadow, or `Busy`, `Skipped` or `Timeout` | See [shadow troubleshooting](../components/analyzers.md#troubleshooting-shadow-and-promotion); `AI_SHADOW_TIMEOUT` |
| Health says `registry and server differ` after a restart | The server restarted and serves `v0` | Wait up to five minutes for `ai-model-server-sync`, or run `ai_model.tasks.sync_server` |
| Label sync fails: `ImapLoginFailed`, `ImapTlsFailed`, `LabelSyncIncomplete` | Wrong credentials, CA not trusted, or no known folder name | 7; fix, then rerun |
| Campaign documents never cleaned up, health detail mentions a collection | `chromadb.collection_name` is `suspicious` | 5.4 |
| Campaign detection log `failed ... retrying` | ChromaDB down or the `campaign:detect` lock busy | Check `chromadb` |
| Shadow seeding stalls | Celery concurrency too low | `CELERY_CONCURRENCY` of 4 or more |

## 15. Tests

```bash
cd Analyzers/AIMailAnalyzer
pip install -r requirements-inference.txt pytest httpx
python -m pytest tests -v
```

Server tests are skipped where torch is absent. Backend: `python manage.py test ai_model connectors`
from `Suspicious/Suspicious` (where `manage.py` is) (or `docker compose --env-file .env run --rm --no-deps suspicious
python manage.py test`).

## Related

- [AI / ML Analyzers](../components/analyzers.md): full reference and runbook
- [Connectors](../components/backend/connectors.md)
- [Configuration](configuration.md) and `CONFIG.md`
- Design: [AI model connector spec](../specs/2026-10-30-ai-model-connector-design.md)
