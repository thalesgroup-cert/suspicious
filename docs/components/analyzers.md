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
| `GET /v2/models/ai_mail` | yes | Model metadata: the versions the server holds. Today one, `active` (id `v0`), the legacy classifier. |
| `POST /v2/models/ai_mail/classify` | yes | Body `{"mail_body": "...", "versions": ["active"]}`. Returns the verdict under `results.active` (class, score, confidence, class and sub-class probabilities, contributing phrases) plus the campaign embedding, its version and the latency. `400` for any other `versions`, `503` when models or vectorizer are not loaded. |

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

**The case view has no AI assessment section yet.** The AI analyzer card reads the Cortex AI
analyzer's report (an `AnalyzerReport`), and the connector does not create one, so it stays empty
for new cases. The AI result in the overview still shows, because it comes from the case's own
fields. The case view gets its AI section in a later change.

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

## Source

| Module | Role |
|---|---|
| `inference_server/server.py` | FastAPI model server (`/health`, `/reload`; mounts `/v2`) |
| `inference_server/v2.py`, `auth.py` | Token-protected `/v2` router and its bearer check |
| `mail_analysis.py` | Classification maths, taxonomy, explainability (needs numpy/torch) |
| `mail_archive.py` | Safe mail-archive extraction (stdlib only), re-exported by `mail_analysis.py` |
| `ResNetMLP.py` | The neural network definition |

The connector lives in the backend: `Suspicious/Suspicious/connectors/contrib/ai_model/`
(`connector.py`, `client.py`, `campaigns.py`, `mailtext.py`), and the replay command in
`Suspicious/Suspicious/ai_model/management/commands/ai_model_campaign_replay.py`.

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
