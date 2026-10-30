# AI / ML Analyzers

`Analyzers/AIMailAnalyzer/` is the machine-learning email classifier exposed to
the platform as a Cortex analyzer.

## How it works

- **Embeddings:** a Sentence Transformers model
  (`paraphrase-multilingual-mpnet-base-v2`) turns email text into vectors.
- **Classifier:** an ensemble of custom `ResNetMLP` networks (several 2-class
  models plus a 4-class danger model) predicts the verdict from the embeddings.
- **Similarity:** ChromaDB stores vectors so finalised cases can be matched
  against prior cases for semantic similarity.

## Architecture: thin Cortex client + persistent inference server

Cortex starts every analyzer in a fresh, one-shot container. Loading a
sentence-transformer and five classifier checkpoints on every mail would
dominate the run time, so the model work lives in a long-running service and
the analyzer is only a client:

```
 Cortex job container (default bridge)          ai_inference container
 ┌─────────────────────────────────┐  POST   ┌──────────────────────────────┐
 │ ai_mail_classifier.py           │ /classify│ inference_server/server.py   │
 │  untar mail → body              │ ───────► │  vectorizer + models in RAM  │
 │  build Cortex report from JSON  │ ◄─────── │  models/ + models_public/    │
 └─────────────────────────────────┘          └──────────────────────────────┘
        http://172.17.0.1:8090  (default-bridge gateway = docker0 on the host)
```

- **Why the gateway IP.** Cortex runs job containers on Docker's *default*
  bridge, which has no DNS and is not `suspicious_net`, so the service name
  `ai_inference` does not resolve there. The compose service publishes its port on
  the gateway address (`AI_INFERENCE_BIND`, default `172.17.0.1`; check with
  `docker network inspect bridge`). Publishing on `127.0.0.1` would not work:
  loopback is not reachable from another container.
- **Variants.** `personal` (`models/`, your own trained weights) drives the case
  verdict. `public` (`models_public/`) is a comparison set and stays unavailable until
  weights are dropped in. Select with the analyzer's `variant` config item.
- **Weights.** Bind-mounted read-only, not baked into the image. The server
  re-checks them every `INFERENCE_RELOAD_CHECK_SECONDS` (30) and hot-swaps changed
  files; `POST /reload` does it immediately. A file that fails to load never replaces a
  working model, so the retrain pipeline can overwrite `models/*.pth` in place.
- **Readiness.** `GET /health` is `200` only when the vectorizer and the five
  `personal` models (four required plus the optional `unwanted_*`) are loaded;
  otherwise `503` with the per-file load error. The client retries `502/503/504` and connection errors, and reports the
  server's own reason in the Cortex error message.

### Deploying

```bash
# 1. put the trained weights where the container mounts them
ls Analyzers/AIMailAnalyzer/models/*_30_epochs_model.pth     # 5 files
# 2. build + start (the Makefile enables the `ai` compose profile; `make build` and
#    `make deploy` also rebuild the aimailanalyzer:local image Cortex runs)
cd deployment && make build && make up
# 3. check from where Cortex runs analyzers (the default bridge)
curl -s http://172.17.0.1:8090/health | python3 -m json.tool
docker run --rm --entrypoint python aimailanalyzer:local AIMailAnalyzer/health.py --require-server
```

Plain compose users add the profile: `docker compose --profile ai up -d`.

### Troubleshooting "inference does not work"

| Symptom (Cortex job error) | Cause / fix |
|---|---|
| `cannot reach inference server at http://172.17.0.1:8090` | Server not running, or published on `127.0.0.1`, or the bridge gateway differs. `docker ps`, `docker network inspect bridge`, then set `AI_INFERENCE_BIND` and the analyzer's `inference_url`. |
| `HTTP 503 … Vectorizer unavailable` | The inference image was built without the vectorizer weights (the build fetches them from Hugging Face; check the build log / proxy). `/health` shows the exact error. |
| `HTTP 503 … Required models unavailable for variant 'personal'` | `Analyzers/AIMailAnalyzer/models/` is empty or has a corrupt/truncated `.pth`; `/health` lists which file and why. |
| `HTTP 503 … variant 'public'` | Expected until real public weights are added to `models_public/`. |
| Verdicts never change after retraining | Weights were baked into an old image instead of mounted, or the mount is not `models/`. Check `/health`, then `POST /reload`. |
| Works from the host, fails from Cortex | A corporate `HTTP(S)_PROXY` inside the job container: the client bypasses proxies by default (`INFERENCE_USE_PROXY=1` re-enables). |
| `401` or `503` on `/v2` (the `ai_model` connector row fails) | From a container on `suspicious_net`, run `curl -H "Authorization: Bearer $AI_INFERENCE_TOKEN" http://ai_inference:8090/v2/models/ai_mail`. `401` = wrong token: the connector's `token` differs from the server's `AI_INFERENCE_TOKEN`. `503` on this route = `AI_INFERENCE_TOKEN` is not set on the server (`token not configured`); set it in `deployment/.env` and recreate `ai_inference`. A `503` on classify that names the models or vectorizer is a loading problem, not a token one: check `curl http://ai_inference:8090/v2/health/ready` (no token needed) and the `detail` in the delivery error. A server `503` shows in the delivery `error` as `inference server HTTP 503: <detail>`; the connector's own empty `token` fails before any call, as `ValueError: token not configured`. |
| Delivery `error` `inference server unreachable: ...` (the `ai_model` connector row fails) | The worker cannot reach the server. Check that `ai_inference` is up on `suspicious_net` (it runs under the `ai` profile) and that the connector `url` is `http://ai_inference:8090`. The `172.17.0.1` gateway address above is only for Cortex job containers. |

## v2 API and the ai_model connector

The inference server has a second, token-protected API under `/v2`, next to the legacy `/classify`,
`/health` and `/reload` routes (those are unchanged and still serve the Cortex analyzer). The
`ai_model` connector uses it so the AI verdict can come from the platform, with no Cortex job.

| Route | Token | What it does |
|---|---|---|
| `GET /v2/health/live` | no | `{"live": true}` while the process is up. |
| `GET /v2/health/ready` | no | The same body as `/health`: `200` when the vectorizer and the `personal` models are loaded, otherwise `503`. |
| `GET /v2/models/ai_mail` | yes | Model metadata: the versions the server holds. Today one, `active` (id `v0`), the legacy classifier. |
| `POST /v2/models/ai_mail/classify` | yes | Body `{"mail_body": "...", "versions": ["active"]}`. Returns the verdict under `results.active` (class, score, confidence, class and sub-class probabilities, contributing phrases) plus the campaign embedding, its version and the latency. `400` for any other `versions`, `503` when models or vectorizer are not loaded. |

### The token

The server reads `AI_INFERENCE_TOKEN` from its environment (`deployment/.env`, passed to the
`ai_inference` service by compose). The `/v2` routes that need a token fail closed: with the variable
unset or empty they answer `503 token not configured`, they never run unauthenticated. A missing or
wrong `Authorization: Bearer ...` header answers `401`. Generate one with `openssl rand -hex 24`.

### Enabling the connector

1. Set `AI_INFERENCE_TOKEN` in `deployment/.env` and recreate `ai_inference`.
2. Put the same value in the connector's `token` (Settings, or `integrations.ai_model.token` in
   `settings.json`). `url` defaults to `http://ai_inference:8090` and `timeout_seconds` to 20.
3. Enable `ai_model` in Settings, or `PATCH /api/connectors/ai_model/` with `{"enabled": true}`. It is off by
   default.

Only one connector may provide `mail_ai` at a time. Enabling a second answers `409`
(`<name> already provides mail_ai`); disable the first one before enabling the other.

With the connector enabled, a mail's AI verdict comes from it and the Cortex AI job is not created. The
AI analyzer gets a ledger row (`CaseAnalyzerJob`) with a `provider-` id instead of a Cortex job id. The
Celery worker (`suspicious_celery`) reads the mail text from the object store first: the mail's `.txt`
and `.headers` objects, under `<mail_id>/` in the submission's own bucket, or under
`<submission_id>/<mail_id>/` in the feeder bucket (`storage.s3.feeder_bucket`) when the submission came
through the prefix layout. It starts there because the e-mail fetch task deletes the working directory
that holds the submission's archive shortly after the handoff, so a retry would no longer find
it. The archive on the shared volume (`mail_case_data` and `mail_work_data`, mounted in both
`suspicious` and `suspicious_celery`) is the fallback, used when the store has no text for the mail. The
worker then posts the body to `/v2/models/ai_mail/classify` over `suspicious_net`, stores the answer as
one `AiAssessment` per case (with the model version, `v0` today), fills the case's AI result, score,
confidence and category, closes the row and queues the case's reconcile. With the connector disabled
nothing changes: the Cortex `AI_Mail_Analyzer` runs as before.

**Keep it disabled in production for now.** Campaign detection and the case view's AI analyzer card
read the Cortex AI analyzer's report (an `AnalyzerReport`), and the connector does not create one. So
for every case analysed while `ai_model` is enabled:

- no campaign is created or joined, no `campaign_updated` event is sent, and TheHive raises no
  campaign alert;
- the mail is not added to the ChromaDB collection that later detection compares new mails against,
  so it stays missing as a neighbour even after the connector is disabled again;
- the case view shows no AI analyzer card. The AI result in the overview still shows, because it
  comes from the case's own fields.

This lasts until campaign detection moves into the connector and the case view gets its AI section,
both in a later change.

### When it fails

- **Where to look.** When the task fails a row, the reason is recorded in the row's `ConnectorDelivery`
  entry (event `analyze`, status `failed`, field `error`), listed by
  `GET /api/connectors/ai_model/deliveries/`.
- **Server unreachable, timeout or 5xx.** The task retries twice, after a wait of 5 s plus up to 3 s of
  jitter and then 10 s plus up to 3 s. `timeout_seconds` (20 s) is the socket timeout of the HTTP call:
  it applies to each connect and each read, not to the whole call. A server that accepts the connection
  and then hangs closes the row as `Failure` after roughly 75 to 81 seconds (three attempts of 20 s plus
  the two waits). A server that sends bytes slowly can take longer, because the read timeout starts
  again after each chunk. A stopped or refusing server fails each attempt at once, so the row closes
  after the two waits alone, about 15 to 21 seconds (6.0 s and 11.3 s in a live drill). The case gets
  `results_ai = Inconclusive` and still finalises.
- **Repeated failures** open the connector's circuit breaker. `GET /api/connectors/` does not report it:
  the breaker lives in the Celery worker process. Its effect shows on the rows. While it is open, new
  rows fail at once without calling the server, and their delivery `error` starts with
  `CircuitBreakerError:` followed by the breaker's own message.
- **A rejected token (`401` or `403`)**, a wrong url (`404`), a proxy, timeout or rate-limit answer
  (`407`, `408`, `429`), and a `503` that says the token, models or vectorizer are missing, fail the row at once, without
  retries. They are setup errors that every case would hit, so they show as a `Failure` row and count
  against the breaker. They are never turned into a quiet `Inconclusive` success.
- **A refusal of one mail (`400`, `413`, `422`)** is a verdict of "cannot tell": the row closes as
  `Success` with an `Inconclusive` result. A mail with no readable text, in the store or in the archive,
  ends the same way.
- **Object store down.** If the store errors (not "not found") and the archive cannot stand in, the row
  closes as `Failure`. An `access_denied` or `invalid` error fails it at once, without retries;
  `unavailable` and any other error are first retried twice like a server outage. The delivery `error` reads
  `object store unavailable: <label>`, where the label is the store's error code (for example
  `unavailable` or `access_denied`) or, for any other error such as a configuration problem, the
  exception class name. It is not turned into an `Inconclusive` success.

## Source

| Module | Role |
|---|---|
| `ai_mail_classifier.py` | Thin Cortex client: untar mail, call the server, build the report |
| `inference_server/server.py` | FastAPI model server (`/classify`, `/health`, `/reload`) |
| `inference_server/v2.py`, `auth.py` | Token-protected `/v2` router and its bearer check |
| `mail_analysis.py` | Classification maths, taxonomy, explainability (needs numpy/torch) |
| `mail_archive.py` | Safe mail-archive extraction (stdlib only, used by the client) |
| `ResNetMLP.py` | The neural network definition |
| `health.py` | Client-image probe; `--require-server` also checks the server |

### Tests

```bash
cd Analyzers/AIMailAnalyzer
pip install -r requirements-inference.txt pytest httpx
python -m pytest tests -v
```

`tests/test_client.py` needs only `requirements-client.txt`; the server tests are skipped where torch is
absent. They use real `ResNetMLP` checkpoints written to a temp dir and a fake
sentence-transformer.

These modules are auto-documented in the
[Python Code Reference](../reference/index.md).
