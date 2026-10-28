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

## Source

| Module | Role |
|---|---|
| `ai_mail_classifier.py` | Thin Cortex client: untar mail, call the server, build the report |
| `inference_server/server.py` | FastAPI model server (`/classify`, `/health`, `/reload`) |
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
