# AI Model Connector, Plan A: Provider Slot, Server v2 and Version 0

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** With the `ai_model` connector enabled, new mail cases get their AI result from the inference server through a provider slot in the case pipeline, using today's weights as version 0, with the same class, score, confidence and sub-class the Cortex job produced.

**Architecture:** The connector framework gains a `provides` kind. The single Cortex launch point (`CortexJob.launch_cortex_ai_jobs`) hands the case to the enabled `mail_ai` provider instead of launching a Cortex job, and creates a pending `CaseAnalyzerJob` for the existing AI `Analyzer` row, so `reconcile_case_core` waits for it exactly as it waits for a Cortex job. A Celery task calls the connector, writes the legacy `Case` fields and a new `AiAssessment` row, closes the ledger row and enqueues `reconcile_case`. The inference server gains a token-protected `/v2` API beside the legacy `/classify`, which stays until Plan B.

**Tech Stack:** Django, Celery, pybreaker (`common.http_client`), FastAPI, torch, pytest.

**Spec:** `docs/specs/2026-10-30-ai-model-connector-design.md` (sections 1, 2, the version 0 paragraph of 3, 9, 11 step 2). Master plan: `docs/plans/2026-10-30-ai-model-connector.md`.

## Global Constraints

- One HTTP call to the model server has a total timeout of 20 seconds. Retry only transient errors, at most 2 times, exponential backoff with jitter (5 s, then 10 s, plus up to 3 s). A 4xx answer and a "model not ready" answer are not retried. Worst case is about 75 seconds; the case must not wait longer for the AI step.
- `run_provider_analysis` is declared with `acks_late=True` and `reject_on_worker_lost=True` and is idempotent.
- Case fields are written exactly as today: `results_ai` = class capitalised (`"Dangerous"`), `score_ai = round(malscore)`, `confidence_ai = round(confidence * 100)`, `category_ai` = sub-class capitalised and cut to `Case._meta.get_field("category_ai").max_length`, and the `MailInfo` flags as `update_mail_models` sets them.
- On failure only `results_ai = "Inconclusive"` is written, the ledger row closes as `Failure`, and a `ConnectorDelivery` row records why.
- The legacy `/classify` endpoint and the Cortex AI path keep working for instances that do not enable the connector.
- At most one enabled connector may provide a given kind.
- The `/v2` routes other than `/v2/health/live` and `/v2/health/ready` require `Authorization: Bearer <AI_INFERENCE_TOKEN>`; with no token configured they answer 503 (fail closed).
- Campaign embedding version name: `cmp-e1`. The campaign embedding is the legacy `email_embedding` string, unchanged.
- Repository conventions: Conventional Commits, subject at most 72 characters, body lines at most 100, no `Co-Authored-By` trailer; one `CHANGELOG.md` entry under `[Unreleased]`; nothing is pushed.
- Test commands: backend `ww test backend <label>`; inference server `cd Analyzers/AIMailAnalyzer && python -m pytest tests/<file> -v`.

## Review Focus

- A mail whose archive has no `.txt` or `.headers` member, or whose body is empty or whitespace: the result is Inconclusive, the ledger row closes, the case finalises (Task 6).
- A body of 100,000+ characters or obfuscated unicode: truncated to `MAX_MAIL_CHARS`, never a 500 (Task 2).
- The task is delivered twice, or the worker dies and it is redelivered: one assessment, one closed row, one reconcile (Task 5).
- The connector is disabled, or the token is wrong, while a job is pending: the row closes as failure at once and the case does not wait for the 2-hour stale timeout (Task 5).
- A second `mail_ai` provider is enabled, or the provider is enabled while legacy Cortex AI jobs are in flight: refused with 409, and in-flight legacy cases are still copied by `manage_ai_jobs` (Tasks 4 and 5).

## File structure

Create:
- `Analyzers/AIMailAnalyzer/inference_server/auth.py`: bearer-token dependency.
- `Analyzers/AIMailAnalyzer/inference_server/v2.py`: `make_v2_router(...)`.
- `Suspicious/Suspicious/ai_model/` (`__init__.py`, `apps.py`, `models.py`, `mailinfo.py`, `migrations/0001_initial.py`, `tests/`): the new app.
- `Suspicious/Suspicious/connectors/providers.py`: queue, finish, errors.
- `Suspicious/Suspicious/connectors/contrib/ai_model/` (`__init__.py`, `connector.py`, `client.py`, `mailtext.py`, `tests/`).

Modify: `inference_server/server.py`, `connectors/base.py`, `connectors/registry.py`, `connectors/tasks.py`, `connectors/contrib/__init__.py`, `connectors/tests/dummy.py`, `api/views/connectors.py`, `cortex_job/cortex_utils/cortex_and_job_management.py`, `suspicious/settings.py`, `deployment/compose_apps.yaml`, `deployment/.env.example`, `docs/getting-started/examples/Suspicious-settings.example.json`, `docs/components/analyzers.md`, `CHANGELOG.md`.

Paths below are relative to `Suspicious/Suspicious/` unless they start with `Analyzers/`, `deployment/` or `docs/`.

---

### Task 1: Server v2 health, metadata and token

**Files:**
- Create: `Analyzers/AIMailAnalyzer/inference_server/auth.py`, `Analyzers/AIMailAnalyzer/inference_server/v2.py`
- Modify: `Analyzers/AIMailAnalyzer/inference_server/server.py` (include the router after `app = FastAPI(...)`)
- Test: `Analyzers/AIMailAnalyzer/tests/test_inference_server_v2.py`

**Interfaces:**
- Produces `auth.require_token(authorization: str | None = Header(None)) -> None`: 503 `{"detail": "token not configured"}` when env `AI_INFERENCE_TOKEN` is empty; 401 on a missing or wrong bearer; compares with `secrets.compare_digest`.
- Produces `v2.make_v2_router(*, store, classify, slots, max_chars) -> APIRouter` (Task 2 adds the classify route to it; `classify` is `server._classify`, `slots` is `server._inference_slots`).
- Produces `GET /v2/health/live` (no auth) `{"live": true}`; `GET /v2/health/ready` (no auth), 200 with `{"ready": true}` merged with the existing `_health_payload()`, or 503 with the same body when not ready; `GET /v2/models/ai_mail` (auth) returning `{"name": "ai_mail", "versions": {"active": {"id": "v0", "preprocessing": "legacy-first128", "campaign_embedding_version": "cmp-e1", "calibrated": false}}}`.

- [ ] **Step 1: Write the failing tests.** Reuse the weight-writing and `FakeVectorizer` helpers of `tests/test_inference_server.py` (import them; if they are not importable, move them unchanged to `tests/conftest.py`). Tests:

```python
def test_live_needs_no_token(client):
    assert client.get("/v2/health/live").json() == {"live": True}

def test_metadata_is_401_without_or_with_a_wrong_token(client, token_env):
    assert client.get("/v2/models/ai_mail").status_code == 401
    assert client.get("/v2/models/ai_mail", headers={"Authorization": "Bearer nope"}).status_code == 401

def test_metadata_with_token(client, token_env):
    body = client.get("/v2/models/ai_mail", headers=token_env).json()
    assert body["versions"]["active"] == {"id": "v0", "preprocessing": "legacy-first128",
                                          "campaign_embedding_version": "cmp-e1", "calibrated": False}

def test_authed_routes_fail_closed_when_no_token_is_configured(client, monkeypatch):
    monkeypatch.delenv("AI_INFERENCE_TOKEN", raising=False)
    assert client.get("/v2/models/ai_mail", headers={"Authorization": "Bearer x"}).status_code == 503

def test_ready_is_503_until_the_models_are_loaded(client_without_models):
    assert client_without_models.get("/v2/health/ready").status_code == 503
```

- [ ] **Step 2: Run to verify they fail.** Run: `cd Analyzers/AIMailAnalyzer && python -m pytest tests/test_inference_server_v2.py -v`. Expected: FAIL with 404 on `/v2/...`.
- [ ] **Step 3: Implement** `auth.require_token`, `v2.make_v2_router` with the three routes, and the `include_router` call in `server.py`. The ready route reuses `server._health_payload()` through the `store` argument.
- [ ] **Step 4: Run the new file and `tests/test_inference_server.py`.** Expected: all PASS (the legacy routes are untouched).
- [ ] **Step 5: Commit**

```bash
git add Analyzers/AIMailAnalyzer/inference_server Analyzers/AIMailAnalyzer/tests
git commit -m "feat(ai-inference): v2 health, metadata and bearer token"
```

### Task 2: Server v2 classify (version 0)

**Files:**
- Modify: `Analyzers/AIMailAnalyzer/inference_server/v2.py`, `server.py` (pass the dependencies)
- Test: `Analyzers/AIMailAnalyzer/tests/test_inference_server_v2.py`

**Interfaces:**
- Consumes: `make_v2_router` and `require_token` (Task 1).
- Produces `POST /v2/models/ai_mail/classify` (auth). Request `{"mail_body": str, "versions": ["active"]}`. Response:

```json
{"results": {"active": {"version": "v0", "class": "DANGEROUS", "score": 7.4, "confidence": 0.81,
  "probabilities": {"SAFE": 0.1, "UNWANTED": 0.09, "DANGEROUS": 0.81},
  "sub_class": "CLASSIC_PHISHING", "sub_class_confidence": 0.6, "sub_probabilities": {},
  "contributing_phrases": [], "tier": null, "similar_cases": []}},
 "campaign_embedding": "[0.1, ...]", "campaign_embedding_version": "cmp-e1", "latency_ms": 12}
```

  Mapping from the legacy `_classify` dict: `classification`→`class`, `malscore`→`score` (float), `confidence`→`confidence` (float), `classification_breakdown`→`probabilities`, `sub_classification`→`sub_class`, `sub_classification_confidence`→`sub_class_confidence` (float), `sub_classification_breakdown`→`sub_probabilities`, `contributing_phrases` unchanged, `email_embedding`→`campaign_embedding`. Any `versions` other than `["active"]` answers 400. Models or vectorizer missing answers 503 with the legacy detail text. The body is cut to `max_chars`.

- [ ] **Step 1: Write the failing tests**

```python
def test_v2_classify_matches_the_legacy_endpoint(client, token_env):
    legacy = client.post("/classify", json={"mail_body": BODY}).json()
    new = client.post("/v2/models/ai_mail/classify", json={"mail_body": BODY, "versions": ["active"]}, headers=token_env).json()
    r = new["results"]["active"]
    assert r["class"] == legacy["classification"] and r["score"] == float(legacy["malscore"])
    assert r["confidence"] == float(legacy["confidence"]) and r["sub_class"] == legacy["sub_classification"]
    assert new["campaign_embedding"] == legacy["email_embedding"]

def test_v0_has_no_tier_and_no_similar_cases(client, token_env):
    r = post_v2(client, token_env)["results"]["active"]
    assert r["tier"] is None and r["similar_cases"] == [] and r["version"] == "v0"

def test_unknown_version_is_400(client, token_env):
    assert post_v2(client, token_env, versions=["shadow"], raw=True).status_code == 400

def test_a_body_far_over_max_chars_is_truncated_not_rejected(client, token_env):
    assert post_v2(client, token_env, body="x " * server.MAX_MAIL_CHARS, raw=True).status_code == 200

def test_503_when_models_are_missing(client_without_models, token_env): ...
```

- [ ] **Step 2: Run to verify they fail.** Expected: 404 on the classify route.
- [ ] **Step 3: Implement the route in `v2.py`**, calling the injected `classify` inside `with slots:` after `store.maybe_refresh()` and the same missing-model checks as `/classify`; time it for `latency_ms`.
- [ ] **Step 4: Run the file.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(ai-inference): v2 classify returning the version 0 result`.

### Task 3: `ai_model` app and `AiAssessment`

**Files:**
- Create: `ai_model/__init__.py`, `ai_model/apps.py` (`AiModelConfig`), `ai_model/models.py`, `ai_model/mailinfo.py`, `ai_model/migrations/0001_initial.py` (generated), `ai_model/tests/__init__.py`, `ai_model/tests/test_models.py`, `ai_model/tests/test_mailinfo.py`
- Modify: `suspicious/settings.py` (add `"ai_model.apps.AiModelConfig"` to `INSTALLED_APPS` after `connectors`), `cortex_job/cortex_utils/cortex_and_job_management.py` (`update_mail_models` delegates)

**Interfaces:**
- Produces `ai_model.models.AiAssessment`: `case` (OneToOneField to `case_handler.Case`, `related_name="ai_assessment"`, CASCADE), `model_version` (Char 32), `result` (Char 20, one of `SAFE`, `UNWANTED`, `DANGEROUS`, `INCONCLUSIVE`), `sub_class` (Char 32, blank), `score` (Float), `confidence` (Float, percent as in `Case.confidence_ai`), `probabilities` (JSON dict), `sub_probabilities` (JSON dict), `tier` (Char 8, blank), `contributing_phrases` (JSON list), `similar_cases` (JSON list), `campaign_embedding` (Text, blank), `embedding_version` (Char 16, default `"cmp-e1"`), `latency_ms` (PositiveInteger, default 0), `created_at`, `updated_at`.
- Produces `ai_model.mailinfo.apply_mail_info(mail_info, category: str, result: str) -> None` with the exact behaviour of today's `CortexJobManager.update_mail_models(mail_info, classification, sub_classification)` (`category` is `category_ai`, `result` is `results_ai`).

- [ ] **Step 1: Write the failing tests**

```python
def test_one_assessment_per_case(self):
    AiAssessment.objects.create(case=self.case, model_version="v0", result="SAFE", score=1, confidence=90)
    with self.assertRaises(IntegrityError):
        AiAssessment.objects.create(case=self.case, model_version="v0", result="SAFE", score=1, confidence=90)

def test_defaults(self):
    a = AiAssessment.objects.create(case=self.case, model_version="v0", result="SAFE", score=1, confidence=90)
    self.assertEqual((a.tier, a.embedding_version, a.probabilities, a.similar_cases), ("", "cmp-e1", {}, []))

def test_deleting_the_case_deletes_the_assessment(self): ...
def test_classic_phishing_sets_is_phishing(self):
    apply_mail_info(mail_info, "Classic_phishing", "Dangerous")
    self.assertTrue(mail_info.is_phishing and mail_info.is_dangerous and mail_info.is_analyzed)
```

  Port the cases of any existing `update_mail_models` tests (search `grep -rn update_mail_models --include=test*.py`) into `test_mailinfo.py` and keep them passing against the delegate.
- [ ] **Step 2: Run to verify they fail.** Run: `ww test backend ai_model`. Expected: FAIL (module missing).
- [ ] **Step 3: Implement the app and model; generate the migration** with `makemigrations ai_model`; move the body of `update_mail_models` into `apply_mail_info` and make the method call it.
- [ ] **Step 4: Run** `ww test backend ai_model cortex_job` and `makemigrations --check --dry-run`. Expected: PASS, no pending migrations.
- [ ] **Step 5: Commit** `feat(ai-model): AiAssessment model and shared mail-info helper`.

### Task 4: Provider extension point

**Files:**
- Modify: `connectors/base.py`, `connectors/registry.py`, `api/views/connectors.py`, `connectors/tests/dummy.py`
- Create: `connectors/providers.py` (only `enabled_provider` in this task)
- Test: `connectors/tests/test_providers.py`

**Interfaces:**
- Produces in `connectors/base.py`: `PROVIDER_KIND_MAIL_AI = "mail_ai"`, `VALID_PROVIDER_KINDS = frozenset({"mail_ai"})`, a new field `ConnectorManifest.provides: str = ""` (validated: empty or in `VALID_PROVIDER_KINDS`), and

```python
@dataclass(frozen=True)
class ProviderResult:
    result: str            # SAFE | UNWANTED | DANGEROUS | INCONCLUSIVE
    score: float           # as Case.score_ai stores it (already rounded)
    confidence: float      # percent, as Case.confidence_ai stores it
    category: str          # as Case.category_ai stores it
    model_version: str
    assessment: dict       # remaining AiAssessment fields; keys are the model's field names
    reason: str = ""       # why, when result is INCONCLUSIVE
```

  and `Connector.analyze(self, kind: str, case_id: int) -> ProviderResult` raising `NotImplementedError` by default.
- Produces `ConnectorRegistry.providers(kind: str) -> list[str]` (registered names whose manifest `provides == kind`) and `connectors.providers.enabled_provider(kind: str) -> str | None` (the single enabled one).
- Produces `DummyProviderConnector` in `connectors/tests/dummy.py` (manifest `name="dummy_provider"`, `provides="mail_ai"`; class attributes `result: ProviderResult | None` and `error: Exception | None` control `analyze`).

- [ ] **Step 1: Write the failing tests**

```python
def test_unknown_provides_fails_validation(self):
    with self.assertRaises(ValueError):
        ConnectorManifest(name="x1", version="1", provides="nope").validate()

def test_enabled_provider_is_none_unless_enabled(self): ...      # disabled -> None; enabled -> "dummy_provider"
def test_enabling_a_second_provider_of_the_same_kind_is_409(self):
    # two dummy providers registered, first enabled, PATCH the second -> 409 and still disabled
def test_disabling_and_enabling_the_same_provider_is_fine(self): ...
```

- [ ] **Step 2: Run to verify they fail.** Run: `ww test backend connectors.tests.test_providers`. Expected: FAIL.
- [ ] **Step 3: Implement** the manifest field and validation, `ProviderResult`, `Connector.analyze`, `registry.providers`, `enabled_provider` (uses `get_state(name).enabled`), and in `ConnectorStateView.patch` a 409 `{"detail": "<name> already provides <kind>"}` when enabling while another enabled connector provides the same kind.
- [ ] **Step 4: Run** `ww test backend connectors`. Expected: PASS, no regression in existing connector tests.
- [ ] **Step 5: Commit** `feat(connectors): provider extension point for the mail_ai kind`.

### Task 5: Provider dispatch, ledger row and Celery task

**Files:**
- Modify: `connectors/providers.py`, `connectors/tasks.py`, `cortex_job/cortex_utils/cortex_and_job_management.py` (`launch_cortex_ai_jobs`, `manage_ai_jobs`)
- Test: `connectors/tests/test_provider_dispatch.py`

**Interfaces:**
- Consumes: `ProviderResult`, `enabled_provider`, `Connector.analyze` (Task 4); `AiAssessment`, `apply_mail_info` (Task 3).
- Produces in `connectors/providers.py`:

```python
class ProviderUnavailable(Exception):
    def __init__(self, message: str, retryable: bool = True) -> None: ...
def queue_provider_analysis(case, kind: str) -> "CaseAnalyzerJob | None"
def finish_provider_analysis(job_id: int, result: "ProviderResult | None", *, error: str = "", attempt: int = 1, duration_ms: int = 0) -> bool
def has_provider_job(case) -> bool
```

  `queue_provider_analysis` returns `None` when no provider is enabled; otherwise it creates `CaseAnalyzerJob(case, cortex_job_id="provider-" + uuid4().hex[:30], analyzer=<AI Analyzer>, status=InProgress)` and enqueues the task on commit. The AI analyzer row is `Analyzer.objects.get_or_create(name=_get_cortex_config()["analyzers"]["ai"], defaults={"analyzer_cortex_id": "provider:" + name})`. `finish_provider_analysis` returns `False` and does nothing if the row is no longer pending; otherwise it writes the `Case` fields (see Global Constraints), upserts the `AiAssessment` from `result.assessment`, applies `apply_mail_info`, sets the row `Success` or `Failure` with `completed_at`, writes a `ConnectorDelivery` row (`event="analyze"`, `error` holds `result.reason` or the failure text), then `tasp.tasks.reconcile_case.delay(case_id)`.
- Produces in `connectors/tasks.py`: `run_provider_analysis(self, case_id: int, kind: str, job_id: int)`, `@shared_task(bind=True, acks_late=True, reject_on_worker_lost=True, max_retries=2)`. It finishes as failure at once if the provider is no longer enabled, or if `get_breaker(name)` is open (`pybreaker.CircuitBreakerError`). It runs `connector.analyze` inside `with breaker.calling():`. `ProviderUnavailable(retryable=True)` retries with countdown `5 * 2 ** self.request.retries + random.uniform(0, 3)`; with `retryable=False`, or after the last retry, it finishes as failure.

- [ ] **Step 1: Write the failing tests** (use `DummyProviderConnector`; patch `connectors.providers.registry` and the task's registry as `test_dispatch.py` does):

```python
def test_queue_creates_a_pending_row_for_the_ai_analyzer(self):
    job = queue_provider_analysis(self.case, "mail_ai")
    self.assertEqual((job.status, job.analyzer.name), ("InProgress", AI_NAME))
    self.assertTrue(job.cortex_job_id.startswith("provider-"))

def test_queue_returns_none_without_an_enabled_provider(self): ...
def test_launch_cortex_ai_jobs_hands_over_and_calls_no_cortex_api(self): ...   # mock CortexJob.run; assert not called
def test_task_writes_case_fields_assessment_and_closes_the_row(self):
    # ProviderResult("DANGEROUS", 7, 81, "Classic_phishing", "v0", {"sub_class": "CLASSIC_PHISHING"})
    # -> case.results_ai == "Dangerous", score_ai == 7, confidence_ai == 81, category_ai == "Classic_phishing";
    #    AiAssessment.model_version == "v0"; row.status == "Success" and completed_at set; reconcile_case.delay called once
def test_unavailable_after_retries_marks_inconclusive_and_the_row_failed(self): ...
def test_not_retryable_unavailable_fails_without_retrying(self): ...
def test_redelivery_of_a_closed_job_is_a_no_op(self):
    run(...); run(...)    # second call: no second ConnectorDelivery, reconcile_case.delay called once
def test_open_breaker_fails_fast(self): ...
def test_disabled_provider_closes_the_row_as_failure(self): ...
def test_manage_ai_jobs_skips_cases_with_a_provider_job_but_still_handles_legacy_cases(self): ...
def test_reconcile_waits_for_the_provider_row_then_finalises(self):
    # reconcile_case_core leaves a case with a pending provider row in ANALYZING;
    # after finish_provider_analysis it can finalise
```

- [ ] **Step 2: Run to verify they fail.** Run: `ww test backend connectors.tests.test_provider_dispatch`. Expected: FAIL.
- [ ] **Step 3: Implement** the functions and task as specified. In `launch_cortex_ai_jobs`, call `queue_provider_analysis(case, "mail_ai")` first and return `None` when it returns a job. In `manage_ai_jobs`, return early when `has_provider_job(case)`. `update_single_job` already returns for rows without an `analyzer_report`; leave it.
- [ ] **Step 4: Run** `ww test backend connectors cortex_job ai_model tasp`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(connectors): run mail_ai through a provider with a ledger row`.

### Task 6: The `ai_model` connector

**Files:**
- Create: `connectors/contrib/ai_model/__init__.py`, `connector.py`, `client.py`, `mailtext.py`, `tests/__init__.py`, `tests/test_connector.py`, `tests/test_client.py`, `tests/test_mailtext.py`
- Modify: `connectors/contrib/__init__.py` (append `"connectors.contrib.ai_model.connector:AiModelConnector"`)

**Interfaces:**
- Consumes: `ProviderResult`, `ProviderUnavailable`, `Connector.analyze` (Tasks 4 and 5).
- Produces `AiModelConnector`: manifest `name="ai_model"`, `version="1.0.0"`, `category="AI"`, `provides="mail_ai"`, `enabled_by_default=False`, `events=()`, config schema `url` (url, default `http://ai_inference:8090`, required), `token` (secret, required), `timeout_seconds` (int, default 20). `health_check()` is ok only when `/v2/health/ready` answers 200 and `/v2/models/ai_mail` accepts the token.
- Produces `client.AiInferenceClient(url: str, token: str, timeout: float)` with `ready() -> tuple[bool, str]` and `classify(mail_body: str) -> dict` (raises `ProviderUnavailable(retryable=True)` on connection error, timeout or 5xx; `retryable=False` on a 503 whose body mentions unavailable models or the vectorizer; raises `ValueError` on any other 4xx).
- Produces `mailtext.read_archive_body(mail_archive) -> str | None`: opens `mail_archive.archive.file_path`, reads the `.txt` member of the tar with member-count and size limits (1,000 members, 200 MB uncompressed, regular files only, no path escapes), and returns `None` when there is no `.txt` or no `.headers` member, or the body is empty after stripping.
- Produces `result_from_server(payload: dict) -> ProviderResult` in `connector.py`: `result=class`, `score=round(score)`, `confidence=round(confidence * 100)`, `category=str(sub_class).capitalize()[:max_length]`, `model_version=version`, `assessment` holding `sub_class`, `probabilities`, `sub_probabilities`, `tier`, `contributing_phrases`, `similar_cases`, `campaign_embedding`, `embedding_version`, `latency_ms`.

- [ ] **Step 1: Write the failing tests**

```python
def test_manifest(self):
    m = AiModelConnector.manifest; m.validate()
    self.assertEqual((m.name, m.provides, m.enabled_by_default), ("ai_model", "mail_ai", False))
    self.assertEqual({f.key: f.type for f in m.config_schema}["token"], "secret")

def test_result_mapping_rounds_like_the_legacy_parser(self):
    r = result_from_server(payload(klass="DANGEROUS", score=7.4, confidence=0.815, sub_class="CLASSIC_PHISHING"))
    self.assertEqual((r.result, r.score, r.confidence, r.category), ("DANGEROUS", 7, 82, "Classic_phishing"))

def test_a_4xx_becomes_an_inconclusive_result_and_never_trips_the_breaker(self): ...
def test_timeout_and_5xx_are_retryable_unavailable(self): ...
def test_a_503_for_missing_models_is_not_retryable(self): ...
def test_empty_or_missing_body_gives_inconclusive_with_a_reason(self):
    # archive without .headers, or an all-whitespace .txt -> ProviderResult("INCONCLUSIVE", reason="archive_unreadable")
def test_tar_with_a_path_escape_or_too_many_members_is_rejected(self): ...
def test_health_check_ok_and_not_ok(self): ...
def test_registered_as_a_builtin(self):
    registry.discover(); self.assertIn("ai_model", registry.names())
```

- [ ] **Step 2: Run to verify they fail.** Run: `ww test backend connectors.contrib.ai_model`. Expected: FAIL.
- [ ] **Step 3: Implement** the three modules and register the path. `analyze` finds the case's mail archive (`case.fileOrMail.mail` then `MailArchive.objects.filter(mail=mail).first()`), reads the body, calls the client and maps the payload; a `ValueError` from the client and an unreadable archive both return `ProviderResult("INCONCLUSIVE", 0, 0, "No subclass found", "", {}, reason=...)`.
- [ ] **Step 4: Run** `ww test backend connectors ai_model`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ai-model): ai_model connector for the mail_ai provider slot`.

### Task 7: Parity with the Cortex path

**Files:**
- Create: `ai_model/tests/test_parity.py`, `ai_model/tests/fixtures/cortex_ai_report.json`

**Interfaces:**
- Consumes: `AiMailParser` (`score_process/scoring/cortex_analyzers/contrib/ai_mail.py`), `result_from_server` (Task 6).

- [ ] **Step 1: Capture a real fixture.** From the dev stack: `docker compose --env-file .env exec -T suspicious python manage.py shell -c "import json; from cortex_job.models import AnalyzerReport as R; r=R.objects.filter(analyzer__name__startswith='AI_Mail', status='Success').first(); print(json.dumps({'summary': r.report_summary, 'full': r.report_full}))"` and save the JSON, replacing `analyzed_mail_content` with a short placeholder. Expected: a dict with `summary` (`classification`, `malscore`, `confidence`) and `full`.
- [ ] **Step 2: Write the failing test**

```python
def test_provider_mapping_equals_the_legacy_parser_and_manage_ai_jobs(self):
    fx = load_fixture()
    legacy = AiMailParser().parse(fx["summary"], fx["full"])        # score, confidence, level
    new = result_from_server(server_payload_from(fx["full"]))        # build the v2 payload from the same report
    self.assertEqual((new.result.lower(), new.score, new.confidence), (legacy.level, legacy.score, legacy.confidence))
    self.assertEqual(new.category, str(fx["full"]["sub_classification"]).capitalize()[:Case._meta.get_field("category_ai").max_length])
```

- [ ] **Step 3: Run to verify it fails or passes for the right reason.** Run: `ww test backend ai_model.tests.test_parity`. Expected: FAIL on the first run only if the mapping differs; fix `result_from_server` until it matches, never the fixture.
- [ ] **Step 4: Run** `ww test backend ai_model connectors`. Expected: PASS.
- [ ] **Step 5: Commit** `test(ai-model): version 0 parity with the Cortex AI report`.

### Task 8: Wiring, docs and a dev-stack check

**Files:**
- Modify: `deployment/compose_apps.yaml` (`ai_inference.environment`: `AI_INFERENCE_TOKEN: "${AI_INFERENCE_TOKEN:-}"`), `deployment/.env.example` (`AI_INFERENCE_TOKEN=`), `docs/getting-started/examples/Suspicious-settings.example.json` (add `integrations.ai_model` with `url`, `token`, `timeout_seconds`), `docs/components/analyzers.md` (a "v2 API and the ai_model connector" section and a troubleshooting row: 401 or 503 on `/v2`), `CHANGELOG.md` (`[Unreleased]` → Added)

- [ ] **Step 1: Make the edits** above; the troubleshooting row says `curl -H "Authorization: Bearer $AI_INFERENCE_TOKEN" http://ai_inference:8090/v2/models/ai_mail`.
- [ ] **Step 2: Rebuild and start the dev stack** per the `/deploy-full-e2e` section of `CLAUDE.md` (with `--profile ai`), set `AI_INFERENCE_TOKEN` in `deployment/.env`, and put the same value in `integrations.ai_model.token`.
- [ ] **Step 3: Verify the network path.** Run: `docker compose --env-file .env exec -T suspicious_celery curl -s http://ai_inference:8090/v2/health/live`. Expected: `{"live":true}`.
- [ ] **Step 4: Enable the connector and submit a mail.** `PATCH /api/connectors/ai_model/` with `{"enabled": true}`; submit a phishing sample as in the `CLAUDE.md` smoke test. Expected, in a Django shell: the case has `ai_assessment` with `model_version == "v0"`; its `CaseAnalyzerJob` for the AI analyzer has a `provider-` id and status `Success`; no job with a Cortex id exists for that analyzer; the case reaches `FINALIZED`; `ConnectorDelivery` shows an `analyze` success.
- [ ] **Step 5: Verify the failure path.** Stop `ai_inference`, submit a mail. Expected: within about 75 seconds the row is `Failure`, `results_ai == "Inconclusive"`, the case finalises, and after repeated failures the connector's breaker opens (visible in `GET /api/connectors/`).
- [ ] **Step 6: Run the full backend suite** (`ww test backend`) and the inference tests. Expected: PASS apart from known skips.
- [ ] **Step 7: Commit** `docs(ai-model): wire the token, settings example and troubleshooting`.

---

## Self-review

- **Spec coverage:** section 1 (slot, ledger row, written fields, failure behaviour, idempotency): Tasks 3-6; section 2 (health, metadata, token, classify, campaign embedding, v0): Tasks 1-2; section 3 version 0 behaviour: Tasks 2 and 6 (registry and bundles are Plan E); section 9 and 10 health: Task 6 `health_check`, breaker use: Task 5; section 11 step 2 and its acceptance: Tasks 7-8. Not in this plan, by design: campaign detection (Plan B), removal of the Cortex path (Plan B), UI (Plans C and G), ledger, retrain, shadow.
- **Types:** `ProviderResult` (Task 4) is the only cross-task record; `result_from_server` (Task 6) and `finish_provider_analysis` (Task 5) use its field names.
- **Proportion:** this plan carries signatures, tests and values, not bodies.
