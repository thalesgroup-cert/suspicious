# AI Model Connector: Follow-ups Before Plan C

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every deferred minor finding and parked item left by Plans A and B, so Plan C starts from a clean base.

**Architecture:** Three independent clean-up tasks: the campaign path and the lock (Task 1), the parked Plan A bugs and the connector `url` check (Task 2), tests, dead code and doc hygiene (Task 3). No new feature.

**Spec:** `docs/specs/2026-10-30-ai-model-connector-design.md`. Plans: `docs/plans/2026-10-30-ai-model-connector-a-provider-slot.md`, `docs/plans/2026-10-30-ai-model-connector-b-campaigns.md`.

## Global Constraints

- Backend paths are relative to `Suspicious/Suspicious/`. Tests run through `ww test backend <label>`; inference tests through `cd Analyzers/AIMailAnalyzer && python -m pytest tests`.
- TDD for every behaviour change (failing test first, shown in the report). Pure test or doc items need no RED step.
- Conventional Commits (subject at most 72 characters, body lines at most 100), no `Co-Authored-By` trailer, explicit `git add <paths>` (never `-A`), nothing pushed, remove a stray root-owned `Suspicious/Suspicious/gunicorn.conf.py` before committing.
- No mail content in logs or exception messages. The Chroma proxy allow-list (`deployment/docker/chroma-proxy/default.conf.template`) is not touched and no code creates-then-drops a collection through the HTTP client.
- Docs prose: no em dashes, no filler vocabulary, every claim checked against the code.
- A `CHANGELOG.md` entry for each user-visible change (Task 1 re-emit, Task 2 url check and label fix).

## Review Focus

- A worker killed after the campaign rows commit: the redelivered task stores the case's document, tags the members and emits `campaign_updated` once more (Task 1).
- Two tasks for one case at once: one `Campaign`, no failure (Task 1).
- A lock held past its TTL is not released by the previous holder's `finally` (Task 1).
- A mail stored in prefix mode or uploaded from the web is found by the TheHive campaign material and the trusted-sender lookup (Task 2).
- A connector `url` such as `file:///etc/passwd` or `http://user:pw@host` is refused when saved (Task 2).

---

### Task 1: Campaign path and the lock

**Files:** `connectors/contrib/ai_model/campaigns.py`, `connectors/contrib/ai_model/mailtext.py`, `connectors/contrib/ai_model/connector.py`, `connectors/tasks.py`, `common/locks.py`, `ai_model/management/commands/ai_model_campaign_replay.py`, their tests, `CHANGELOG.md`.

- [ ] **1. Redelivery after a kill (re-emit).** In `detect_campaign`, when the case already has a `CampaignMember` row, do not return `None`: take that row's campaign, store the case's document if absent (`add_to_suspicious_collection` is idempotent by document id), tag the campaign's members with `set_campaign_ref`, and return the campaign so the task emits `campaign_updated` again. Re-check membership right after the `campaign:detect` lock is taken, so two tasks for one case create one campaign. Update the Task 4 redelivery test (a second delivery now emits again, adds no document and no row) and the replay command, which deletes the members first and is unaffected. CHANGELOG: say a repeated finalisation re-sends `campaign_updated` (TheHive's sync is idempotent).
- [ ] **2. Lock release by holder.** `common/locks.py` `cache_lock`: release only if the stored value is still this holder's token (a compare before delete; an atomic form if the cache backend supports it, else the compare-then-delete with the residual race documented in a comment). Tests: a holder whose TTL expired and whose lock another holder now owns does not delete the other's key; the normal path is unchanged; existing users of `cache_lock` (`grep -rn cache_lock`) keep passing.
- [ ] **3. Small campaign-path items.** `header_dict` normalises `\r\n` and `\r` to `\n` before parsing (the Cortex analyzer read in text mode); `_is_vector` rejects NaN and Infinity; `collection_mismatch` and `health_check`: the lazy import in the task moves inside the `try`, `health_check` reads the collection name without building a full `current_profile()` (no DB query), the bare `except` logs the exception class at DEBUG, and the sentence stops saying the cleanup "cleans up collection 'X'" for a collection that does not exist (say old campaign documents are not removed); the replay's failed local delete raises `CommandError`; a second `EphemeralClient` in one process with different settings cannot raise (build the client through one helper used by the command and its tests).
- [ ] **4. Tests.** Strengthen: `test_read_archive_body_returns_only_the_text` asserts `read_archive_body` directly; a `literal_eval` round trip with quotes, a backslash and U+FFFD in a header; an assessment with a DANGEROUS result and an empty embedding is not stored; a smaller `neighbours` and a tighter `distance_threshold` each turn a would-be campaign into none; a neighbour whose `Case` was deleted is ignored; the lock is released after both post-row writes; the breaker-isolation test also injects the failure part-way through detection; the never-HTTP replay test also patches `chromadb.HttpClient`; the repeated setup block in the replay tests becomes a helper; `max(replayable)` with `min_members == 0` fails with "cannot replay".
- [ ] **5. Run** `ww test backend connectors ai_model common`, then the full `ww test backend`. Commit in two or three commits by concern.

### Task 2: Parked Plan A bugs and the connector `url`

**Files:** `Analyzers/AIMailAnalyzer/inference_server/server.py` and tests, `score_process/` (`trusted_sender.py`), `connectors/contrib/thehive/campaign_material.py`, `common/storage/layout.py` (reuse only), `connectors/providers.py`, `connectors/base.py` and the connector settings path (`api/views/connectors.py` or where `ConfigField` values are saved), their tests, `CHANGELOG.md`.

- [ ] **1. Sub-class label shift.** `inference_server/server.py` `SUB_LABELS` versus the `SubClass` enum: indices 5 to 7 are shifted (a 96% CLONE can read as WHALING_PHISHING). First check whether the shifted list is still used by any live route (the legacy `/classify` is gone; `/v2` is reported unaffected). If used, fix it with a test that pins every index against the enum; if dead, delete it and say so in the report.
- [ ] **2. Bucket blind spot.** `trusted_sender.py` and `campaign_material.py` look the mail up by bucket and miss prefix-mode and web-upload mails. Use `common.storage.layout.resolve_submission_location` (as `mail_feeder/utils/email_preview/preview_jobs.py` and the ai_model mail reader do). Tests for the legacy bucket layout, the feeder prefix layout and a mail with no object (behaves as today).
- [ ] **3. Provider latent bugs.** `connectors/providers.py`: a duplicate provider row for a case must not leave stale `Case` fields from the earlier row (a failed second row keeps the earlier assessment but the case fields follow the latest finished row); the empty-`model_version` gate: a result with an empty `model_version` must be rejected as a failure, not stored as an assessment. Tests first.
- [ ] **4. Connector `url` check.** A `ConfigField` of type `url` is validated when saved: scheme `http` or `https`, a host, no embedded credentials; anything else is refused with a 400 naming the field (not the value). Find where connector config is written (`api/views/connectors.py`, `connectors/registry.py`) and validate in one place. Existing saved values are not rewritten; a health check on an invalid saved value fails with a clear detail. Tests for `file://`, `ftp://`, `http://user:pw@host`, no host, a valid `http://ai_inference:8090` and `https://x/y`. CHANGELOG entry.
- [ ] **5. Run** the affected labels, the inference tests, then the full `ww test backend`. Commit by concern.

### Task 3: Dead code, test hygiene and docs

**Files:** `cortex_job/cortex_utils/cortex_and_job_management.py`, `connectors/providers.py`, `mail_feeder/global_submission/handlers.py` and tests, `connectors/tests/test_provider_dispatch.py`, `Analyzers/AIMailAnalyzer/tests/test_inference_server.py`, `Analyzers/AIMailAnalyzer/inference_server/`, `deployment/.env.example`, `deployment/Makefile`, `deployment/compose.ci.yaml`, `Suspicious/settings.ci.json`, `docs/plans/*`.

- [ ] **1. Dead code.** `CortexJobManager.update_mail_models` and `connectors.providers.has_provider_job` have no production caller: confirm with `grep -rn`, delete them with their tests if nothing else uses them.
- [ ] **2. Tests.** `handle_attachments` flags `ai_missing` for an archive row with no file (own test, real `Handlers`, not mocked); the dispatch test that asserts `method_calls == []` proves little: make it assert something that fails if a Cortex job is launched; `test_concurrent_requests_are_bounded_by_the_semaphore`: stop monkeypatching a semaphore the v2 router already captured, set the real concurrency through the supported setting and assert against it; add a test that the `public` weights, when present, load and hot-reload (the variant is loaded but unrouted: state in the report whether it should be removed, and remove it only if nothing reads `models_public/`).
- [ ] **3. Config and comment hygiene.** The `.env.example` header and `deployment/Makefile` comments still describe `ai_inference` in Cortex-client terms: correct them. `Suspicious/settings.ci.json` and `deployment/compose.ci.yaml`: make the CI Cortex stub and the `ai` key agree (a name the stub lists, or no unresolved warning).
- [ ] **4. Plan documents.** `docs/plans/2026-10-30-ai-model-connector-b-campaigns.md`: the Task 6 section still describes the HTTP scratch collection and `open_collection` patching; the Calls table lacks the later rulings (P6 in-process Chroma, P7 what stays, P9 no-AI-vote behaviour, P10 `analyzers.ai` stays); correct them, and mark Plans A and B done in `docs/plans/2026-10-30-ai-model-connector.md`.
- [ ] **5. Run** the affected labels, the inference tests, then the full `ww test backend`. Commit by concern.
