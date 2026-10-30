# AI Model Connector, Plan B: Campaigns in the Connector and the Cortex Cutover

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** With the `ai_model` connector enabled, phishing-campaign detection and the TheHive campaign alert run from the connector with the same membership and event as the Cortex path; then the Cortex AI path is removed.

**Architecture:** The connector subscribes to `case_finalised`. Its hook only enqueues a Celery task, which reads the case's `AiAssessment` and mail text, runs the ported detection against the `suspicious_mails` Chroma collection under the existing `campaign:detect` lock, and emits `campaign_updated`. The TheHive connector, the Campaigns page and the 15-day cleanup are unchanged. Tasks 1 to 6 are additive; Task 7 proves parity on the dev stack; Tasks 8 to 10 delete the Cortex AI path and run only if Task 7 passes.

**Tech Stack:** Django, Celery, ChromaDB client, pybreaker.

**Spec:** `docs/specs/2026-10-30-ai-model-connector-design.md` (section 7, section 11 steps 2 and 3, Risks "Silent loss of phishing campaigns"). Master plan: `docs/plans/2026-10-30-ai-model-connector.md`. Plan A is merged and provides `AiAssessment`, `connectors/contrib/ai_model/{connector,client,mailtext}.py` and the provider slot.

## Global Constraints

- Campaign profile `cmp-e1`: first 128 tokens of `paraphrase-multilingual-mpnet-base-v2`, cosine distance 0.25, 3 minimum members, 20 neighbours, 15-day window, trigger "AI class is Dangerous", collection `suspicious_mails`.
- Detection keeps today's behaviour: one `campaign:detect` lock (`ttl=120, wait=90`), a case already in a `CampaignMember` row is left alone, a sender domain on the campaign allow-list is skipped and not stored, every other analysed mail is stored in the collection (one document `case-<id>`), `campaign_updated` is emitted only when a campaign was created or joined.
- The connector disabled means no detection. The Cortex AI job is never launched while the connector is enabled (Plan A), so the Cortex path and the connector never both detect.
- Chroma outages must not open the `ai_model` circuit breaker: the classification calls share it. Detection therefore never runs inside the `deliver_now` hook.
- No mail content in logs or exception messages.
- Repository conventions: Conventional Commits (subject at most 72 characters, body lines at most 100), no `Co-Authored-By` trailer, one `CHANGELOG.md` entry per user-visible change, backend tests through `ww test backend <label>`, nothing pushed, remove a stray root-owned `Suspicious/Suspicious/gunicorn.conf.py` before committing, commit only the files a task lists.

## Review Focus

- A Chroma outage while detecting leaves the `ai_model` breaker closed and the AI vote working (Task 4).
- `case_finalised` delivered twice, or the task redelivered: one collection document, one member row, one `campaign_updated` (Task 4).
- A web-uploaded mail whose text exists only in the tar, not in the object store, still reaches the collection (Task 2).
- An assessment with no embedding (Inconclusive) and a mail with a MIME-encoded `Subject`: no crash, no document, and the decoded subject titles the campaign (Tasks 2, 3).
- Two siblings finalising one after the other: one `Campaign`, the second joins it (Task 3).

## Calls made in this plan

| # | Call | Why |
|---|---|---|
| B1 | The mail text and headers come from the `.txt` and `.headers` that the Cortex analyzer read (through `mailtext`), not from `Mail.mail_body` and `Mail.mail_header` | Parity is the acceptance test. `MailHeader.header_value` is `str(data.headers)`, not the `.headers` file, and one reader already has the store, layout and tar fallbacks from Plan A. Swapping the source is one function |
| B2 | The hook enqueues `run_campaign_detection`; detection is not inline in the hook | `deliver_now` wraps hooks in the connector's breaker; a Chroma failure there would open the breaker and stop classification. The task has its own retries |
| B3 | No `dry_run` parameter and the return stays `Campaign \| None` | Plan F adds the dry run and widens the return. YAGNI until then |
| B4 | Queries do not filter on `embedding_version`; the tag is written on new documents only | The collection name separates versions (spec section 7); old documents have no tag and must keep matching across the cutover |
| B5 | Chroma errors before the campaign rows exist propagate (the task retries); errors after are logged and the campaign is still returned | A retry after rows exist would hit the "already placed" guard and lose the event |
| B6 | The row writes run in `transaction.atomic()` | A crash between `Campaign.create` and the members must not leave an empty campaign |
| B7 | Document metadata: `malscore` is the rounded `AiAssessment.score`, `confidence` is the percent divided by 100 (as Cortex stored it) | Informational only; nothing reads them (checked in `api/services/campaigns` and the TheHive code, which read `case.score_ai`) |
| B8 | The replay command is read-only: it runs inside a transaction it rolls back and uses a scratch collection | It must be safe to run against production data |
| B9 | After the cutover the `ai_archive` plumbing stays as the trigger "this mail has a readable archive"; its two callers call `queue_provider_analysis(case, PROVIDER_KIND_MAIL_AI)` directly | Keeps when the AI step is dispatched exactly as today |
| B10 | Tasks 8 to 10 do not start unless Task 7 reports a match | The spec makes the replay the guard against silently losing campaigns |

---

### Task 1: Campaign profile

**Files:**
- Create: `ai_model/campaign_profile.py`
- Test: `ai_model/tests/test_campaign_profile.py`

**Interfaces:**
- Produces:
```python
@dataclass(frozen=True)
class CampaignProfile:
    embedding_version: str; collection_name: str; max_tokens: int; distance_threshold: float
    min_members: int; neighbours: int; window_days: int; trigger_class: str; allow_list_digest: str

def allow_list_digest() -> str   # sha256 hex of the sorted allow-listed domain values joined by "\n", first 16 characters
def current_profile() -> CampaignProfile   # cmp-e1 with today's allow_list_digest()
```
  The allow-list is `settings.models.CampaignDomainAllowList` (`domain.value`); rows with no domain are ignored.

- [ ] **Step 1: Write the failing tests.** `test_profile_values_match_the_spec_table` (every constant in Global Constraints), `test_digest_ignores_order_and_changes_with_the_list` (add a domain, digest changes; same set in another insertion order, same digest), `test_empty_allow_list_has_a_defined_digest`.
- [ ] **Step 2: Run** `ww test backend ai_model.tests.test_campaign_profile`. Expected: FAIL (module missing).
- [ ] **Step 3: Implement** the dataclass, `allow_list_digest` and `current_profile`.
- [ ] **Step 4: Run** the same label. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ai-model): campaign profile cmp-e1 with allow-list digest`.

### Task 2: Mail material reader

**Files:**
- Modify: `connectors/contrib/ai_model/mailtext.py`, `connectors/contrib/ai_model/connector.py` (use `mail_archive_for`)
- Test: `connectors/contrib/ai_model/tests/test_mailtext.py`

**Interfaces:**
- Consumes (Plan A): `read_archive_body(mail_archive) -> str | None`, `fetch_mail_text_from_minio(client, mail_id, bucket_name) -> (headers, text)`, `MAIL_TEXT_MAX_BYTES`.
- Produces:
```python
@dataclass(frozen=True)
class MailMaterial:
    headers: str   # raw text of the .headers file
    text: str      # text of the .txt file

def read_archive_material(mail_archive) -> MailMaterial | None   # same sources, caps, fallbacks and ProviderUnavailable rules as read_archive_body
def read_archive_body(mail_archive) -> str | None                # unchanged contract; returns the material's text
def header_dict(raw_headers: str) -> dict[str, list[str]]        # as the Cortex analyzer built it (email.message_from_string, values collected per key), then MIME words decoded with connectors.contrib.thehive.utils.parse_and_decode_defaultdict(str(defaultdict))
def mail_archive_for(case) -> MailArchive | None                 # the lookup AiModelConnector.analyze does inline today
```
  The tar fallback reads the `.headers` member too, with the same `MAIL_TEXT_MAX_BYTES` cap. A mail with blank headers or blank text is `None`, as today.

- [ ] **Step 1: Write the failing tests.** Material from the store (both layouts), material from a tar when the store has none, tar with no `.headers` member is `None`, a store outage with no tar raises `ProviderUnavailable`, `header_dict("Subject: =?utf-8?B?...?=\nFrom: a@b.example")` decodes the subject, repeated header keys keep every value, `read_archive_body` still returns only the text. All existing `test_mailtext.py` and `test_connector.py` tests stay unchanged and green.
- [ ] **Step 2: Run** `ww test backend connectors.contrib.ai_model`. Expected: new tests FAIL.
- [ ] **Step 3: Implement** by returning `(headers, text)` from the two private readers and building `MailMaterial` at the public boundary; move the archive lookup out of `analyze`.
- [ ] **Step 4: Run** `ww test backend connectors.contrib.ai_model`. Expected: PASS.
- [ ] **Step 5: Commit** `refactor(ai-model): read headers with the mail text, share the archive lookup`.

### Task 3: Detection port

**Files:**
- Create: `connectors/contrib/ai_model/campaigns.py`
- Modify: `score_process/score_utils/chromadb_utils.py` (`get_suspicious_collection(client, name="suspicious_mails")`; `add_to_suspicious_collection(..., extra_metadata=None)` merged into the document metadata), `connectors/contrib/thehive/utils.py` (`get_phishing_campaign(similar_mails, similar_threshold=0.25, campaign_threshold=3)`)
- Test: `connectors/contrib/ai_model/tests/test_campaigns.py`

**Interfaces:**
- Consumes: Task 1 `CampaignProfile`; Task 2 `header_dict`; `AiAssessment`; the existing helpers `get_similar_dangerous_mails`, `set_campaign_ref`, `extract_sender_domain_from_headers`, `is_domain_in_campaign_allow_list`, `get_most_common_subject`, `common.locks.cache_lock`.
- Produces:
```python
class CampaignStoreUnavailable(Exception): ...

def open_collection(profile: CampaignProfile)   # get_chroma_client() + get_suspicious_collection(client, profile.collection_name); any failure -> CampaignStoreUnavailable
def detect_campaign(case: Case, assessment: AiAssessment, text: str, headers: dict, profile: CampaignProfile, collection) -> Campaign | None
```
  Behaviour (a port of `case_handler.campaigns.detect_campaign`, which stays until Task 8): member guard, then no embedding means `None` and nothing stored; a class other than `profile.trigger_class` is stored and returns `None`; an allow-listed sender returns `None` unstored; under the lock, query `profile.neighbours` Dangerous neighbours, `get_phishing_campaign(similar, profile.distance_threshold, profile.min_members)`; none stores and returns `None`; otherwise the member rows (join the campaign with most known members, lowest id on a tie, else create titled by `get_most_common_subject`) are written in `transaction.atomic()` (B6), then the document is stored with the campaign ref and `set_campaign_ref` tags the members (B5). Documents carry `extra_metadata={"embedding_version": profile.embedding_version}`. The Cortex-shaped `full` dict the helpers expect is built from the assessment (B7).

- [ ] **Step 1: Write the failing tests** by porting the ten tests of `case_handler/tests/test_campaign_detection.py` (same fakes, copied into the new module) to the new signature, plus: `test_a_non_dangerous_assessment_is_stored_not_a_campaign`, `test_an_assessment_without_an_embedding_is_not_stored`, `test_documents_carry_the_embedding_version`, `test_the_second_sibling_joins_the_campaign_the_first_created` (one `Campaign`), `test_a_chroma_error_before_the_rows_is_raised_as_store_unavailable`, `test_a_chroma_error_after_the_rows_still_returns_the_campaign`, `test_a_mime_encoded_subject_titles_the_campaign`, `test_open_collection_wraps_a_client_failure`. The existing `case_handler` tests stay green.
- [ ] **Step 2: Run** `ww test backend connectors.contrib.ai_model.tests.test_campaigns`. Expected: FAIL.
- [ ] **Step 3: Implement** `campaigns.py` and the three small helper changes (defaults keep every current caller unchanged).
- [ ] **Step 4: Run** `ww test backend connectors.contrib.ai_model case_handler score_process connectors.contrib.thehive`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ai-model): campaign detection ported to read the AI assessment`.

### Task 4: Subscription, task and changelog

**Files:**
- Modify: `connectors/contrib/ai_model/connector.py` (`events=(EVENT_CASE_FINALISED,)`, `on_case_finalised`), `connectors/tasks.py`, `CHANGELOG.md`
- Test: `connectors/contrib/ai_model/tests/test_campaign_task.py`

**Interfaces:**
- Consumes: Tasks 1 to 3; `connectors.dispatch.emit`, `EVENT_CAMPAIGN_UPDATED`.
- Produces:
```python
@shared_task(bind=True, acks_late=True, reject_on_worker_lost=True, max_retries=3)
def run_campaign_detection(self, case_id: int) -> None
```
  `on_case_finalised(event)` calls `run_campaign_detection.delay(event.case_id)` and nothing else. The task loads the case, its `ai_assessment` and `mail_archive_for(case)`; no assessment, no archive or no material means return quietly; it opens the collection, runs `detect_campaign(case, assessment, material.text, header_dict(material.headers), current_profile(), collection)` and, with a campaign, `emit(EVENT_CAMPAIGN_UPDATED, case, campaign_id=campaign.id)`. `CampaignStoreUnavailable` and a retryable `ProviderUnavailable` retry with `countdown=30 * 2 ** self.request.retries`; when retries run out it logs the case id and exception class at ERROR and returns. It never uses the connector's breaker.

- [ ] **Step 1: Write the failing tests.** `test_the_hook_only_enqueues` (one `.delay`, no collection opened), `test_a_dangerous_assessment_creates_the_campaign_and_emits_once`, `test_a_second_delivery_adds_no_document_row_or_event`, `test_a_chroma_outage_retries_and_leaves_the_breaker_closed` (assert `get_breaker("ai_model").fail_counter` is unchanged and the task retried), `test_exhausted_retries_log_and_return`, `test_no_assessment_means_no_work`, `test_a_disabled_connector_receives_no_case_finalised` (through `emit`), `test_the_thehive_connector_receives_campaign_updated` (fake TheHive connector subscribed to the event).
- [ ] **Step 2: Run** `ww test backend connectors.contrib.ai_model.tests.test_campaign_task`. Expected: FAIL.
- [ ] **Step 3: Implement** the hook, the task and a `CHANGELOG.md` entry under `[Unreleased]`: with `ai_model` enabled, campaign detection and the TheHive campaign alert run from the connector.
- [ ] **Step 4: Run** `ww test backend connectors`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ai-model): run campaign detection from the connector on case_finalised`.

### Task 5: Collection-name check

**Files:**
- Modify: `connectors/contrib/ai_model/campaigns.py` (`collection_mismatch`), `connectors/contrib/ai_model/connector.py` (`health_check`), `connectors/tasks.py` (one WARNING per process)
- Test: `connectors/contrib/ai_model/tests/test_campaigns.py`

**Interfaces:**
- Produces `collection_mismatch(profile: CampaignProfile) -> str | None`: when the `chromadb` connector is enabled and its `collection_name` config (default `suspicious`) differs from `profile.collection_name`, a sentence naming both; else `None`. Read the other connector's config through `registry.instantiate("chromadb").config`.
- `health_check` appends the sentence to `HealthStatus.detail` without changing `ok`. `run_campaign_detection` logs it at WARNING once per process.

- [ ] **Step 1: Write the failing tests.** Mismatch, match, cleanup connector disabled (no message), health detail carries the sentence and `ok` is unchanged, the warning is logged once across two task runs.
- [ ] **Step 2: Run** `ww test backend connectors.contrib.ai_model`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `ww test backend connectors.contrib.ai_model`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ai-model): warn when the cleanup connector watches another collection`.

### Task 6: Parity replay command

**Files:**
- Create: `ai_model/management/commands/ai_model_campaign_replay.py` (plus the `management/__init__.py` packages)
- Test: `ai_model/tests/test_campaign_replay.py`

**Interfaces:**
- `manage.py ai_model_campaign_replay <campaign_ref>`: for the stored campaign, replay its member cases in id order through the new `detect_campaign` and compare. Inside one `transaction.atomic()` that is always rolled back: delete the campaign's `CampaignMember` rows, open a scratch collection `suspicious_mails__replay_<hex>` (dropped in `finally`; tests patch `open_collection`), and for each member build a transient, unsaved `AiAssessment` from the case's Cortex AI `AnalyzerReport.report_full` (class, score, confidence, `email_embedding`) with the report's `analyzed_mail_content` and decoded `analyzed_mail_headers` as text and headers. Print one line per member (`created`, `joined`, `stored`) and the verdict. Compare the member set of the campaign the last member lands in with the stored member set and the trigger case (the last member) with the stored one; the `campaign_updated` event is built from the trigger case and the campaign id only, so equal membership and trigger mean an equal payload (B8). Exit 0 and print `MATCH`, or raise `CommandError` printing the missing and extra case ids.
- Members whose Cortex AI report is missing are listed as skipped; if fewer than `min_members` remain, the command fails with "cannot replay".

- [ ] **Step 1: Write the failing tests** with a small in-memory collection that implements `add`, `get`, `update` and a cosine `query` (no chromadb needed): `test_a_campaign_built_by_the_old_path_replays_to_a_match`, `test_a_member_with_a_distant_embedding_is_reported_as_a_difference_and_fails`, `test_the_replay_changes_no_rows` (row counts before and after are equal), `test_a_member_without_a_cortex_report_is_skipped`, `test_too_few_replayable_members_fails`. Build the stored campaign with the old `case_handler.campaigns.detect_campaign` and the same fake, so the test compares the two paths.
- [ ] **Step 2: Run** `ww test backend ai_model.tests.test_campaign_replay`. Expected: FAIL.
- [ ] **Step 3: Implement** the command.
- [ ] **Step 4: Run** `ww test backend ai_model`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(ai-model): ai_model_campaign_replay compares the new path with a stored campaign`.

### Task 7: Dev-stack acceptance (controller-run, no new code)

Run by the controller against the dev stack, like Plan A Task 8; record the outputs in the ledger.

- [ ] **Step 1: Build** the `suspicious` image from the worktree and recreate the stack services (`suspicious`, `suspicious_celery`, `suspicious_celery_beat`) with the connector still disabled.
- [ ] **Step 2: Cortex-built campaign.** Submit at least three near-identical phishing mails through the feeder with the connector disabled, so the Cortex path scores and groups them. Confirm a `Campaign` with 3 or more members.
- [ ] **Step 3: Replay.** Run `ai_model_campaign_replay <ref>` in the `suspicious` container. Expected: `MATCH`. **On any difference, stop: Tasks 8 to 10 do not start (B10); report the diff.**
- [ ] **Step 4: Connector-built campaign.** Enable `ai_model`, submit three near-identical new mails, confirm one new `Campaign` with 3 members, a `case_finalised` delivery row for `ai_model`, the documents in `suspicious_mails` carrying `embedding_version`, and (TheHive is not in the dev stack) the `campaign_updated` event emitted once. Stop the Chroma container for one mail and confirm the AI rows of the next mails still succeed (the breaker stays closed) and the detection task retries, then recovers.
- [ ] **Step 5: Cleanup check.** Read the `chromadb` connector's `collection_name` on the dev stack and report whether `health_check` shows the mismatch sentence.
- [ ] **Step 6: Restore** the connector to disabled and any edited config files from backups; delete drill cases' tokens or users created.

### Task 8: Cutover, backend

Only after Task 7 matched.

**Files:**
- Delete: `case_handler/campaigns.py`, `case_handler/tests/test_campaign_detection.py`, `score_process/scoring/cortex_analyzers/contrib/ai_mail.py` and its parser tests
- Modify: `cortex_job/cortex_utils/reconciliation.py` (remove the `run_campaign_detection` import and call), `cortex_job/cortex_utils/cortex_and_job_management.py` (remove `launch_cortex_ai_jobs`, `manage_ai_jobs`, `get_sub_class`), `score_process/scoring/cortex_analyzers/reports.py` (remove the `manage_ai_jobs` call and the AI branches), `mail_feeder/global_submission/gsubmission.py` and `tasp/tasks.py` (B9), `ai_model/tests/test_parity.py` (its legacy side is gone: assert the mapped case fields against the values frozen in the fixture instead), the parser registry that names `AiMailParser`, and every test that imports a removed name.
- Interfaces: the two callers call `queue_provider_analysis(case, PROVIDER_KIND_MAIL_AI)` where they called `launch_cortex_ai_jobs`; `ai_archive` stays as the trigger.

- [ ] **Step 1: List** every import and use of each removed name with `grep -rn` and write the list in the report.
- [ ] **Step 2: Make the deletions and edits**, one concern per commit if the diff is large.
- [ ] **Step 3: Prove** nothing references a removed name (`grep` returns nothing outside git history and the CHANGELOG), then run `ww test backend` (full suite). Expected: PASS.
- [ ] **Step 4: Commit** `refactor(cortex): remove the Cortex AI path and the old campaign hook`.

### Task 9: Cutover, analyzer assets, legacy classify and settings

**Files:**
- Delete: `Analyzers/AIMailAnalyzer/AIMailAnalyzer.json`, `ai_mail_classifier.py`, the thin-client `Dockerfile`, `requirements-client.txt` and tests that cover only them
- Modify: `Analyzers/AIMailAnalyzer/inference_server/server.py` (remove the legacy `/classify` route; keep `/health`, `/reload` and the classify function `/v2` uses), the `inference_url` setting wherever it is defined and documented, `deployment/compose_apps.yaml` (remove the `172.17.0.1` host port binding of `ai_inference`; the connector reaches `ai_inference:8090` on `suspicious_net`), `deployment/.env.example`, `docs/getting-started/examples/Suspicious-settings.example.json`
- Test: the inference server tests

- [ ] **Step 1: Find** every reference to each deleted file and setting (`grep -rn`), including Makefile targets, image builds and the Cortex analyzer catalog sync.
- [ ] **Step 2: Remove** them; update the inference tests that call `/classify` to call `/v2/models/ai_mail/classify`.
- [ ] **Step 3: Run** `cd Analyzers/AIMailAnalyzer && python -m pytest tests` and `ww test backend`. Expected: PASS.
- [ ] **Step 4: Commit** `refactor(ai-inference): remove the thin Cortex client and the legacy classify route`.

### Task 10: Cutover, docs

**Files:**
- Modify: `docs/components/analyzers.md`, `docs/components/backend/connectors.md` (list `ai_model`), `CLAUDE.md` (the `ai_inference` row, the AI / ML inference-path paragraph, the `connectors` row), `CHANGELOG.md`

- [ ] **Step 1: Rewrite** the sections that describe the Cortex AI job, the gateway-IP URL and the `ai_model` caveat. State plainly: an instance that does not enable `ai_model` has no AI vote; campaign detection needs it; Plan C adds the case section.
- [ ] **Step 2: Add** a `CHANGELOG.md` entry under Removed or Changed for the Cortex AI path.
- [ ] **Step 3: Check** every claim against the code (`grep` for each name and number written).
- [ ] **Step 4: Commit** `docs(ai-model): the connector replaces the Cortex AI analyzer`.
