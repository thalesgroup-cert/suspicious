# AI Model Connector, Plan D: Label Ledger and Sync Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A nightly sync fills an append-only label ledger from the analysts' IMAP review folders, analyst verdicts and reporter challenges are recorded beside it, hard conflicts are flagged, and the campaign line of the case view shows the labels of campaign siblings.

**Architecture:** `ai_model` gets `LabelRecord` and `LabelSyncState`. The model server gets `POST /v2/embed`. The connector gets a `sync()` on a nightly schedule that reads the review folders read-only over IMAP, matches each mail to a case by `Message-ID`, embeds it through `/v2/embed` and appends ledger rows. The verdict and challenge paths append rows in-process. The folder row is the label of record; verdict and challenge rows are provenance.

**Tech Stack:** Django models and management commands, `imaplib`, FastAPI, pytest, Django `TestCase`.

**Spec:** `docs/specs/2026-10-30-ai-model-connector-design.md` section 4 (label ledger), section 2 (`/v2/embed`), section 7 (campaign cross-check). Master plan: `docs/plans/2026-10-30-ai-model-connector.md`, Plan D.

## Global Constraints

- Backend paths are relative to `Suspicious/Suspicious/`, UI paths to `suspicious-ui/` (run UI tooling in containers: `ww test frontend`, the Playwright image). Backend tests: `ww test backend <label>`; inference tests: `cd Analyzers/AIMailAnalyzer && python -m pytest tests`.
- TDD for every behaviour change (failing test first, shown in the report).
- Conventional Commits (subject at most 72 characters, body lines at most 100), no `Co-Authored-By` trailer, explicit `git add <paths>` (never `-A`), nothing pushed, remove a stray root-owned `Suspicious/Suspicious/gunicorn.conf.py` before committing.
- The IMAP mailbox is opened read-only (`select(folder, readonly=True)`, `BODY.PEEK[]`); nothing is moved, flagged or deleted there.
- No mail text, subject or address in logs, exception messages or stored errors. The ledger stores embeddings and a small snapshot, never the mail text.
- The IMAP password is a `secret` config field (Vault), never logged.
- Docs prose: no em dashes, no filler vocabulary, every claim checked against the code. `CHANGELOG.md` entry for each user-visible change.

## Review Focus

- A mail re-synced on the next night adds no row (idempotent); the same mail moved to another folder supersedes the old row (Task 5).
- A folder holding unreadable or non-forwarded mails: those are skipped and counted, the sync still succeeds (Task 4, 5).
- `UIDVALIDITY` changes: the folder is re-read from the start, rows are not duplicated (Task 4, 5).
- A Dangerous folder label against a Safe verdict (and the reverse) flags the folder row and keeps it out of training, whichever arrives first (Task 6).
- The verdict save never fails because the ledger write failed (Task 6).
- A mail with no `Message-ID` is matched on sender, date and subject; two candidates mean no match (Task 3).
- A reporter's challenge proposal is stored with trust `proposal` and is never trainable (Task 6).

## Calls made in this plan

- **Ruling D1: the 8 folders.** The spec never names them. The only source in the repo is `Analyzers/AIMailAnalyzer/train_models.ipynb`: `0_LEGIT_INTERNAL_COMMUNICATION`, `0_LEGIT_EXTERNAL_COMMUNICATION` (Safe); `1_SPAM`, `1_NEWSLETTER` (Unwanted); `2_CLASSIC_PHISHING`, `2_CLONE_PHISHING`, `2_BLACKMAILING_PHISHING`, `2_WHALING_PHISHING` (Dangerous). The class comes from the digit prefix. The folder list is the config field `imap_folders` (comma separated, these 8 by default), because the production mailbox names are not in the repo. A folder not in the list is never read; a configured name without a known prefix is skipped and counted. Cost if wrong: a config edit.
- **Ruling D2: text form for ledger mails.** Version 0 keeps the legacy extraction the review-folder notebook uses (prefer the plain part, else the HTML part reduced to text) and the `legacy-first128` preprocessing, which `/v2/embed` applies for both profiles in version 0. The gap measurement against the live `.txt` body and the canonical text form belong to Plan E (retrain), where the recipe is chosen; the embedding is stored with its `preprocessing_version` so it can be recomputed.
- **Ruling D3: Message-ID.** Normalised by stripping whitespace and angle brackets and lower-casing; stored with its SHA-256. An id above 998 characters normalises to "" (no Message-ID). A folder row of a mail without a Message-ID stores `message_id=""` and keys on `sha256("no-message-id:" + sender address + "|" + UTC date (ISO) + "|" + lower-cased subject + "|" + sha256(text))`, so a `UIDVALIDITY` reset or a move between folders finds it again. Fallback match on the sender address, the send date (UTC day) and the lower-cased subject, taken from the case's stored mail; exactly one candidate matches, zero or several mean no match.
- **Ruling D4: audit.** The ledger is append-only. A resolution fills `resolved_by`, `resolved_at` and `resolution_note` on the flagged row and sets its status; no separate event table before Plan E's `ModelEvent`.
- **Ruling D5: supersession.** A new observation of a message with a different label (different folder) appends a row and sets the older folder rows of the same message that are not yet superseded (active or flagged) to `superseded`; the new row is conflict-checked again (Task 6). The same label again adds nothing.
- **Ruling D6: verdict rows only while `ai_model` is enabled**, written inside `_apply_verdict` after the case save, failures logged by exception class only. The backfill command (Task 7) covers history.
- **Ruling D7: near-duplicate handling** (`flag_reason=duplicate`) is Plan E's, where training and evaluation dedupe. Plan D stores the campaign embedding that makes it possible.
- **Ruling D8: sync batch cap.** At most 500 UIDs examined (skipped and already-observed ones included) per folder per run, checkpointed by `LabelSyncState.last_uid`, so the first backfill spans several nights unless the command in Task 7 is used with `--all`. A folder is read in chunks of 100 mails; each chunk is embedded, then its rows and the checkpoint (that chunk's `last_uid`) commit in one transaction under a row lock on the folder's `LabelSyncState`. The run stops cleanly between chunks, and between embed batches inside a chunk (that chunk is then not committed), once 300 s have passed since it started (Celery's soft limit is 540 s). The Task 7 command has no time budget. An embed refused for a chunk (4xx, an answer that does not fit the batch, versions changing within the chunk) skips that folder without moving its checkpoint, and after all folders ran the sync raises `LabelSyncIncomplete` (not retried, message: the count and the `ascii()` folder names) so the delivery is recorded failed; an unavailable embed endpoint fails the run.
- **Ruling D9: snapshot** holds only what is cheap and already stored: sender domain, subject length, allow/deny list hits and the AI result and version at observation time. The rest of the spec list (link domains, auth results, Cortex bands) waits for the plan that uses it ("not used in v1").
- **Ruling D10: sibling labels** (Plan C's deferred part) land in Task 8.
- **Ruling D11: conflict check limits (Task 6, accepted).** A verdict or challenge row of a case whose mail has no Message-ID (or no mail) keys on `sha256("no-message-id:case:<pk>")`, because the folder content key needs the forwarded mail's text, which the verdict path does not read; such rows join folder rows on the case only. So a folder row of a mail without Message-ID that matched no case is never checked against a verdict. The same Message-ID on two cases is not cross-checked: a verdict is checked against its own case's folder rows and the unmatched ones. A flag survives a later verdict change; only `resolve_flag` closes it. Task 8's docs repeat these limits.

## Contracts

- `ai_model/taxonomy.py`: `FOLDERS: tuple[str, ...]` (the 8 names), `class_of(folder: str) -> str | None` returning `"Safe"`, `"Unwanted"`, `"Dangerous"` or `None`.
- `ai_model.models.LabelRecord`: `message_id` (CharField 998, indexed, normalised), `message_id_hash` (CharField 64, indexed), `case` (FK `case_handler.Case`, null, `SET_NULL`, `related_name="label_records"`), `source` (`imap_folder|analyst_verdict|challenge`), `source_ref` (CharField 255), `label` (CharField 64: the folder name, or the verdict/proposal class), `label_class` (`Safe|Unwanted|Dangerous|Suspicious|Inconclusive`), `trust` (`folder|verdict|proposal`), `observed_at`, `embedding` (TextField), `preprocessing_version` (CharField 32), `campaign_embedding` (TextField), `embedding_version` (CharField 16), `snapshot` (JSONField), `status` (`active|superseded|flagged`), `flag_reason` (CharField 64), `resolved_by` (FK `auth.User`, null), `resolved_at`, `resolution_note`. Never updated except `status`, `flag_reason` and the three resolution fields. Property `trainable`: `trust == "folder"` and `status == "active"`.
- `ai_model.models.LabelSyncState`: `folder` (unique), `uidvalidity` (BigInteger), `last_uid` (BigInteger), `last_run_at`, `skipped` (Integer, last run).
- Server: `POST /v2/embed` body `{"texts": [str, ...], "profile": "classifier" | "campaign"}` (at most 32 texts), bearer token as the other `/v2` routes; answer `{"vectors": [[float, ...], ...], "preprocessing_version": "legacy-first128", "embedding_version": "cmp-e1"}`; 503 while the vectorizer is not loaded.
- `AiInferenceClient.embed(texts: list[str], profile: str) -> dict` (same error handling as `classify`).
- `ai_model/messageid.py`: `normalise(header: str) -> str`, `message_id_hash(normalised: str) -> str`, `stored_sender(mail: Mail) -> str`, `match_case(message_id: str, *, sender: str = "", date=None, subject: str = "") -> Case | None`.
- `connectors/contrib/ai_model/mailtext.py`: `text_from_message(message: email.message.EmailMessage) -> str`.
- `connectors/contrib/ai_model/imap_sync.py`: `ReviewMail(folder, uidvalidity, uid, message_id, sender, date, subject, text, inner_message_ids)` (the labelled mail is the first `message/rfc822` part in document order; `inner_message_ids` holds the normalised Message-IDs of `message/rfc822` parts nested inside it, depth-first, a match fallback only; `date` is aware, a naive Date taken as UTC, `None` when missing or invalid); `read_folder(imap, folder, *, since_uid, limit, known_uidvalidity=None) -> tuple[list[ReviewMail], int, int, int]` (mails, skipped count, current `uidvalidity`, `last_uid`: the highest UID examined, skipped ones included, `since_uid` when none is newer). When `known_uidvalidity` is given and differs from the folder's, the same call reads from UID 0. `FolderUnavailable` (this folder only: a name with a control, DEL or non-ASCII character, refused before anything is sent; a failed SELECT or SEARCH) and `ImapConnectionLost` (`imaplib.IMAP4.abort`, `OSError`, `TimeoutError` at any point; fatal for the run; the message is the exception class name only). `connect` raises `ImapLoginFailed` (message: the original exception class name only) when login fails. Error messages show the folder name in `ascii()` form, at most 64 characters. A refused fetch of one UID counts it as skipped and `last_uid` moves past it, so that mail is not retried. Sizes are asked once per batch with `UID FETCH <uids> (RFC822.SIZE)`, so a mail above 25 MB is skipped without being downloaded. The folder name is sent as an IMAP quoted string.
- `ai_model/ledger.py`: `prepare_folder_observation(mail: ReviewMail) -> FolderObservation | None` (read-only pre-pass: key, class, matched case, snapshot; None for an unknown folder or a message already observed there, i.e. a row for that folder that is active or flagged; a superseded one does not count), `record_folder_observation(observation, vectors, *, preprocessing_version, embedding_version) -> LabelRecord | None` (re-checks, supersedes every other non-superseded folder row of the message, active or flagged, inserts the new row, flagged when it conflicts with the active verdict), `is_observed(mail) -> bool`, `record_verdict(case, user, label_class) -> LabelRecord | None`, `record_challenge(case, proposed) -> LabelRecord | None` (supersedes the case's earlier active proposal), `resolve_flag(record, user, note, *, keep: bool)` (re-reads the row under a lock; ValueError unless flagged), `ledger_summary() -> dict` (`{"by_source": {source: {class: n}}, "flagged": n, "trainable": n}` over the rows not superseded).

---

### Task 1: Taxonomy, models, migration

**Files:** Create `ai_model/taxonomy.py`, `ai_model/migrations/0002_label_ledger.py`, `ai_model/admin.py`, `ai_model/tests/test_taxonomy.py`, `ai_model/tests/test_label_models.py`. Modify `ai_model/models.py`.

- [ ] **1. Tests first:** `class_of("2_WHALING_PHISHING") == "Dangerous"`, `"1_NEWSLETTER" -> "Unwanted"`, `"0_LEGIT_EXTERNAL_COMMUNICATION" -> "Safe"`, `"Inbox" -> None`; `FOLDERS` has 8 entries; `LabelRecord.trainable` is true only for an active folder row; a row can be created with a null case; deleting the case keeps the row with `case` null; admin registers both models read-only (no add, change or delete permission).
- [ ] **2. Implement** the two models per Contracts, the taxonomy module and the read-only admin; generate the migration.
- [ ] **3. Run** `ww test backend ai_model`. Commit: `feat(ai-model): add the label ledger models`.

### Task 2: `POST /v2/embed`

**Files:** Modify `Analyzers/AIMailAnalyzer/inference_server/v2.py`, `connectors/contrib/ai_model/client.py`, tests `Analyzers/AIMailAnalyzer/tests/test_inference_server_v2.py`, `connectors/contrib/ai_model/tests/test_client.py`.

- [ ] **1. Tests first** (the `make_client` fixture and `FakeVectorizer` already exist): auth required (401 without the token, 503 when unconfigured, as the other routes); a 2-text request returns 2 vectors of 768 floats and the version fields; `profile` other than `classifier|campaign` gives 422; more than 32 texts gives 422; a text longer than `max_chars` is truncated, not rejected; vectorizer not loaded gives 503; the campaign vector for a text equals the vector `classify` returns as `campaign_embedding` for the same text. Client: `embed` sends the bearer token, returns the dict, maps 503 to `ProviderUnavailable` like `classify`, and the error text carries only the status (no body).
- [ ] **2. Implement** the route inside `make_v2_router` (same `Depends(require_token)`, inference slot, surrogate-safe truncation) and `AiInferenceClient.embed`.
- [ ] **3. Run** the inference tests and `ww test backend connectors`. Commit: `feat(inference): add the /v2/embed route and client call`.

### Task 3: Message-ID and the mail text function

**Files:** Create `ai_model/messageid.py`, `ai_model/tests/test_messageid.py`. Modify `connectors/contrib/ai_model/mailtext.py`, `connectors/contrib/ai_model/tests/test_mailtext.py`.

- [ ] **1. Tests first:** `normalise("  <ABC.123@Mail.Example>  ") == "abc.123@mail.example"`; empty or garbage gives `""`; `message_id_hash` is the SHA-256 hex of the normalised value; `match_case` finds a case whose stored `MailHeader.header_value` (the `defaultdict(list)` repr, built as `mailtext.header_dict` reads it) has that Message-ID; case-insensitive; no match gives `None`; with an empty Message-ID, one case with the same sender, UTC day and subject matches, two such cases give `None`, none gives `None`; `text_from_message` returns the plain part when there is one, else text reduced from the HTML part (tags and scripts dropped), decodes charsets, and returns `""` for a message with neither.
- [ ] **2. Implement.** `match_case` reads `Mail.mail_header.header_value` through `header_dict` and compares normalised ids; narrow the candidate set with an indexed filter first (do not parse every mail); the fallback reads sender from the `From` header when `Mail.mail_from` is blank. `text_from_message` reuses `html.parser` from the standard library, no new dependency.
- [ ] **3. Run** `ww test backend ai_model connectors`. Commit: `feat(ai-model): match mails by Message-ID and extract review mail text`.

### Task 4: IMAP reader

**Files:** Create `connectors/contrib/ai_model/imap_sync.py`, `connectors/contrib/ai_model/tests/fake_imap.py`, `connectors/contrib/ai_model/tests/test_imap_sync.py`.

- [ ] **1. Tests first** against a `FakeImap` that implements `select(folder, readonly)` (answers `UIDVALIDITY`), `uid("SEARCH", ...)`, `uid("FETCH", uid, "(BODY.PEEK[])")`, `logout` and records every command: `select` is always called with `readonly=True` and no store/copy/expunge command is ever issued; only UIDs above `since_uid` are fetched, the lowest `limit` of them, and `last_uid` is the highest UID examined (skipped ones included, `since_uid` when nothing is newer); a forwarded `message/rfc822` attachment yields a `ReviewMail` with the inner message's Message-ID, sender, date, subject and text; a mail that is not a forward (no `message/rfc822` part), an unparseable message, and a message over 25 MB each count in `skipped` and yield nothing; a `known_uidvalidity` different from the folder's makes the same call read from UID 0 and return the new `uidvalidity`; a folder name with a space is selected as a quoted string; an empty folder returns `([], 0, uidvalidity, since_uid)`; a missing folder (select fails) raises `FolderUnavailable`.
- [ ] **2. Implement** `read_folder` and `connect(host, port, user, password, use_ssl, timeout=30)` returning an `imaplib.IMAP4_SSL` or `IMAP4`. Exceptions never carry mail content: log the class and the folder name only.
- [ ] **3. Run** `ww test backend connectors`. Commit: `feat(ai-model): read the review folders over IMAP`.

### Task 5: Connector sync and folder rows

**Files:** Create `ai_model/ledger.py`, `ai_model/tests/test_ledger.py`. Modify `connectors/contrib/ai_model/connector.py` (config fields, `schedules`, `sync`), `connectors/contrib/ai_model/tests/test_connector.py`, `ai_model/tests/test_label_sync.py` (new).

- [ ] **1. Config and schedule:** `ConfigField` entries `imap_host` (str), `imap_port` (int, default 993), `imap_user` (str), `imap_password` (secret), `imap_use_ssl` (bool, default true), `imap_folders` (str, default the 8 names comma separated); `schedules=(Schedule("label-sync", 86400),)`. Update `ManifestTest.test_config_schema` and add a test that the secret is registered for the Vault overlay (`SECRET_FIELDS`).
- [ ] **2. Ledger tests first:** `record_folder_observation` creates an active `trust="folder"` row with the message hash, the label class from the folder, the case when matched, the two vectors and the snapshot of Ruling D9; the same message and folder again adds no row; the same message in another folder adds a row and supersedes the old active folder row; an unmatched mail (no case) still creates a row with `case` null.
- [ ] **3. Sync tests first** (patch `imap_sync.connect` with the fake, patch the client's `embed`): `sync()` returns quietly and does nothing when `imap_host` is empty; reads each configured folder with a known class, skips unknown ones, embeds both profiles per new mail (batches of at most 32 texts, one call per profile), writes rows, advances `LabelSyncState.last_uid` to the `last_uid` `read_folder` returns (so skipped mails are not re-read) and sets `skipped`; the 500-per-folder cap holds across runs; a `UIDVALIDITY` change (passed as `known_uidvalidity`) re-reads the folder from UID 0 in the same run and stores the new `uidvalidity`, without duplicating rows (the idempotence rule skips known observations); an IMAP login failure raises a `ConnectorError`-style failure whose message has no credentials; `/v2/embed` unavailable leaves `last_uid` unchanged so the next run retries.
- [ ] **4. Implement** `sync()` as: build the client, connect, loop folders, `read_folder`, embed, `record_folder_observation`, checkpoint after each folder. Use one DB transaction per folder batch.
- [ ] **5. Run** `ww test backend ai_model connectors`. Commit: `feat(ai-model): sync the review folders into the label ledger`.

### Task 6: Verdict and challenge rows, flags, summary

**Files:** Modify `ai_model/ledger.py`, `api/views/investigations.py` (`_apply_verdict`), `tasp/services/challenge.py` (`mark_challenged`), tests `ai_model/tests/test_ledger.py`, `api/tests/` (verdict hook), `tasp/tests/` (challenge hook).

- [ ] **1. Tests first:**
  - `record_verdict(case, user, "Safe")` creates `source="analyst_verdict"`, `trust="verdict"`, `source_ref` = `"user:<pk>"` (no username or address in the ledger), `message_id` from the case's mail (empty when none); an identical later verdict adds nothing, a different one adds a row and supersedes the older verdict row.
  - `record_challenge(case, "Safe")` creates `source="challenge"`, `trust="proposal"`; a blank proposal creates nothing; a proposal row is never `trainable`.
  - Conflict rule: an active folder row of class Dangerous and a verdict row of class Safe for the same case (and the reverse) set the folder row to `flagged` with `flag_reason="folder_verdict_mismatch"`, whichever row arrives second; Unwanted or Suspicious or Inconclusive on either side never flags; a flagged row is not `trainable`.
  - `resolve_flag(record, user, note, keep=True)` sets status `active` and fills the resolution fields; `keep=False` sets `superseded`; resolving an unflagged row raises `ValueError`.
  - `ledger_summary()` returns counts per source and class, the number flagged and the number trainable.
  - Hook tests: `_apply_verdict` writes a verdict row when `ai_model` is enabled and none when disabled; if `record_verdict` raises, the verdict is still saved and the response unchanged (patch it to raise); `mark_challenged` writes the proposal row the same way.
- [ ] **2. Implement** the three recorders, the conflict check (inside the same function that appends a row, in one transaction), `resolve_flag`, `ledger_summary`, and the two guarded hooks (`try/except Exception` logging the class only, after the case save).
- [ ] **3. Run** `ww test backend ai_model api tasp`. Commit: `feat(ai-model): record verdicts and challenges and flag conflicts`.

### Task 7: Backfill command

**Files:** Create `ai_model/management/commands/ai_model_backfill_labels.py`, `ai_model/tests/test_backfill_labels.py`.

- [ ] **1. Tests first:** the command records a verdict row for every case with `last_update_by` set (class from `Case.results`) and a proposal row for every case with a non-empty `challenge_proposed_result`; running it twice adds no row; `--folders` runs the review-folder sync for all folders without the per-run cap (`--all`) using the patched fake IMAP; `--dry-run` writes nothing and prints counts; it refuses to run when `ai_model` is disabled or no IMAP host is configured for `--folders`.
- [ ] **2. Implement** with the Task 5/6 functions; print counts only, never mail data.
- [ ] **3. Run** `ww test backend ai_model`. Commit: `feat(ai-model): add the label backfill command`.

### Task 8: Campaign sibling labels in the case view, docs

**Files:** Modify `ai_model/presentation.py`, `ai_model/tests/test_presentation.py`, `suspicious-ui/src/features/submissions/api.ts`, `suspicious-ui/src/features/submissions/components/AiAssessmentSection.tsx` and its test, `CHANGELOG.md`, `docs/components/analyzers.md`, `docs/plans/2026-10-30-ai-model-connector.md`, `docs/plans/2026-10-31-ai-model-connector-c-case-view.md`.

- [ ] **1. Backend tests first:** for a case in a campaign, `campaign` gains `labels` (a dict class to count, from active folder rows of the sibling cases, this case excluded) and `members_disagree` (true when the labelled siblings contain both Dangerous and Safe, or this case's AI class is Dangerous while a sibling folder label is Safe, or the reverse); no labelled siblings gives `labels == {}` and `members_disagree False`; labels are shown only to elevated viewers (same gate as `cross_check`); one query for all siblings' labels.
- [ ] **2. UI tests first:** the campaign line shows "Labelled by analysts: 3 Dangerous, 1 Safe" when `labels` is non-empty and a "Campaign members disagree" alert when `members_disagree`; absent for reporters (`labels` absent) and when empty. Sibling labels never appear as numbers other than these counts.
- [ ] **3. Implement.** Update the Plan C contract block and the TS type (`labels?: Record<string, number>`, `members_disagree?: boolean`).
- [ ] **4. Docs:** `analyzers.md` section "Label ledger" (what is stored, the nightly sync, the read-only mailbox, folders and their classes, the config fields, precedence and flags, the backfill command), CHANGELOG Added bullets, mark Plan D done in the master plan ("built on feature/ai-model-label-ledger, not merged" until merged) and remove the deferred sentence in the Plan C doc.
- [ ] **5. Run** `ww test backend ai_model api`, `ww test frontend`, the inference tests and the full `ww test backend`. Commit: `feat(ai-model): show campaign sibling labels in the case view`.
