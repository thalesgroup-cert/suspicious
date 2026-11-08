# AI Model Connector: Master Implementation Plan

> **For agentic workers:** This is the programme plan. Each sub-plan below is a separate document; execute one at a time with superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax. Plan A is fully detailed. Plans B to G are task outlines that are detailed, in order, when the plan before them has landed, because they build on interfaces Plan A creates.

**Goal:** Replace the Cortex AI mail analyzer with an `ai_model` connector that scores mail through a provider slot, learns from analyst labels, retrains on demand or on a schedule, proves a candidate in shadow before an admin promotes it, and keeps phishing-campaign detection and its TheHive alert working.

**Architecture:** A provider slot in the case pipeline calls the connector, which calls a token-protected inference server. Versioned model bundles (heads, nearest-neighbour index, calibration, campaign profile) live in object storage and are tracked by a registry. A label ledger fed from the review folders and verdict edits drives retraining. A candidate runs in shadow, including a campaign dry run, then an admin promotes it. Campaign detection moves into the connector.

**Tech Stack:** Django, Celery, pybreaker, ChromaDB, FastAPI, torch, scikit-learn, React 19 and MUI, Vitest, Playwright.

**Spec:** `docs/specs/2026-10-30-ai-model-connector-design.md`

## Global Constraints

Values copied from the spec; every plan's tasks include them.

- Shadow minimum 7 days and 500 mails; every Safe-to-Dangerous or Dangerous-to-Safe verdict flip and every campaign in the alert delta reviewed; the gate re-run with the labels that arrived during shadow.
- Provider call: 20 s total timeout, at most 2 retries on transient errors only, exponential backoff with jitter, `acks_late` and `reject_on_worker_lost`, case never waits more than about a minute.
- A class is decided only at a calibrated probability of at least 0.5, else Inconclusive. Tiers: High at 0.85 and above, Medium from 0.60, Low below (illustrative; stored per version). Score mapping: Safe 0-5, Unwanted 5-6.5, Dangerous 6.5-10, linear in confidence. No numeric confidence on screen.
- Recipe: `ResNetMLP` heads, 30 epochs, Adam 1e-3, class weights only (no SMOTE, no oversampling); main decision is the mean of the calibrated head hierarchy and a 5-nearest-neighbour vote (cosine, distance-weighted); whole body in chunks of about 90 words, at most 8, averaged; one temperature fitted on held-out groups.
- Groups: near-duplicate at cosine 0.95 on the classifier embedding; campaign groups at similarity 0.75 on the campaign embedding, joined with `CampaignMember` ties.
- Gate: Dangerous called Safe not above the baseline plus a tolerance (plan-level call: 0.01); macro-F1 not more than 0.02 below the baseline; calibration error below 0.12; at least 8 samples per class in every head, and a head that cannot train fails the candidate; High tier right at least 90% of the time; same check on held-out campaign groups. Baseline is the active recipe retrained on the same folds; 3 repeats.
- Campaign profile `cmp-e1`: first 128 tokens of `paraphrase-multilingual-mpnet-base-v2`, cosine distance 0.25, 3 minimum members, 20 neighbours, 15-day window, trigger "AI class is Dangerous", collection `suspicious_mails` (later profiles `suspicious_mails__<embedding_version>`).
- Only folder labels train; verdicts and challenges are provenance. Only a Dangerous-against-Safe conflict flags a label. A `Message-ID` from the stored headers, not `Mail.mail_id`, matches folder mails to cases.
- Volumes: about 85 mails a day, 20 to 30 challenged mails a month. Model age warning at 60 days. Purity warning below 80% over 30 days with at least 10 labelled members.
- Repository conventions: Conventional Commits (subject at most 72 characters, body lines at most 100), no `Co-Authored-By` trailer, a `CHANGELOG.md` entry per change, backend tests through `ww test backend <label>`, nothing pushed. Plans live in `docs/plans/`, specs in `docs/specs/`.

## Review Focus

Programme-level conditions the spec implies and no single task owns; each is pinned by a test in the plan named.

- A live case already in the ledger (after "Redo analysis") finding itself as its own nearest neighbour (Plan E).
- The review mailbox changing `UIDVALIDITY`, a folder missing, or a forwarded mail without an attachment: the sync skips and reports, never crashes or double-counts (Plan D).
- The same campaign finalising on several workers at once: one `Campaign`, one TheHive alert (Plan B, via the existing lock).
- A promotion while a training job or a shadow seeding is running (Plan F).
- The module disabled with cases that already carry assessments: the section is hidden, nothing 500s, scoring still reads the stored fields (Plans A and C).

## How the work is split

| Plan | Delivers | Spec sections | Depends on |
|---|---|---|---|
| A. Provider slot, server v2, version 0 | The AI result comes from the connector, same values as the Cortex job | 1, 2, 3 (v0), 10, 11 step 2 | none |
| B. Campaigns in the connector, Cortex cutover | Campaign detection and the TheHive alert run from the connector; the Cortex AI path is removed | 7, 11 steps 2-3 | A |
| C. Case view: AI assessment section | The new section with tier, similar cases (empty until Plan D), campaign line and cross-check | 8 (case part), 7 (campaign line) | A |
| D. Label ledger and sync | Ledger, review-folder sync about every 24 hours, verdict and challenge rows, flags, campaign sibling labels | 4, 7 (sibling labels) | A |
| E. Retrain, gate and registry | Candidate versions from the ledger, gated, stored as bundles | 3, 5, 9, Evidence | A, D |
| F. Shadow, promotion, campaign dry run, counters | Shadow scoring, promote and rollback, alert delta, per-version stats | 6, 7 (versioning, counters), 9 | A, B, E |
| G. Settings AI model card | The admin card, queue and connector line | 8 (Settings part), 10 | D, E, F |

Order: A, then B and C (parallel), then D, E, F, G. Release checkpoints: **R1** = A + B + C (cutover to the connector, behaviour unchanged, Cortex job gone); **R2** = D + E (ledger and candidates, driven by a management command); **R3** = F + G (shadow, promotion and the admin card).

## Shared contracts

Names later plans rely on; Plan A defines the first four.

- `ai_model.models.AiAssessment` (OneToOne to `Case`, `related_name="ai_assessment"`): `model_version`, `result`, `sub_class`, `score`, `confidence`, `probabilities`, `sub_probabilities`, `tier`, `contributing_phrases`, `similar_cases`, `campaign_embedding`, `embedding_version`, `latency_ms`.
- `connectors.base.ProviderResult`, `Connector.analyze(kind, case_id)`, `ConnectorManifest.provides`, `connectors.providers.{enabled_provider, queue_provider_analysis, finish_provider_analysis, has_provider_job, ProviderUnavailable}`.
- Server `/v2`: `GET health/live`, `GET health/ready`, `GET models/ai_mail`, `POST models/ai_mail/classify` (Plan A); `POST embed` (Plan D); `POST/GET train`, `POST reload` (Plan E); `versions` in classify extended to `["active", "shadow"]` (Plan F).
- Bundle transfer (plan-level call): Django hands the server presigned object-store URLs: GET for the training dataset and for bundles to load, PUT for a bundle the server produces. The server holds no storage credentials.
- `ai_model.models.ModelVersion` (status `candidate|shadow|active|previous|discarded`, bundle prefix, manifest JSON, campaign profile), `ModelEvent` (audit), `ModelVersionStats` (daily roll-up), `ShadowResult`, `ShadowCampaignEffect`, `LabelRecord` (Plans D, E, F).
- `ai_model.campaign_profile.CampaignProfile` (frozen dataclass of the profile fields) and `current_profile()` returning `cmp-e1` (Plan B).
- The connector's settings section is `integrations.ai_model` with `url`, `token`, `timeout_seconds` (Plan A) plus `imap_*` fields (Plan D).

## Plan A: Provider slot, server v2, version 0

**Status: done.** Built as `docs/plans/2026-10-30-ai-model-connector-a-provider-slot.md` describes and merged into the local `design/ai-model-connector` branch (not `main`, not pushed).

Detailed in `docs/plans/2026-10-30-ai-model-connector-a-provider-slot.md` (8 tasks: server v2 health and token, v2 classify, `ai_model` app and `AiAssessment`, provider extension point, dispatch with ledger row and Celery task, the connector, parity with the Cortex report, wiring and a dev-stack check).

## Plan B: Campaigns in the connector and the Cortex cutover

**Status: done.** Built as `docs/plans/2026-10-30-ai-model-connector-b-campaigns.md` describes and merged into the local `design/ai-model-connector` branch (not `main`, not pushed).

Detailed in `docs/plans/2026-10-30-ai-model-connector-b-campaigns.md` (10 tasks: campaign profile, mail material reader, detection port, subscription and task, collection-name check, parity replay command, dev-stack acceptance, then the cutover removal in three tasks that run only if the replay matches).

## Plan C: Case view, AI assessment section

**Status: done**, built on feature/ai-model-case-view, not merged. Detailed plan: `docs/plans/2026-10-31-ai-model-connector-c-case-view.md` (5 tasks). The outline below is the earlier sketch; the detailed plan's Calls table supersedes it (backend null instead of a UI connector hook, legacy caption kept for cases without an assessment, sibling labels wait for Plan D, which added them).

Deliverable: the case drawer and investigation overview show the new section only while the connector is enabled.

1. **API fields**: add `ai_assessment` (class, sub-class, tier, model version, age, similar cases, campaign line) to the submission and investigation serializers (`api/serializers/submissions.py`, `investigations.py`), `null` when the connector is disabled; similar cases filtered to cases the viewer may open.
2. **Cross-check facts**: `ai_model/crosscheck.py` builds the plain-fact list from the verdict explanation (decisive rule, sources, allow/deny hits, flagged links) and the "AI disagrees with the evidence" flag. Tests with the existing explanation fixtures.
3. **Component**: `suspicious-ui/src/features/submissions/components/AiAssessmentSection.tsx`, tier chip with its meaning, runner-up on Low, "confidence not calibrated" for version 0, similar cases table, campaign line, cross-check; shared by `OverviewTab.tsx` and `investigation/components/InvestigationOverview.tsx`, replacing the caption line.
4. **Hidden when disabled**: the section reads the enabled-connectors endpoint (`EnabledConnectorsView`); absent when `ai_model` is not enabled; old cases follow the spec (hidden too).
5. **Tests**: Vitest for each state (High, Low with runner-up, version 0, disabled, campaign conflict); Playwright path through a drawer.

## Plan D: Label ledger and sync

**Status: done**, built on feature/ai-model-label-ledger, not merged. Detailed plan: `docs/plans/2026-11-01-ai-model-connector-d-label-ledger.md` (8 tasks). The outline below is the earlier sketch; the detailed plan's Calls table supersedes it (folder taxonomy from the training notebook, text form and canonical recipe left to Plan E, a smaller snapshot without link domains, auth results or Cortex bands, verdict rows written while `ai_model` is enabled, challenge proposals recorded too, sibling labels in the case view included).

Deliverable: a sync about every 24 hours fills the append-only ledger from the review folders, read-only; analyst verdicts and reporter challenge proposals add rows beside it; a hard conflict between a folder label and the analyst verdict flags the folder row; `ledger_summary()` and `resolve_flag()` exist for Plan G, with no API yet; `ai_model_backfill_labels` backfills history without superseding verdicts recorded live, and matches unmatched folder rows to cases; the case view's campaign line shows the folder labels of the campaign siblings to analysts, with a "Campaign members disagree" warning.

1. **Models**: `LabelRecord` (spec section 4 table) with append-only supersession, migration, admin read-only.
2. **Server `POST /v2/embed`**: `{"texts": [...], "profile": "classifier"|"campaign"}` returning vectors; tests with the fake vectorizer.
3. **Message-ID**: `ai_model/messageid.py` with `normalise(header) -> str` and `match_case(message_id) -> Case | None` reading `Mail.mail_header` (repr of a dict); fallback on sender, date, subject. Tests with the dev header shape.
4. **IMAP reader**: `connectors/contrib/ai_model/imap_sync.py`: read-only `SELECT`, `UIDVALIDITY` handling, opens the forwarded `message/rfc822` part, extracts text with the single mail-text function, skips and counts folders or mails it cannot read. Tests against a fake IMAP.
5. **Connector `sync()`** on a nightly `Schedule`, config `imap_host`, `imap_port`, `imap_user`, `imap_password` (secret), `imap_use_ssl`, folder names; computes both embeddings through `/v2/embed`; stores a `snapshot` (sender domain from headers, link domains, auth results, Cortex bands, list hits, AI answer).
6. **Verdict rows**: record a `LabelRecord` from `_apply_verdict` (`api/views/investigations.py`) when the user is an investigator.
7. **Flags**: hard-conflict rule, `flagged` status and `resolve_flag(record, user, note)`; summary function for the card.
8. **Backfill command** `ai_model_backfill_labels` and tests for idempotence.

## Plan E: Retrain, gate and registry

**Status: done**, merged locally into design/ai-model-connector, not pushed. Detailed plan: `docs/plans/2026-11-01-ai-model-connector-e-retrain.md` (9 tasks, with a go/no-go checkpoint after Task 5). The outline below is the earlier sketch; the detailed plan's Calls table supersedes it.

Deliverable: `manage.py ai_model_retrain` (and a start/poll task) turns the ledger into a gated candidate stored as a bundle.

1. **One text function**: `Analyzers/AIMailAnalyzer/mailtext.py` (`mail_text(message) -> str`, html2text of text and HTML parts) used by sync and classify; a `ai_model_text_gap` command that embeds the same mails both ways and reports the cosine gap. Decide the canonical form from its output and record it in the preprocessing version.
2. **Training package** `Analyzers/AIMailAnalyzer/training/`: `recipe.py` (chunk-mean embedding, heads, nearest-neighbour index, blend, temperature), `groups.py`, `gate.py` (six checks, report with Wilson intervals), `bundle.py` (write and read a bundle). Port the test-bed logic from `~/ai-experiment/testbed/` (`lib_spike.py`, `exp_e_combined.py`, `exp_i_campaign_groups.py`).
3. **Evaluation regression**: a pytest module, marked `slow`, that runs the recipe on the stored 505-mail dataset and asserts grouped accuracy about 0.85 or better and Dangerous called Safe about 5% or lower within seed noise. Excluded from default CI.
4. **Server training job API**: `POST /v2/train`, `GET /v2/train/{id}`, `POST /v2/train/{id}/cancel`, 409 when busy, dataset fetched from a presigned URL, bundle uploaded to a presigned PUT URL.
5. **Registry**: `ModelVersion`, `ModelEvent`; bundle layout in the `ai-models` bucket; version 0 import from the mounted weights directory; `POST /v2/reload` with presigned bundle URLs.
6. **Start and poll**: Celery task that exports the ledger, starts the job, polls with short tasks, then creates a `candidate` `ModelVersion` with the report; schedule and the `ai_model_retrain` command; failure leaves the active model untouched.
7. **Calibrated scoring**: tier and `score_ai` mapping for versions that have calibration; version 0 keeps the legacy rule, and gets a fitted temperature (calibration only, on held-out ledger groups) once enough labels exist, so its tier can be shown.

## Plan F: Shadow, promotion, campaign dry run, counters (outline)

**Status: done**, merged locally into design/ai-model-connector (f936cc3c), not pushed; dev-stack acceptance run recorded in `docs/plans/2026-11-08-ai-model-f-acceptance-run.md`. Detailed plan: `docs/plans/2026-11-07-ai-model-connector-f-shadow.md` (11 tasks). The outline below is the earlier sketch; the detailed plan's Rulings supersede it (dry run on the live collection, gate recheck job, server sync, no v0 temperature fit).

Deliverable: a passing candidate becomes `shadow`, is compared on live mail, and can be promoted or rolled back.

1. **Dual classify**: server accepts `versions: ["active", "shadow"]`; provider stores `ShadowResult` and never lets a shadow failure touch the case (shorter timeout).
2. **Would-be verdict**: recompute the case verdict with the shadow answer as the AI vote through the pure engine (`score_process/scoring/engine.py`); store beside the shadow result. Add the offline command `ai_model_engine_replay` that replays recent cases through the engine with a candidate's answers, to measure the engine's sensitivity to calibrated confidence before the first promotion.
3. **Campaign dry run**: shadow collection seeded from the live one at shadow start; `detect_campaign(..., dry_run=True)` records `ShadowCampaignEffect`; alert delta against real `campaign_updated` events.
4. **Stats**: `ModelVersionStats` daily roll-up, purity, warnings.
5. **Promote, rollback, discard, extend**: conditions from the spec enforced server-side; atomic pointer moves; `ModelEvent` audit; reload call; concurrency with a running job refused.
6. **Review API**: review a flip or a campaign difference with a note; list of open items.

## Plan G: Settings "AI model" card

Status: done on branch `feat/ai-model-plan-g`, not pushed. Detailed in `docs/plans/2026-11-08-ai-model-connector-g-admin-card.md` (12 tasks: five backend reads and writes, then the card). Outline below kept for reference.

Deliverable: the admin card, hidden when the module is disabled.

1. **Read API**: status, versions, candidate and gate report, shadow comparison, ledger summary, queue.
2. **Card shell and status**: health, breaker with reset, active version and age with the 60-day warning, schedule and Retrain button.
3. **Candidate and gate**: results table, campaign-held-out result.
4. **Shadow panel**: agreement, differences, campaign dry-run table, alert delta, review actions.
5. **Versions**: history with counters and purity, rollback.
6. **Ledger and queue**: label mix with jump warnings, flagged labels with resolve, disagreement and campaign-conflict queue.
7. **Connector gallery line**, admin-only visibility, Vitest per state, Playwright path through retrain, shadow and promote.

## Self-review

- **Spec coverage:** every spec section maps to a plan in the table above; decisions D1-D13 are carried by A (D1, D11, D12), B (D10), C (D4, D5, D8, D9), D (D3), E (D2), F (D6, D7, D13), G (D2, D4).
- **Interfaces:** shared names are listed once under "Shared contracts"; Plan A fixes `ProviderResult` and `AiAssessment`, which all later plans use.
- **Proportion:** Plan A is the only detailed plan; B to G stay at task outlines until their turn, to avoid planning against interfaces that do not exist yet.
