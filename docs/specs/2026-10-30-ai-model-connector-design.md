# AI Model Connector: Design

Status: draft for approval. Nothing in this document is built. Marks used below:
**Decided** is the owner's decision; **Call** is a choice made while writing, listed again in
[Calls made in this document](#calls-made-in-this-document) so it can be reversed.

## Context

The AI mail analyzer classifies a mail body as Safe, Unwanted or Dangerous and, for Dangerous and
Unwanted mails, a sub-type. Today it runs as a Cortex analyzer (`AI_Mail_Analyzer`) that is a thin
HTTP client to a separate model server (`ai_inference`). Retraining is a set of scripts under
`Analyzers/AIMailAnalyzer/retrain_model_monthly/` that nobody schedules, and the weights are
git-ignored and copied around by hand.

What the owner wants: simplify and improve the analyzer and its server so that training and
retraining become a module of Suspicious, a connector, not a Cortex job. An admin can launch a
retrain from Suspicious, on demand or on a schedule, and sees what the model is, how old it is and
how it behaves.

Measurements on the existing labelled data (505 mails) and on 269 production challenged cases
show three problems this design has to fix, not just move:

1. The reported test scores are inflated. About half the mails have a near-identical twin, and the
   random train/test split puts twins on both sides.
2. The confidence is not usable. The model reports 96-98% on average while being right 78-80% of
   the time on unseen groups.
3. The current production answer barely predicts what analysts decide on challenged mails.

The evidence is in [Evidence](#evidence). Its limits are stated there.

The AI analyzer is also the input of the phishing-campaign detection: at finalisation, campaign
detection reads the analyzer's report (score, class, embedding, mail text), groups similar
Dangerous mails into a campaign and emits the event that makes the TheHive connector raise a
phishing-campaign alert. Removing the Cortex job without carrying that over would stop campaigns and
those alerts silently. See section 7.

## Goals

- Run the AI step as an `ai_model` connector. The Cortex AI job, its image and the hard-coded
  gateway address go away.
- An admin starts a retrain from Settings, or schedules it. Retraining is one code path.
- A retrained model is checked on data it has not seen, runs in shadow on live mail, and goes live
  only when an admin promotes it. Rollback is one click.
- Confidence is calibrated and shown as High, Medium or Low, with the meaning of each level.
- Labels come from the analysts' existing process (review folders, verdict edits, challenges) and
  are recorded in a ledger with provenance.
- The AI result has its own section in the case view, shown only while the module is enabled.
- Failure of the model server never blocks a case for long and never fakes a result.
- Phishing-campaign detection and the TheHive phishing-campaign alert keep working with the same
  behaviour, and belong to the connector. Their parameters are versioned with the model, the gate
  measures how a model does on campaigns it has not seen, and shadow shows how a candidate would
  change campaign alerts before it goes live.

## Non-goals

- No automatic promotion. No retraining on every verdict edit.
- No change to scoring weights or to how the engine combines votes.
- No Cortex or allow-list results as inputs to the model (see [Evidence](#evidence), E5).
- No public corpora in training. They are used only as an optional check.
- No sender, subject or link features in the model in v1. The ledger records them so a later
  version can use them without a backfill.
- No SetFit, no local language-model triage, no per-user models.
- No new TheHive alert types. The campaign alert, the challenge alert and the push button keep their
  current behaviour.
- Campaign membership is not an input of the model and does not create training labels. It is
  derived from the model's own Dangerous call and the embedding, so using it would be circular.
- No external services: everything runs locally on CPU hosts.

## Anti-goals

- A model that looks sure and is wrong. Uncalibrated numbers must not reach the screen.
- A silent change of verdicts. A new model never counts before it has run in shadow.
- Labels an attacker can write. The ledger has to survive someone filing a mail in the wrong folder.
- A second retrain path. Scripts, notebooks and the connector must not drift apart.

## Decisions

| # | Decision |
|---|---|
| D1 | **Decided.** Full connector in v1; the Cortex `AI_Mail_Analyzer` job is removed. |
| D2 | **Decided.** A button in Suspicious launches a retrain, on demand or scheduled. |
| D3 | **Decided.** Both label sources are used, with provenance: analyst-filed review folders and Suspicious verdicts and challenges. Labels are read on the connector's own schedule. |
| D4 | **Decided.** The AI result has its own section in the case view; it is not rendered when the module is disabled. |
| D5 | **Decided.** Confidence is shown as High, Medium or Low, not as a percentage. |
| D6 | **Decided.** A passing candidate waits for an admin to promote it. |
| D7 | **Decided.** A candidate runs in shadow on live mail before it can be promoted. |
| D8 | **Decided.** v1 shows similar past cases as a hint. The hint itself does not change a verdict. The promoted model's answer does feed the AI score. |
| D9 | **Decided.** No Cortex results as model inputs in v1. v1 shows a deterministic cross-check instead. |
| D10 | **Decided.** The phishing alert to TheHive that depends on the AI analyzer (campaign detection and its alert) moves to the connector and keeps working. |
| D11 | **Decided.** The Celery worker can reach the review mailbox over IMAPS, as the email feeder does. |
| D12 | **Decided.** The `ai_inference` image can download the encoder from Hugging Face at build time. |
| D13 | **Decided.** Campaign detection is part of the model versioning in v1: a campaign profile per version, campaign-level evaluation in the gate, a campaign dry run in shadow, live campaign counters per version, and a campaign cross-check in the AI section. A live new-campaign recall per version is deferred. |

Volumes given by the owner: about 2,550 mails analysed per month (about 85 a day) and 20 to 30
challenged mails per month.

## Design

### Overview

```
IMAP review folders --nightly--> label ledger (DB) <--- Suspicious verdicts / challenges
                                      |
                  Retrain (button / schedule) --HTTP--> ai_inference (training job)
                                      |                      |
                              ModelVersion registry <-- bundle in object storage
                                      |
case pipeline --> analysis provider --> ai_inference /classify (active [+ shadow])
                       |                              |
          score_ai fields, AiAssessment      similar cases, tier, sub-type, campaign embedding
                       |
                reconcile_case --> engine --> verdict --> case_finalised
                                                              |
                          ai_model connector: campaign detection (ChromaDB "suspicious")
                                                              |
                                  campaign_updated --> TheHive connector --> phishing alert
```

Four pieces: the **analysis-provider slot** in the case pipeline, the **`ai_model` connector**
(settings, health, labels, retrain control, campaign detection), the **inference server** (classify,
train, health), and the **UI** (case section, Settings card).

### 1. The analysis-provider slot

Connector events are notifications after the fact; none of them can return a result into scoring.
The AI step needs one. This design adds a small extension point to the connector framework:

- A connector may declare `provides = "mail_ai"`. At most one enabled connector provides each kind.
- Where the pipeline launched the Cortex AI job (`CortexJob`, `cortex_and_job_management.py`),
  it asks the registry for the `mail_ai` provider. If there is none, nothing is queued and the case
  proceeds without an AI vote, as it does today when the AI job fails.
- Queuing writes the same ledger row the webhook flow relies on (`CaseAnalyzerJob`, status
  in-progress) for a virtual analyzer whose name is the configured AI analyzer name
  (`cortex.analyzers.ai`). `reconcile_case_core` already waits for pending ledger rows, so the
  case waits for the AI step exactly as it waits for a Cortex job. The analyzer's weight stays on
  its `Analyzer` row in Settings.
- A Celery task, `run_provider_analysis(case_id, kind)`, calls the connector, writes the result and
  closes the ledger row, then enqueues `reconcile_case` as the webhook view does.

**What gets written.** The same fields `manage_ai_jobs` writes today: `case.results_ai`,
`score_ai`, `confidence_ai`, `category_ai`, and the `MailInfo` flags. A new field records the model
version that produced the result. A new per-case **AI assessment record** (`AiAssessment`, in the
`ai_model` app) holds the rest: class and sub-class, calibrated probabilities, tier, the campaign
embedding and the similar past cases. The UI section and campaign detection read it. Everything
that reads the AI result today must keep working: `collect_votes` (`AiSignal`), the
`ai-classifier-decisive` explanation rule, the reconcile wait, and the existing analyzer card until
the new section replaces it. Whether the result is also kept as an `AnalyzerReport` row is left to
the builder, within that constraint.

**Failure behaviour.**

- One HTTP call to the model server with a total timeout of 20 seconds (**Call**).
- Retry only on transient errors (connection, 5xx), at most 2 times, with exponential backoff and
  jitter. A 4xx or "model not ready" answer is not retried.
- After the last attempt, or immediately when the circuit breaker is open: `results_ai =
  Inconclusive`, ledger row closed as failure, reason recorded. The case must not wait more than
  about a minute for the AI step. `fail_stale_jobs` remains the backstop.
- The existing connector circuit breaker is reused. Its state changes are logged and visible, and
  an admin can reset it from the Settings card.
- The task is idempotent: for a given case and model version it writes the same values again and
  closes the same row. It is declared with `acks_late` and `reject_on_worker_lost`, so a killed
  worker re-delivers it instead of dropping it.

### 2. The inference server

The existing FastAPI server (`Analyzers/AIMailAnalyzer/inference_server/`) becomes the only place
that holds the encoder, the classifier heads and the training code. It already ships torch.

**API** (shape borrowed from the Open Inference Protocol, not its tensor format):

| Endpoint | Purpose |
|---|---|
| `GET /v2/health/live`, `GET /v2/health/ready` | Liveness; readiness only when encoder and active bundle are loaded |
| `GET /v2/models/ai_mail` | Metadata: active and shadow version, preprocessing version, encoder id, trained-at |
| `POST /v2/models/ai_mail/classify` | Body plus the versions to score with (`active`, optionally `shadow`) |
| `POST /v2/embed` | Embedding of a text under a named preprocessing version (used by label sync) |
| `POST /v2/train`, `GET /v2/train/{id}`, `POST /v2/train/{id}/cancel` | Start, poll, cancel a training job |
| `POST /v2/reload` | Load bundles named by the registry |

**Authentication.** A bearer token from the connector config (stored in Vault). The server rejects
requests without it. The host port on the Docker bridge gateway is dropped: Celery reaches the
server by service name on the internal network, which removes the gateway-IP URL. Only the
`ai_inference` service and Celery share that network.

**Classify.** For each requested version the server returns the class probabilities after
calibration, the tier, the sub-type with its probabilities, up to 5 similar past cases (case id,
similarity, label, provenance), the version ids and the latency. Once per call it also returns the
**campaign embedding**, computed with a fixed preprocessing (first 128 tokens of the same encoder)
that does not change with the classifier recipe (section 7). The legacy `/classify` endpoint is
removed with the Cortex job.

**Input.** The model version names its preprocessing. v1 of the recipe reads the whole body in
chunks of about 90 words (at most 8) and averages the chunk embeddings. The legacy preprocessing
(first 128 tokens) stays available, because the imported legacy model needs it.

**One text function.** The text the model sees must come from one function, used for live cases
and for ledger mails alike, and its name goes into the preprocessing version. Today they differ:
the Cortex job classifies the parsed body (`.txt`) from the mail archive, while the retrain scripts
embed the `html2text` rendering (links kept, images dropped) of the text and HTML parts of the filed
mail, and every figure in this document was measured on that second form. The builder first embeds
the same mails both ways and measures the gap, then picks the canonical form. Version 0 keeps its
legacy extraction so cutover stays neutral.

**Resources.** CPU only. One training job at a time; a second request gets 409. Training uses a
bounded number of torch threads and must not starve classify (builder to set limits).

### 3. Model versions and the registry

A **model version** is a bundle in object storage (existing `ObjectStore` layer, a bucket for
models, prefix per version):

| File | Content |
|---|---|
| `heads/*.npz` | (Plan E Ruling E15: float32 arrays per state-dict key, not pickled `.pth`) The five heads: safe/unwanted split, spam/dangerous split, internal/external, spam/newsletter, phishing sub-type |
| `calibration.json` | Temperature for the main decision and the tier cutoffs derived from held-out data |
| `knn_index.npz` | Embeddings, label ids and case ids of the labelled mails used |
| `campaign_profile.json` | The campaign profile (below) |
| `manifest.json` | Version id, recipe id, preprocessing version, encoder id and hash, ledger snapshot digest, the campaigns the training labels belonged to (references and a digest), metrics and gate results, parent version, trainer revision |

**Campaign profile.** The settings under which campaign detection works, recorded with every
version and copied to every `AiAssessment`:

| Field | Value today |
|---|---|
| `embedding_version` | `cmp-e1` (a name, bumped on any change below) |
| `encoder_id`, `encoder_hash` | `paraphrase-multilingual-mpnet-base-v2` and its hash |
| `preprocessing` | first 128 tokens, as today |
| `metric`, `distance_threshold` | cosine, 0.25 |
| `min_members`, `n_neighbours` | 3, 20 |
| `window_days` | 15 |
| `trigger` | the AI class is Dangerous |
| `allow_list_digest` | digest of the campaign sender allow-list when the version was made |

A new classifier version normally copies the active profile unchanged. A version that changes it is
a profile migration (section 7).

The DB registry (`ModelVersion`) holds status `candidate`, `shadow`, `active`, `previous` or
`discarded`, a pointer to the bundle, who and what triggered the training, and the manifest.
`active` and `shadow` are pointers that can be moved; every move writes an audit row (`ModelEvent`)
with the user, the time and a note. Models for these tables live in a new Django app, `ai_model`,
so its migrations are isolated (**Call**).

The registry also keeps a daily roll-up per version (`ModelVersionStats`): mails scored, Dangerous
calls, campaign checks, campaigns created and joined, TheHive campaign alerts raised. Each
`AiAssessment` names the version that produced it, so every campaign event is attributed to a
version.

**Version 0.** On first enable, the connector imports the weights that run in production today as
version 0, with the legacy preprocessing and the legacy decision rule. Cutover therefore changes no
verdict. Version 0 has no calibration, so its tier is computed by fitting a temperature on the
ledger once enough labels exist; until then the UI shows "confidence not calibrated" for it.

### 4. The label ledger

One row per label observation, append-only. A correction adds a row that supersedes the old one.

| Field | Notes |
|---|---|
| `message_id` | Normalised `Message-ID` header of the original mail, and its hash |
| `case` | FK to the Suspicious case, null until matched |
| `source` | `imap_folder`, `analyst_verdict`, `challenge` |
| `source_ref` | Folder name and IMAP UID/UIDVALIDITY, or the user |
| `label` | The 8-folder taxonomy value, with the derived Safe/Unwanted/Dangerous class |
| `trust` | `folder` (filed by an analyst), `verdict` (edit in Suspicious), `proposal` (reporter, never trained on) |
| `observed_at` | When the label was seen |
| `embedding`, `preprocessing_version` | Vector computed by the model server |
| `campaign_embedding`, `embedding_version` | The vector under the campaign profile, used to build campaign groups |
| `snapshot` | Sender domain (from the stored headers), subject length, link domains, SPF/DKIM/DMARC, Cortex band per analyzer, allow/deny hits, the AI answer at that time. Not used in v1 |
| `status` | `active`, `superseded`, `flagged` |
| `flag_reason` | For example `folder_verdict_mismatch`, `duplicate` |

**Sync.** A scheduled sync (nightly, **Call**) reads the 8 review folders read-only, opens the
forwarded `message/rfc822` attachment, extracts its `Message-ID` header, and matches it to the
`Message-ID` in the stored mail headers (`Mail.mail_header`). `Mail.mail_id` cannot be used: it is
the feeder's generated id, not the Message-ID (checked on the dev stack). A mail without a
Message-ID is matched on sender, date and subject; the builder details that. The first run
backfills the whole history and computes both embeddings (classifier and campaign) for each row. Verdict rows come from cases an analyst edited (`last_update_by` set),
recorded when the edit happens.

**Precedence.** The folder is the label of record and the only source the model trains on. The
verdict and the challenge are provenance, used for cross-checks and shadow comparisons (**Call**).
Only a hard conflict counts as a mismatch: a Dangerous folder against a Safe verdict, or a Safe
folder against a Dangerous verdict. A mismatch sets `flagged` and keeps the row out of training
until an admin resolves it in Settings (**Call**). The folder taxonomy has 8 values and the
analyst verdict has 4, so a Suspicious verdict is never converted into a training label.

**Poisoning controls** (the feedback loop is an attack surface):

- Folder labels exist only if the mail sits in a folder of the review mailbox; access to that
  mailbox is the control. Verdict labels exist only through the investigator-only verdict API.
- Every row, resolution and promotion is audited.
- Near-duplicate mails count once in training and evaluation (see the gate).
- The Settings card shows the label mix and warns when one source or one class jumps.

The ledger stores an embedding, not the mail text. Re-embedding under a new preprocessing version
re-fetches the mail by its stored locator.

### 5. Retraining

**Trigger.** A button and a schedule on the Settings card (default monthly, **Call**), both
admin-only. The request starts a Celery task that calls `POST /v2/train` and then polls with short
tasks; no Celery task runs for the length of the training, so the broker's visibility timeout
never redelivers it. Training itself runs in the `ai_inference` image.

**Recipe** (what the evidence supports):

- Inputs: all `active` ledger rows with trust `folder` or `verdict`, embedded under the recipe's
  preprocessing version.
- Heads: the existing `ResNetMLP`, same hyper-parameters (30 epochs, Adam 1e-3), **class weights
  only**. No SMOTE, no random oversampling.
- Main decision: the mean of the calibrated probabilities of the head hierarchy and of a 5-nearest-
  neighbour vote over the labelled embeddings (cosine, distance-weighted). Sub-types come from
  the heads.
- Calibration: one temperature fitted on predictions for groups the model did not train on.
- Tier cutoffs: chosen on the same held-out predictions so the High tier meets a precision target.

**Groups.** Two kinds of group, both connected components:

- Near-duplicate groups: mails whose classifier embeddings have cosine similarity of 0.95 or more.
  Splits, calibration and the shadow comparison never separate one. The threshold was checked on the
  legacy embedding space; chunk-averaged embeddings are more similar to each other, so the builder
  re-checks it (random-split versus grouped-split accuracy should still differ).
- Campaign groups: mails whose campaign embeddings are within the profile's distance threshold
  (similarity 0.75), joined with the ties recorded in `CampaignMember` for cases that are known. The
  gate's campaign check (below) splits on these.

A live case that is already in the ledger, for example after "Redo analysis", is excluded from its
own neighbour list.

**Cost.** In the test bed, the repeated grouped evaluation took about 10 minutes on 10 cores and a
final fit about a minute. The gate runs 3 repeats by default (**Call**); the builder measures it on
the production host.

**The gate (offline checks).** A candidate is eligible for shadow only if, on held-out groups
(5-fold, repeated), all of these hold. The comparison baseline is the active version's recipe
retrained on the same folds, because the active weights may have seen those mails (version 0 did):

1. Dangerous mails called Safe: the rate is not above the baseline's rate on the same folds,
   plus a small tolerance (**Call**).
2. Macro-F1 on the three classes is not more than 0.02 below the baseline's.
3. Calibration error is below 0.12 (**Call**).
4. Every head has at least 8 samples in every class. A head that cannot train fails the whole
   candidate; nothing is silently skipped (**Call**, a change from today's behaviour).
5. The High tier is right at least 90% of the time (**Call**).
6. On held-out campaign groups (the same folds, but split on campaign groups), Dangerous mails
   called Safe are not above the baseline's rate plus a small tolerance (**Call**). This measures
   what happens on a campaign the model has never seen; see Evidence, E8.

The report stores per-class results with Wilson intervals, the confusion matrix, the tier table, the
campaign-held-out result and the comparison with the active model. Optionally, an admin-supplied check set of recent public
phishing (see Evidence, E6) can add a recall floor; it is off by default.

**Failure.** A failed or cancelled job leaves the active model untouched and records why.

### 6. Shadow mode

A candidate that passes the gate becomes `shadow`. From then on, every new mail case is scored by
the active and the shadow version in one classify call. The shadow answer is stored (`ShadowResult`)
and never reaches `score_ai` or the engine. A shadow failure or timeout is logged and ignored, with
a shorter timeout than the real one.

Each stored shadow result also records the verdict the case would have received had the shadow
model's answer been the AI vote. The engine is pure (`score_process/scoring/engine.py`), so this is
a recomputation on the stored votes. Verdict flips matter more than class flips, because the
retrained model's confidence is calibrated and will not look like the legacy numbers (see
[Risks](#risks)).

**Campaign dry run.** Detection starts from the AI class Dangerous, so a different model changes
which mails reach it and how many TheHive alerts follow. Shadow therefore runs detection for the
candidate in dry-run mode:

- A separate shadow collection holds the candidate's own classification of each document. At shadow
  start it is seeded by classifying the live collection's documents (about 15 days, 1,300 documents
  at the owner's volume) with the candidate (**Call**), so the first days are not blind.
- Dry run creates no `Campaign` or `CampaignMember` rows, sends no event and touches no live
  collection. It records what would have happened for each case: no check, no campaign, would
  create, would join, with the member case ids (`ShadowCampaignEffect`).
- The comparison with the real events of the same period gives the **alert delta**: campaigns the
  candidate would have raised that the active model did not, and the reverse.
- If the candidate's campaign profile differs from the active one, the dry run must cover a full
  profile window before promotion (**Call**).

**Promotion conditions** (all **Call**; an admin can extend the shadow period):

- At least 7 days and at least 500 mails scored. At about 85 mails a day this is about a week.
- Every Safe-to-Dangerous or Dangerous-to-Safe flip of the case verdict has been reviewed by an
  admin, with a note.
- Every campaign in the alert delta has been reviewed in the same way.
- The gate still passes when re-run with the labels that arrived during shadow.

Shadow shows agreement, the table of differences, and which version was closer when the case has an
analyst verdict. At the owner's volume only about six cases a week have one, so most of the
evidence is the reviewed differences, not an accuracy figure.

**Promote** moves the `active` pointer to the shadow version, keeps the old one as `previous`, and
tells the inference server to reload. **Rollback** moves it back. Both are admin-only and audited.
Stored results of earlier cases are not recomputed.

### 7. Phishing campaigns and the TheHive alert

**Today.** At finalisation `reconcile_case_core` calls `case_handler.campaigns.run_for_case`.
Detection finds the AI analyzer's report by its analyzer name (prefix `AI_Mail`) and reads the score,
confidence, class, sub-class, the mail embedding, the mail text and the decoded headers from it.
Every analysed mail goes into the rolling `suspicious_mails` similarity collection in ChromaDB
(cosine space; the existing `chromadb` connector deletes items older than 15 days). For a mail scored above 6.5, which
means Dangerous, detection asks the collection for the 20 nearest Dangerous mails. Three or more
within cosine distance 0.25 make a `Campaign`, or join an existing one; the documents are tagged
with the campaign reference and `campaign_updated` is emitted. The TheHive connector turns that
event into a phishing-campaign alert with observables, files and comments. Sender domains on the
campaign allow-list are skipped.

**The trap.** Detection is tied to the Cortex analyzer report. If the Cortex AI job is removed, the
lookup finds nothing and detection stops without an error: no campaigns and no TheHive phishing
alerts. D10 requires that this keeps working.

**Design.**

- Campaign detection moves into the `ai_model` connector. It subscribes to `case_finalised`, reads
  the case's AI assessment record, runs the same logic (same collection, thresholds, allow-list,
  lock, `Campaign` and `CampaignMember` rows) and emits `campaign_updated` itself (**Call**). The
  call from `reconcile_case_core` is removed. The TheHive connector, the Campaigns page and the
  15-day cleanup do not change. With the module disabled there is no detection, as there is none
  today when the AI job is off.
- The assessment record replaces the lookup of an analyzer report by name. The mail text and headers
  come from the stored mail (`Mail.mail_body`, `Mail.mail_header`).
- The campaign embedding is separate from the classifier's input. The server returns it with every
  classify call, computed under the version's campaign profile (`cmp-e1`: the fixed preprocessing
  used today). When the classifier recipe moves to whole-body chunks, the campaign embedding does
  not change, so new mails keep matching the 15-day window and the 0.25 threshold stays valid
  (**Call**).
- The check runs for a case whose AI class is Dangerous. That equals today's "score above 6.5" for a
  Dangerous result (**Call**). Mails of other classes are still added to the collection, as today.
- Shadow results never write to the live collection, never create campaign rows and never emit
  campaign events. Their effect is only recorded, in dry-run mode (section 6).
- The labelled neighbours behind the "similar past cases" hint are a different store: long-lived,
  versioned with the model, labelled mails only. They are not the campaign collection.
- No new alert types. The challenge alert and the push button are unchanged and keep reading the AI
  classification from the case fields.

**Versioning the profile.** Every `AiAssessment` and every Chroma document carries the
`embedding_version` of the profile that produced it. Detection compares only documents of its own
version. The live collection keeps the name `suspicious_mails` for `cmp-e1`; a later profile uses
`suspicious_mails__<embedding_version>` (**Call**), so a migration never mixes two embedding spaces.
A profile migration fills the new collection beside the old one for a full window, with detection
in dry-run, and only then switches (section 6). Changing the sender allow-list is not a profile
change, but its digest is recorded so a replay can reproduce a past decision.

**Live counters and purity.** The registry's daily roll-up (section 3) counts, per version, mails
scored, campaign checks, campaigns created and joined, and TheHive campaign alerts raised (from the
delivery ledger). **Purity** is the share of campaign members with an analyst label that are
labelled Dangerous, with the number of labelled members beside it. The Settings versions table shows
both. A warning appears when purity over the last 30 days is below 80% with at least 10 labelled
members (**Call**): either the model or the threshold is raising campaigns that are not phishing.
At the owner's volume few members are labelled, so the count stays visible; a purity figure on three
labels means little.

**Campaign cross-check.** When a case belongs to a campaign, the AI section shows the campaign
reference, its size and the labels of the members that have one. If labelled siblings disagree with
each other, or with this case's AI class, in a hard way (Dangerous against Safe), the case is flagged
"campaign members disagree" and appears in the review queue in Settings. Sibling labels are display
and review only. They never become training labels (**Call**): near-duplicates add little
information, and the ledger already holds the folder label of record.

**Check before relying on the 15-day window.** Detection writes to `suspicious_mails` (hard-coded
in `get_suspicious_collection`), while the cleanup connector defaults to a collection named
`suspicious` unless its own config sets `collection_name`. The example settings set it to
`suspicious_mails` for the Campaigns API only. If the cleanup connector's config does not, its
nightly run fails and old documents are never removed. Verify on each deployment.

**Acceptance.** Replaying a recent real campaign through the new path gives the same campaign
membership and the same `campaign_updated` payload as the Cortex path did, and the TheHive alert is
created (against a fake TheHive in tests). With the connector disabled, no detection runs and
nothing else breaks.

### 8. User interface

**Case section ("AI model assessment").** Replaces the one-line AI caption in the submission drawer
(`OverviewTab`) and the investigation overview. It is not rendered when the module is disabled.
Content: the class and sub-type; the confidence as High, Medium or Low with its meaning; the
runner-up class when the tier is Low; the model version and age; the similar past cases with
their label and provenance (shown only for cases the viewer may already open); a short statement of
what the model reads (the body only) and does not read; the **campaign line** when the case belongs
to a campaign (reference, size, labels of labelled siblings, and a "campaign members disagree" flag);
and the **cross-check**: the other evidence in plain facts, built from the existing verdict
explanation (decisive rule, sources, allow/deny hits, flagged links), with an "AI disagrees with the
evidence" flag when they conflict. No numeric confidence is shown. Cases analysed while the module
was on keep their stored section, read-only and labelled with the version; with the module off they
are hidden too (**Call**).

**Settings "AI model" card.** Admin-only and hidden when disabled. It shows: server health and
breaker state with a reset; the active version, age, label counts by class and source; the
schedule and the Retrain button; the latest candidate and its gate results, including the
campaign-held-out result; the shadow comparison, the review list and the campaign dry-run table with
the alert delta; the version history with rollback and, per version, the campaign counters and
purity; the label ledger summary and the list of flagged labels. A queue lists mails where the AI and
the other evidence disagree, and cases whose campaign members disagree, as candidates for review and
labelling.

**Connector gallery.** The standard card (enabled, configuration, health, last sync). It shows a
read-only line pointing to the AI model card (**Call**).

**API.** Read endpoints for status, versions, candidate, shadow comparison, ledger summary; write
endpoints for retrain, promote, discard, rollback, extend shadow, review a flip or a campaign
difference, resolve a flag.
Writes are admin-only, reads Admin and CISO (**Call**).

### 9. Confidence tiers and scoring

The tier comes from the calibrated probability of the predicted class with cutoffs stored in the
bundle. The illustrative starting points, from the evidence, are High at 0.85 and above, Medium from
0.60, Low below. The tier is shown to people; the engine keeps receiving numbers.

As today, a class is decided only when its calibrated probability is at least 0.5; below that the
result is Inconclusive (**Call**). The builder measures how often that happens with calibrated
numbers. `confidence_ai` and `score_ai` are produced from the calibrated probability using the
existing mapping (Safe 0-5, Unwanted 5-6.5, Dangerous 6.5-10, linear in confidence) (**Call**). Because the
legacy confidence is inflated and the calibrated one is not, the same mail will have a lower
`confidence_ai` than before. The builder must measure the engine's sensitivity to this (see Risks).

### 10. Health and observability

- Connector `health_check`: server ready, active bundle loaded, token accepted.
- The circuit breaker logs and exposes state changes; an open breaker is a visible state.
- Metrics: classify latency and error rate, shadow agreement, label counts per source, model age
  with a warning at 60 days (**Call**).
- No mail content in logs.

### 11. Migration and rollout

1. Publish an `ai_inference` image that holds no classifier weights. Bundles come from object
   storage. The encoder is downloaded from its official Hugging Face repository at build time (D12).
2. Deploy with the connector disabled. Enable it: version 0 is imported from the weights directory
   the current `ai_inference` service mounts (a path in the connector config), and the provider slot
   takes over the AI step. Acceptance: on a sample of recent cases version 0 returns the same class
   and score as the Cortex job did. An instance that never enables the connector runs without an AI
   vote, as an instance with the AI job failing does today.
3. Remove the Cortex `AI_Mail_Analyzer` (catalog entry, thin-client image and its client script),
   the AI launch and `manage_ai_jobs` in the cortex_job code, the call to
   `case_handler.campaigns.run_for_case` in `reconcile_case_core` (campaign detection now runs in
   the connector, section 7), the gateway-IP URL setting, and update
   `docs/components/analyzers.md`, `docs/components/backend/connectors.md` and `CLAUDE.md`. This
   is done in the same release as step 2 (D1). Campaign detection is verified in step 2 before the
   Cortex path is removed.
4. Run the label backfill, then the first retrain, shadow, review, promote.

Archiving the old `retrain model monthly/` data and the large local vectorizer directories before
deleting them is a separate task for the owner, not part of this design.

## Evidence

All numbers come from a throwaway test bed (scripts kept in `~/ai-experiment/testbed/`, outside the
repository), run on the 505 labelled mails and on a read-only export of 269 production challenged
cases. They are the basis for the recipe and the gate; the builder re-runs them.

**E1. Near-duplicates inflate scores.** 55% of mails have a twin at cosine 0.97 or higher; 94.6% of
those twins share the label. 263 independent groups for 505 mails. The production recipe on the real
`ResNetMLP`, 5 seeds, 5 folds: accuracy 0.889 on a random split and 0.777 on a split by group;
Dangerous mails called Safe 11.6 versus 32 of 241.

**E2. Rebalancing.** `smote_ros` scales every class by the same factor, so only the class weights
rebalance. Class weights alone: accuracy 0.798 and 18 ± 2 Dangerous called Safe, against 32 ± 11.5
with the production recipe.

**E3. Confidence.** Mean confidence 0.96-0.98 against accuracy 0.78-0.80. A single temperature
(about 5), fitted on half the groups and scored on the other half, takes calibration error from
0.17-0.20 to 0.09-0.10. After scaling, High (0.85 and above) covers about 40% of mails and is right
95% of the time; Medium about 40% and about 75%; Low about 20% and 43-51%.

**E4. Structure and input** (grouped, held-out halves, accuracy / Dangerous called Safe):

| Setup | Result |
|---|---|
| Five heads, first 128 tokens, class weights | 0.794 / 7.6% |
| Five heads, whole body in chunks | 0.828 / 8.5% |
| One single three-class head | 0.752 / 43.6 of 241 (raw) |
| Logistic regression | 0.728-0.760 |
| 5-nearest-neighbour vote, whole body in chunks | 0.861 / 4.0% |
| Blend of heads and neighbour vote, whole body in chunks | 0.861 / 4.7%, High tier 54% of mails right 95% |

The sub-heads still earn their place: phishing sub-type 0.657 (heads) against 0.583 (neighbours);
newsletter recall 0.60 against 0.22. Stripping markup helped the heads and slightly hurt the
neighbour vote, so it is not part of the recipe. The top rows are within noise of each other, and the
variant was chosen on the same data, so the figures are slightly optimistic.

**E5. More information.** Link structure and domain names alone reach 0.791; added to the text blend
they leave accuracy unchanged and lower Dangerous called Safe from 4.7% to 2.6%. On 187
analyst-edited production cases, against analyst verdicts: the stored AI answer has AUC 0.58 for
"Dangerous" (precision 0.39, recall 0.13 as a rule); adding Cortex and list features gives 0.66
(difference +0.07, 95% interval -0.02 to +0.17); for "not Safe", header and link features raise
0.55 to 0.66-0.69 (+0.13, interval +0.04 to +0.22). On the later 54 cases, Cortex features alone
reach 0.81 and the AI alone 0.45. On the 66 cases whose verdict the engine set, the AI alone
predicts it at 0.86, so any test against engine verdicts is circular. Caveats: challenged cases are
a selected, hard subset; the baseline is a weak production model; analysts saw the same Cortex
reports; many variants were compared. Hence D9.

**E6. Public corpora.** Apache SpamAssassin public corpus (2003-05, English) and the Nazario
phishing corpus 2023-25 (CC BY 4.0). A model trained on the labelled mails puts 83-84% of the
recent Nazario phishing in Dangerous but only 45-47% of old SpamAssassin ham in Safe, while
reporting 0.92-0.97 confidence. Trained on public data alone it scores 0.54 on the labelled mails.
Adding 150 or 600 public mails per class to training gave no reliable gain (0.80, 0.79, 0.75).
Public data is therefore a stress test, not training data. The SpamAssassin maintainers ask that
the messages never be sent into a live mail system.

**E7. Data facts that shape the ledger.** `Mail.mail_from` is blank on 254 of 269 production
challenged cases; the sender must be parsed from the stored headers (`Mail.mail_header`, stored as
the repr of a dict, which also holds the real `Message-ID`; `Mail.mail_id` is a generated id). `Case.results` is overwritten on an analyst edit with no history; the only
markers are `last_update_by`, `final_score` and `final_confidence`. Authentication-Results headers
are present on about a third of reported mails.

**E8. Campaigns the model has not seen.** Held-out groups at looser and looser "same campaign"
rules, on the campaign embedding (first-128-token space), 3 seeds, 5 folds. The production campaign
rule is similarity above 0.75.

| Same-campaign rule | Groups (largest) | Five heads: accuracy / Dangerous called Safe | Neighbour vote (5): accuracy / Dangerous called Safe |
|---|---|---|---|
| 0.95 | 263 (63) | 0.797 / 8.0% | 0.800 / 6.8% |
| 0.90 | 229 (63) | 0.758 / 10.5% | 0.800 / 5.3% |
| 0.85 | 203 (89) | 0.721 / 14.7% | 0.677 / 5.1% |
| 0.80 | 180 (89) | 0.714 / 17.8% | 0.663 / 7.6% |
| 0.75 | 145 (89) | 0.675 / 18.7% | 0.618 / 7.1% |

On an unseen campaign the five heads miss about one Dangerous mail in five; the neighbour vote
keeps misses near 7% but is worse on the other classes. The blend was not tested at campaign
granularity. With 145 groups and 3 seeds this is a strong hint, not a figure; hence gate check 6
rather than a fixed threshold, and a builder task to re-run it on the blend.

### Sources

Google, MLOps continuous delivery and automation pipelines (levels, validation, rollback); Google,
Rules of Machine Learning; MLflow Model Registry (aliases); NIST AI RMF; OWASP ML08 Model Skewing;
scikit-learn (grouped and time-aware cross-validation, calibration); Microsoft HAX guidelines;
Google PAIR, Explainability and Trust; KServe Open Inference Protocol; Azure circuit-breaker
pattern; Celery task and Redis broker documentation; SetFit documentation; Guo et al., On
Calibration of Modern Neural Networks; imbalanced-learn common pitfalls; Google Machine Learning
Crash Course (imbalanced data, dividing datasets); the `paraphrase-multilingual-mpnet-base-v2`
model card (128-token limit). Datasets: Apache SpamAssassin public corpus; Nazario phishing corpus.

## Risks

- **Alert volume changes with the model.** A promoted model changes which mails reach campaign
  detection. The shadow dry run and the reviewed alert delta are the guard; the seeded shadow
  collection costs one batch classification of about 15 days of mail at shadow start.
- **Purity needs labels.** At 20 to 30 labels a month, few campaign members are labelled, so purity
  rests on small counts. It is shown with its count and warns only above a minimum.
- **Silent loss of phishing campaigns.** Campaign detection and the TheHive alert depend on the AI
  analyzer today (section 7). The acceptance replay is the guard; it must run before the Cortex path
  is removed.
- **Train/serve skew in the text.** If the live text form differs from the one the model trained on,
  live results will be worse than the figures here. See "One text function".
- **Engine sensitivity to calibrated confidence.** The engine compares `ai.confidence` with the base
  confidence and applies `CONF_FLOOR`. Lower, honest confidences may change which signal decides.
  Shadow records would-be verdicts to measure this before promotion; the builder should also replay
  recent cases through the engine offline before the first promotion.
- **Small data.** 505 labels, 263 independent groups, 20 to 30 new labels a month. Retrains change
  little, which is why the gate is conservative and promotion is manual. Intervals on any figure in
  this document are wide.
- **Feedback loop.** Verdict labels come from analysts who read the same Cortex output as the
  engine. Gains from learning on them partly mean imitating that output.
- **First-class heads with few samples.** Newsletter (10 labelled mails) and whaling and blackmail
  (about 18 each) are barely learnable; sub-type output is advisory.
- **Operations.** Training and classify share the `ai_inference` host. Resource limits and
  scheduling keep a monthly training from slowing live classification.
- **Redis visibility timeout** (default one hour) redelivers tasks that run longer. The design keeps
  every Celery task short for that reason.

## Test approach

- Unit: provider contract and failure paths; ledger matching and supersession; group assignment;
  gate arithmetic; tier derivation; score mapping; permission checks.
- Integration (dev stack with a fake inference server): idempotent redelivery; breaker open gives
  Inconclusive within the time limit; a shadow failure never changes a case; promote and rollback
  are atomic and audited; the Cortex job is not launched.
- Evaluation regression: re-run the grouped evaluation on the 505-mail dataset and require the
  recipe to reproduce the reported figures within seed noise (grouped accuracy about 0.85 or
  better, Dangerous called Safe about 5% or lower). It needs torch and the encoder, so it runs as a
  separate manual or scheduled job, not in the default CI. The default CI uses a fake inference
  server.
- UI: the section is absent when the module is disabled; tiers and cross-check render; admin-only
  controls hidden from others; Playwright path through retrain, shadow, promote.
- Campaigns: replay a recent campaign and compare membership and the `campaign_updated` payload with
  the Cortex path; a shadow result writes nothing to the live collection, creates no campaign rows
  and sends no event; the dry run records would-create and would-join correctly on a replayed
  campaign; documents of another `embedding_version` are never compared; with the module disabled no
  detection runs; the TheHive alert is created against a fake TheHive; the roll-up counts and the
  purity figure match a hand count on a small fixture; sibling disagreement raises the flag.
- Chaos: stop the inference container mid-case and during training.

## Left to the builder

Table and column names, URL shapes, exact layout and copy, the number of neighbours (3 or 5; the
data does not separate them) and tier cutoffs after re-running the evaluation, container resource
limits, how to compute groups efficiently as the ledger grows, whether the AI result also stays an
`AnalyzerReport`, how version 0's tier is shown, the bucket name, the fields and indexes of `AiAssessment`, how the connector's `case_finalised`
subscription keeps detection off the finalisation path, and the packaging of the `ai_inference`
image.

## Deferred

Sender, subject and link features in the model (E5 shows link domains help); learning analyzer
reliability from analyst-edited verdicts, which may be a better use of Cortex data than feeding it
to the text model; SetFit; automatic promotion; an active-learning queue beyond the simple
disagreement list; re-testing Cortex-as-input once about 300 edited labels with snapshots exist; a
live **new-campaign recall** per version (the first member's AI verdict against the campaign's
eventual analyst verdict), which needs enough labelled campaigns first.

## Calls made in this document

| # | Call | Why |
|---|---|---|
| C1 | 20 s total timeout, 2 retries on transient errors only | Keeps a case from waiting; matches the breaker guidance |
| C2 | New Django app `ai_model` for the tables | Isolated migrations, removable |
| C3 | Nightly label sync; monthly default retrain | Volume is low; labels arrive slowly |
| C4 | A folder-versus-verdict mismatch is flagged and kept out of training | Cheapest guard against a mislabelled mail |
| C5 | Gate thresholds: no more Dangerous-called-Safe than the active model, macro-F1 within 0.02, calibration error below 0.12, High tier at least 90% right | Taken from the test bed; tune on re-run |
| C6 | A head that cannot train fails the whole candidate | Today a failed head is skipped silently |
| C7 | Shadow minimum 7 days and 500 mails; every verdict flip reviewed; gate re-run | At 85 mails a day this is about a week |
| C8 | Any admin reviews flips; writes admin-only; reads Admin and CISO | Existing roles |
| C9 | Tier cutoffs 0.85 and 0.60, stored per version | Illustrative, from E3 |
| C10 | Existing score mapping applied to the calibrated confidence | Keeps the engine interface unchanged |
| C11 | Model age warning at 60 days | Arbitrary; a staleness alert is the point |
| C12 | With the module off, old cases' AI section is hidden too | Matches D4 literally; easy to flip |
| C13 | Connector card shows a read-only line pointing to the AI model card | One home for controls |
| C14 | Markup stripping is not in the recipe | Mixed result in E4 |
| C15 | Version 0 imported from current weights so cutover changes no verdict | Safest cutover |
| C16 | Cortex job removed in the same release as the provider (D1) | Avoids two AI paths |
| C17 | Only folder labels train; verdicts and challenges are provenance and cross-checks | The verdict has 4 values, the folders 8; every challenged mail is also filed in a folder |
| C18 | Only hard conflicts (Dangerous against Safe) flag a label | Spam and newsletters are judged Safe or Suspicious by different analysts |
| C19 | Gate baseline is the active recipe retrained on the same folds | The active weights may have seen the held-out mails |
| C20 | Gate runs 3 repeats by default | Keeps a retrain to minutes, not hours |
| C21 | Similar past cases are shown only for cases the viewer may already open | Respects existing access rules |
| C22 | Campaign detection runs in the connector on `case_finalised` and emits `campaign_updated` itself | D10 says the phishing alert part belongs to the connector; the TheHive connector stays unchanged |
| C23 | The campaign check keys on the AI class being Dangerous, not on a score above 6.5 | The two are equivalent for a Dangerous result and the class survives recalibration |
| C24 | The campaign embedding uses a fixed preprocessing, separate from the classifier's | Keeps the 15-day window and the 0.25 threshold valid when the recipe changes |
| C25 | A class is decided only at a calibrated probability of at least 0.5, else Inconclusive | Same rule as today, applied to calibrated numbers |
| C26 | A per-case `AiAssessment` record holds the full AI result | Campaign detection and the UI read one record instead of an analyzer report found by name |
| C27 | The campaign profile is part of every version and changes only by an explicit migration | Keeps the embedding space and thresholds stable and reproducible |
| C28 | The collection keeps its name for `cmp-e1`; later profiles use `suspicious_mails__<embedding_version>` | No data migration now, no mixed spaces later |
| C29 | A version with a different campaign profile needs a full profile window of dry run before promotion | Detection needs 15 days of neighbours to be meaningful |
| C30 | The ledger stores the campaign embedding, and campaign groups are components at the profile threshold joined with `CampaignMember` ties | Lets the gate test unseen campaigns without needing every label matched to a case |
| C31 | Gate check 6: Dangerous called Safe on held-out campaigns not above the baseline plus a tolerance | E8 shows this is where the heads are weakest |
| C32 | The shadow collection is seeded from the live collection at shadow start | Otherwise the dry run is blind for the first days |
| C33 | Campaigns in the alert delta are reviewed with the verdict flips before promotion | A promotion changes TheHive alert volume |
| C34 | Purity warning below 80% over 30 days with at least 10 labelled members | Arbitrary; the count is always shown |
| C35 | Sibling labels in a campaign are display and review only, never training labels | Near-duplicates add little information |
