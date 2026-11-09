# ai_model: mail AI model lifecycle

`ai_model` owns the data and the lifecycle behind the mail AI verdict: the stored
assessment of each case, the ledger of analyst labels the model is trained on, the
registry of model versions, and the retrain, shadow and promotion workflow. The
classification itself is done by the `ai_inference` container (`Analyzers/AIMailAnalyzer/inference_server`)
and reached through the `ai_model` connector (`connectors/contrib/ai_model/`), which is
off by default. This app has no Celery beat entries of its own: the connector registers
them (see [Beat entries](#beat-entries)).

Operations (setup, token, bundle hosts, troubleshooting) are in
[`docs/components/analyzers.md`](../../../docs/components/analyzers.md) and
[`docs/getting-started/ai-inference.md`](../../../docs/getting-started/ai-inference.md).

---

## Models

| Model | Purpose |
|---|---|
| `AiAssessment` | One row per case (one-to-one): `model_version`, `result` (`SAFE`, `UNWANTED`, `DANGEROUS`, `INCONCLUSIVE`), `sub_class`, `score`, `confidence` (percent), `probabilities`, `sub_probabilities`, `tier`, `contributing_phrases`, `similar_cases`, `campaign_embedding`, `embedding_version`, `latency_ms`. Written when the `mail_ai` provider job finishes |
| `LabelRecord` | The label ledger. Append-only except for `status`, the flag and resolution fields, and the embedding replaced by `ai_model_reembed_ledger`. `source` is `imap_folder`, `analyst_verdict` or `challenge`; `trust` is `folder` (trainable), `verdict` or `proposal` (provenance only); `status` is `active`, `superseded` or `flagged`. Rows are keyed by the mail's Message-ID (stored and as a hash), matched to a case when one exists |
| `LabelSyncState` | Per review folder checkpoint of the IMAP label sync: `uidvalidity`, `last_uid`, `last_run_at`, `skipped` |
| `ModelVersion` | One registered model version: `version_id`, `status`, `parent`, `trigger` (`manual`, `schedule`, `import`), `bundle_prefix` in the `ai-models` bucket, `manifest`, `campaign_profile`, shadow window (`shadow_since`, `shadow_min_days`) and the last gate `recheck`. Exactly one `active` and at most one `shadow` and one `previous` are enforced by unique slot columns |
| `ModelEvent` | Audit trail of every registry action: version, action, user, time, note |
| `RetrainJob` | One training or gate-recheck job on the inference server: `job_id`, `state` (`running`, `succeeded`, `failed`, `cancelled`), row counts, params, error class. One running job at a time |
| `ShadowResult` | The shadow model's answer for a case (`live` from new mails, `seed` from replayed past cases), plus what the live verdict would have been (`would_be_result`, `would_be_rule`) and the `flip` class (`none`, `changed`, `critical` for Safe/Dangerous flips) |
| `ShadowCampaignEffect` | Whether the shadow would have created or joined a campaign for a case (`no_check`, `none`, `would_create`, `would_join`) |
| `ShadowReview` | An admin's review of one critical flip or campaign difference, which promotion requires |

Version `v0` stands for the legacy weights directory (no bundle). Version statuses: `candidate` (a finished retrain), `shadow`, `active`,
`previous`, `discarded`, `failed`.

## Modules

| Module | Role |
|---|---|
| `registry.py` | The only place a version's status changes; every change writes a `ModelEvent`. Promoting makes the old active `previous` and discards an older `previous`. Presigned URLs for bundles (`ai-models` bucket) and datasets (`ai-datasets` bucket) |
| `retrain.py` | Exports the ledger, starts `POST /v2/train` with presigned URLs, polls the job with short Celery tasks, registers a succeeded job as a `candidate`; also the gate recheck of a shadow. Jobs older than 6 hours are cancelled; a failed or refused scheduled run backs off 7 days |
| `promotion.py` | `start_shadow`, `promote`, `rollback`, `discard`, `extend`, `review`. `can_promote` lists the unmet conditions by code: `not_shadow`, `too_young` (shadow window), `too_few_results` (fewer than 500 compared live results), `unreviewed_flips`, `unreviewed_campaigns`, a gate recheck code, `profile_window`, `job_running` |
| `shadow.py`, `tasks.seed_shadow` | Store the shadow's answer next to the live one, never touching the live verdict; seed it from past cases |
| `serversync.py` | Keeps the models loaded in the inference server equal to the registry; a restarted server is brought back by `sync` |
| `ledger.py`, `messageid.py`, `taxonomy.py` | Writers and matching for the label ledger; the review-folder taxonomy (the digit prefix of a folder name is the class) |
| `export.py`, `training_data.py` | The npz dataset a training job downloads: trainable rows as embeddings, folder labels and case ids; no mail text |
| `campaign_profile.py` | The campaign-detection profile (collection `suspicious_mails`) stored with each version |
| `stats.py`, `schedule.py`, `queue.py`, `presentation.py` | Daily per-version counters; next scheduled retrain date; review queue (AI disagrees with the evidence, campaign members disagree); the assessment dict the case views render |
| `mailinfo.py` | Applies the AI category and result to the reporter's `MailInfo` |

## REST endpoints (`/api/ai-model/`)

Read endpoints need the Admin or CISO group; writes need Admin. Writes take a JSON
body with a `note` (and where relevant `version_id`) and answer `409` with a fixed
message when the state changed or a condition is unmet.

| Endpoint | Method | Access | Purpose |
|---|---|---|---|
| `status/` | GET | Admin, CISO | Active, previous and shadow versions, running job, connector health, breaker state, retrain schedule, counts, latest jobs, ledger summary |
| `versions/`, `candidates/`, `jobs/` | GET | Admin, CISO | Paginated version history, candidates, retrain jobs |
| `shadow/` | GET | Admin, CISO | The running shadow: results, verdict changes, campaign differences, promotion conditions |
| `reviews/` | GET, POST | read Admin/CISO, write Admin | List shadow reviews; record one |
| `shadow/start/` | POST | Admin | Start the shadow period for a candidate |
| `promote/`, `rollback/`, `discard/`, `extend/` | POST | Admin | Promote the shadow, roll back to `previous`, discard a candidate or shadow, extend the shadow window |
| `retrain/` | POST | Admin | Start a manual retrain (202 with `job_id`) |
| `recheck/` | POST | Admin | Start a gate recheck of the shadow (202) |
| `ledger/`, `flags/`, `queue/` | GET | Admin, CISO | Ledger counts and label mix, flagged labels, review queue |
| `flags/<id>/resolve/` | POST | Admin | Keep or drop a flagged label, with a note |
| `breaker/reset/` | POST | Admin | Reset the `ai_model` circuit breaker |

## Management commands

| Command | Purpose |
|---|---|
| `ai_model_retrain` | Start a retrain, or `--status`, `--cancel`, `--wait` (with `--timeout`). The result is a `candidate`; nothing is activated |
| `ai_model_backfill_labels [--folders] [--dry-run]` | Backfill verdict and proposal rows for existing cases and late case matches; `--folders` also syncs the review folders without the per-run cap |
| `ai_model_reembed_ledger [--limit N] [--dry-run]` | Re-embed trainable rows not yet in the training preprocessing, so the ledger can be exported |
| `ai_model_campaign_replay <campaign_ref>` | Replay a campaign through the connector's detection in a rolled-back transaction and an in-process Chroma; read-only |
| `ai_model_engine_replay <version_id> [--limit N] [--since-days N] [--json]` | How much scoring verdicts would move if the shadow's AI signal replaced the live one; read-only, counts only |
| `ai_model_text_gap [--limit N]` | Cosine gap between the live mail text and the filed mail's text; read-only, statistics only |

## Beat entries

Registered by `connectors/apps.py` when the connector is registered (each task checks that
it is enabled):

| Name | Task | Cadence |
|---|---|---|
| `connector-ai_model-label-sync` | `connectors.tasks.run_connector_sync` (the connector's `sync()`) | 86400 s |
| `ai-model-retrain-check` | `ai_model.tasks.maybe_start_retrain` | 86400 s |
| `ai-model-materialise-stats` | `ai_model.tasks.materialise_model_stats` | 86400 s |
| `ai-model-server-sync` | `ai_model.tasks.sync_server` | 300 s |

## Tests

```bash
docker exec suspicious bash -c "cd /app/Suspicious && python manage.py test ai_model"
```
