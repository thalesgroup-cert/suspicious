# ai_model

Data and lifecycle of the mail AI verdict. The `ai_inference` container does the
classification; the `ai_model` connector (off by default) calls it; this app
stores each case's `AiAssessment`, the label ledger the model is trained on, the
registry of model versions, and the retrain, shadow, promotion and rollback
workflow.

- Models: `AiAssessment`, `LabelRecord`, `LabelSyncState`, `ModelVersion`,
  `ModelEvent`, `RetrainJob`, `ShadowResult`, `ShadowCampaignEffect`,
  `ShadowReview`.
- REST: `/api/ai-model/*` (Admin and CISO read, Admin write).
- Commands: `ai_model_retrain`, `ai_model_backfill_labels`,
  `ai_model_reembed_ledger`, `ai_model_campaign_replay`,
  `ai_model_engine_replay`, `ai_model_text_gap` (see the
  [management commands reference](../../reference/management-commands.md)).
- Beat: `ai-model-retrain-check`, `ai-model-materialise-stats`,
  `ai-model-server-sync` and the connector's `label-sync`.

Full description of models, modules, endpoints and commands:
[`Suspicious/Suspicious/ai_model/README.md`](https://github.com/thalesgroup-cert/suspicious/blob/main/Suspicious/Suspicious/ai_model/README.md).
Connector configuration: [connectors](connectors.md#ai_model). Setup and
troubleshooting: [AI / ML Analyzers](../analyzers.md). Operator view:
[Profile & Settings](../../user-guide/profile.md#ai-model-card).
