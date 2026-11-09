# AI Mail Analyzer

The classifier code in `Analyzers/AIMailAnalyzer/` and the Django side that manages
its model versions. For how the pieces are deployed and operated see
[AI / ML Analyzers](../components/analyzers.md); for the Django app's models and
endpoints see [ai_model](../components/backend/ai_model.md).

## Classifier modules

::: mail_analysis

::: mail_archive

::: ResNetMLP

## Inference server

`inference_server.server` is the FastAPI application; `inference_server.v2` is the
token-protected `/v2` API (`/v2/classify`, `/v2/embed`, `/v2/train`, `/v2/reload`,
health and model endpoints) the `ai_model` connector calls.

::: inference_server.server

::: inference_server.v2

::: inference_server.bundles

::: inference_server.training_job

## Training

The recipe, bundle format and promotion gate the training job runs.

::: training.recipe

::: training.bundle

::: training.gate

::: training.dataset

## Model registry (Django)

The `ai_model` app: the registry is the only code that changes a model version's
status; promotion enforces the conditions; retrain drives the training job.

::: ai_model.registry

::: ai_model.promotion

::: ai_model.retrain

::: ai_model.ledger
