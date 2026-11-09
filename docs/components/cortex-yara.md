# Cortex + YARA

## Cortex

Cortex is the analyzer execution engine. Django dispatches analyzers to Cortex
through `cortex4py`, and Cortex reports results back to
`/api/cortex/webhook/` using an HMAC-signed, jobId-deduped webhook. The
analyzers in use (header, sandbox, YARA, file-info and the others the scoring
engine consumes) are configured under `integrations.cortex.analyzers` in
`settings.json`. The mail AI verdict does not run in Cortex: the `ai_model`
connector provides it from the `ai_inference` model server (see
[AI / ML Analyzers](analyzers.md)). The `analyzers.ai` entry only names the
`Analyzer` row that carries that vote in the ledger.

See [cortex_job](backend/cortex_job.md) for the orchestration layer and
[Integrations](../operations/integrations.md) for configuration.

## YARA rules

Static detection rules live in `yara-rules/`. The YARA analyzer matches
submitted artifacts against these rules as one input to the final verdict.
