# Cortex + YARA

## Cortex

Cortex is the analyzer execution engine. Django dispatches analyzers to Cortex
through `cortex4py`, and Cortex reports results back to
`/api/cortex/webhook/` using an HMAC-signed, jobId-deduped webhook. The
analyzers in use (header, AI, sandbox, YARA, file-info) are configured under
`integrations.cortex.analyzers` in `settings.json`.

See [cortex_job](backend/cortex_job.md) for the orchestration layer and
[Integrations](../operations/integrations.md) for configuration.

## YARA rules

Static detection rules live in `yara-rules/`. The YARA analyzer matches
submitted artifacts against these rules as one input to the final verdict.
