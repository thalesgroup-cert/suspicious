# score_process

Risk scoring, plus two subsystems added since the original write-up: rule-based
verdict explanation (`scoring/explanation/` — composes the analyst/reporter
"why this verdict" text) and the deterministic narration safety-lock and
prompt builder (`scoring/narration/`) the `ai_narration` connector calls.
TheHive/MISP pushes and reporter SMTP notification now happen via the
[connectors](connectors.md) framework's `case_finalised` event, not inline
here.
