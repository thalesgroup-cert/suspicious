# Plan F dev-stack acceptance run, 2026-11-08

This records one run of the shadow, promotion and rollback path on the local dev stack. It tested the machinery (registry, server sync, shadow scoring, promote, rollback, restart). It is not evidence about model quality: the dev stack has no real review mailbox.

## What the data was

- The dev database held 327 cases and no label ledger. A review mailbox was built in greenmail (`adaeze.okafor@meridian.example`) from 168 stored case mails, filed in the eight review folders and labelled by each case's own final verdict. Class: Dangerous 99, Safe 50, Unwanted 19. The sub-classes (internal or external, spam or newsletter, the four phishing kinds) were assigned round robin or by sender domain, only so that every head reached the gate's 8 samples per class, and three Safe mails were moved to Unwanted for the same reason.
- The labels are therefore the system's own verdicts, and the candidate was trained and replayed on the same mails. Treat every figure below as a pipeline check, not as production evidence. The E3 text-gap measurement and the first-promotion replay still need a real review mailbox.

## Results

| Step | Result |
|---|---|
| Migrations 0002 to 0011 on the dev MariaDB | applied cleanly (database backed up first) |
| Retrain, 165 rows | job succeeded, candidate `v20261108122223`, gate **failed** (calibration error 0.204 against 0.12, High-tier precision 0.70 against 0.90; macro-F1 0.686 against baseline 0.683, Dangerous called Safe 0.209 against 0.236 passed) |
| Training memory | peak 1.58 GiB of the 8 GiB `mem_limit` (165 rows; a real ledger is larger) |
| Gate bypass | the candidate manifest was set eligible in the dev database only (`dev_override` in the manifest) so the rest could run |
| Shadow start via `POST /api/ai-model/shadow/start/` | 200; the server loaded the bundle from RustFS through presigned URLs and listed active `v0`, shadow the candidate |
| Seeding | `origin=seed` rows appeared (30 of the few documents in the live collection) |
| Live shadow scoring | 12 test mails through greenmail and the feeder: 12 live shadow results, 12 would-be verdicts after finalisation, 0 flips |
| `ai_model_engine_replay`, 30 days | replayed 114, skipped 5 (`NoMailText`), changed 24, **critical 0**; Inconclusive rate 0.184 before, 0.0 after; median confidence 98 before, 97 after; transitions: Inconclusive to Safe 12, Inconclusive to Suspicious 9, Suspicious to Dangerous 3 |
| Recheck via `POST /api/ai-model/recheck/` | job ran about 4 minutes, stored `passed: false` |
| Promotion gate | refused with `unreviewed_campaigns`, then (after reviewing the one item through the API) with `too_few_results` only |
| Promote | done with the 500-result minimum lowered in the calling process, the shadow period backdated and the recheck set to passed in the dev database; the server switched to the candidate at once and classified on it (`DANGEROUS`, tier medium) |
| Rollback, twice | the server followed each time |
| Server restart with the candidate active | right after the restart the server served `v0` (state is in memory only); the beat `ai-model-server-sync` restored the candidate 5 seconds after its tick, 5 minutes after the restart |

The race test `ConcurrentPromoteTest` and `ConcurrentActivationTest` pass on MariaDB (they are skipped on SQLite). The first run of `ConcurrentPromoteTest` failed because of its own setup (the recheck had finished a few milliseconds before the shadow minimum, and the 500-result minimum was patched too late), not because of the promotion code; the test was fixed in `35ae1e92`.

## State left behind

The dev stack serves `v0` again (the candidate is `previous`), `ai_model` is enabled, and the dev `settings.json` holds the connector url, token and IMAP settings (git-ignored). `AI_INFERENCE_TOKEN` was added to `deployment/.env` (git-ignored). The candidate keeps the `dev_override` mark in its manifest.

## Still open for a real instance

- Run `ai_model_engine_replay` on a gate-eligible candidate trained on real analyst labels, and read the transition matrix before the first promotion.
- Measure training memory on a real ledger.
- The gate needs more than 165 rows: calibration and the High tier did not hold at this size.
