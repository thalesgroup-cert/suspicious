# Security plan status and backlog

Source: the "Audit de Sécurité & Posture d'Architecture" report of 2026-10-16
(v1.6.2, commit 00d6efe5), section 6 roadmap. Status checked on 2026-10-26;
"not re-tested" means the code change is merged but the report's own payloads
were not replayed.

## Where things stand

- Upstream `origin/main` is at `5232de22`. Local `main` is 21 commits ahead of it
  (the object-storage stage 1 work below plus its spec and plan) and the fork's
  `main` was fast-forwarded to the same commit. Nothing from this list is on
  upstream `main` yet.
- Open pull requests on the upstream repository from the fork: #424 (nltk), #425
  (Chroma proxy routes), #428 (Traefik without Docker access), #431 (Pillow 13),
  #432 (CI baseline), #433 (DRF and OpenTelemetry), #434 (frontend dependencies).
- The dev stack was not recreated after stage 1: the running `suspicious`,
  `suspicious_celery` and `suspicious_celery_beat` containers still run the image
  built before it. Recreating them drops the manual MISP network connections.
- The shared test image tag (`ghcr.io/thalesgroup-cert/suspicious:test`) is rebuilt
  from whichever branch last built it. It has no `minio-py` since stage 1.

## Roadmap status

| Report item | Finding | Status | Where |
|---|---|---|---|
| Phase 1.1 docker-socket-proxy | VULN-01 | Cortex: done. Only `docker_proxy_cortex` mounts the socket (`CONTAINERS/IMAGES/INFO/POST=1`), tested on the dev stack; it filters by path and method, not request body, so a compromised Cortex could still ask for a privileged container. Traefik: its Docker provider and proxy are removed (nothing uses labels; a read-only proxy still exposes every container's environment). Static checks only, no live Traefik run. | `5232de22`, PR #428 |
| Phase 1.2 network segmentation | VULN-03 | Done: `data`, `storage` and `cortex` tiers beside the shared `suspicious_network`. The report names four networks (frontend/backend/data/cortex); the split differs but the UI and feeder are off the data tier. | `dd8d804d` |
| Phase 1.3 nltk >= 3.10.4 | VULN-02 (partly) | PR open. | #424 |
| Phase 1.3 chromadb >= 1.5.10 | VULN-02 | **No fixed release exists** (1.5.9 is the latest on PyPI, Docker tags past it are `1.5.10.dev*`). Mitigated: the proxy forwards only the routes the app uses. The report cites CVE-2026-45829; Dependabot lists GHSA-36p7-vc44-83pf, GHSA-2wm9-hf6c-p5cr, GHSA-xph7-9rjv-w5fr. PR open. | #425 |
| Phase 1.4 database authentication | VULN-03 | Done: Redis, Elasticsearch and ChromaDB (token proxy). Harness: `deployment/scripts/ci/db_auth_harness.sh`, 25 checks. | `918c01bc`..`d8689e4a` |
| Phase 2.1 mail preview sanitiser | VULN-04 | Merged: `nh3` allow-list and rendering without network access (`eml2png_renderer.py`). Report payloads not re-tested. | `fix(preview)` 2026-10-21 |
| Phase 2.1 replace wkhtmltoimage | VULN-08 | Branch `feature/chromium-mail-renderer`. Separate `mail_renderer` container (headless Chromium, internal network, no route out, non-root, seccomp, read-only). `wkhtmltopdf` and `imgkit` removed from the Django image. Also fixes a storage bloat: previews were a fixed ~14 MB each (114 took 1.6 GB), now ~20-40 KB. After deploying, run `regenerate_mail_previews --all` to shrink old ones. Git merges it cleanly with stage 1, but both change `eml2png_renderer.py` and they have not been tested together. | `a4caa59b` |
| Phase 2.2 CISO fail-closed | VULN-07 | Done in `profiles_utils/scope.py` (no profile returns none). | main |
| Phase 2.2 CISO scope on submissions | VULN-07 | Branch `feature/ciso-scope` (backend and the challenge button UI, 2 commits). Submissions page lists a CISO's own submissions only; scope is on Investigations; a CISO can challenge for a user in scope (audit trail names the CISO) and cannot edit case details. Redo-analysis, ticket push and comments are still open to a CISO in scope (decision pending). Conflicts with `main` only in `CHANGELOG.md`. | `724cdb1d`, `5ea12875` |
| Phase 2.3 single MinIO bucket | VULN-09 | Branch `feature/single-mail-bucket`. Web uploads go to `storage.s3.web_bucket` (default `mail-submissions`), one prefix per submission, untagged so the legacy scanner skips it. Existing buckets untouched. **Conflicts with stage 1** in `case_handler/.../mail/minio.py`: it has to be redone on `ObjectStore` (object tags are the `tags` argument of `put`, bucket tags are `set_bucket_labels`). | `c350d308` |
| Phase 3.1 Vault TLS, unseal keys off the host | VULN-05 | Branch `feature/vault-tls`. TLS on the listener (Vault-only CA, SANs), `VAULT_CACERT` for clients; `make unseal` prompts for the keys, no file; auto-unseal documented as the production path. Merges cleanly. Not run: `make up`/`deploy` end to end or an upgrade of an existing Vault. | `4dac184e`, `f4665043` |
| Phase 3.2 `no-new-privileges` + `cap_drop: ALL` | n/a | Done for `suspicious`, `suspicious_celery`, `suspicious_celery_beat`, `suspicious_ui`, `feeder`, `cortex`. Not applied to the database services, Vault or Traefik. | `5232de22` |
| Phase 3.2 non-root analyzers | VULN-06 | Branch `feature/analyzers-non-root`. Both run as uid 1001; AIMailAnalyzer needed a writable `./tmp`. Verified through Cortex; AI image tested as a layer, not a full rebuild. Merges cleanly; will conflict with `feature/ai-inference-server` (same Dockerfile). | `e5d1d775` |

## Object storage provider layer

Not in the audit report; it came from the plan to move production from RustFS to a
Google Cloud Storage bucket. Spec: `docs/specs/2026-10-23-object-store-providers-design.md`.
Plan for stage 1: `docs/plans/2026-10-23-object-store-providers.md`.

| Stage | State |
|---|---|
| 1. `ObjectStore` interface, `s3` provider on boto3, every backend caller moved, `minio-py` removed | On local `main` (`fe5fda9f`), not on upstream. Full backend suite 1996 tests OK (29 skipped); the 14-test live contract passed against the dev RustFS from a throwaway container. Not exercised in the running app (containers not recreated). |
| 2. `gcs` provider (`google-cloud-storage`, workload identity by default) | Not started. |
| 3. Settings page Storage section, test connection, optional detect | Not started. |
| 4. Email feeder on presigned upload URLs, backend commit endpoint | Not started. Assumes the feeder host can reach `storage.googleapis.com`; if not, the feeder uploads through the backend instead. |
| 5. Read fallback, `verify_storage_copy`, migration runbook | Not started. |

Known and deferred from the stage 1 reviews:
- A single-object read failure mid-loop in `ai_minio_utils` still lets a TheHive campaign
  alert go out with partial evidence during a storage outage (the old minio behaviour).
- A missing `storage.s3.access_key` now fails at first store use as a plain `KeyError`, not
  at boot.
- `MinioMediaStorage.exists()` and `delete()` still catch every exception, so an outage reads as
  "missing".
- RustFS alpha.90 returned 500 for SSE and conditional puts and 403 on a valid presigned POST;
  re-test any storage feature (lifecycle, object lock, checksums) on the version deployed.

## Dependencies and CI

Dependabot lists **65 open alerts** against `main`:

| Package | Alerts | Fixed in | Where |
|---|---|---|---|
| pillow 12.3.0 | 41 (1 critical) | 13.0.0 | #431 |
| vite 8.1.5 | 10 | 8.1.6 | #434 |
| chromadb 1.5.9 | 3 | no fix | mitigated by the proxy (#425) |
| djangorestframework 3.18.1 | 3 | 3.18.2 | #433 (pins 3.18.3) |
| follow-redirects, zod, @vitest/mocker, undici | 2, 2, 2, 1 | 1.16.1, 4.6.6, 4.1.12, 7.30.1 | #434 |
| nltk 3.10.3 | 1 | 3.10.4 | #424 |
| opentelemetry-api 1.45.0 (pip-audit, not in this count) | 1 | 1.45.1 | #433 |

Why most pull requests were red: four checks failed on `main` itself.

| Check | Cause | Fix |
|---|---|---|
| docs `build`, `migration-check` | `suspicious.settings` requires `REDIS_CACHE_PASSWORD` at import and the CI settings file did not provide it | #432 |
| `backend-lint` | four ruff errors on `main` | #432 |
| `commit-lint` | Dependabot's long message bodies | #432 (ignores `Signed-off-by: dependabot[bot]`) |
| `pip-audit`, `npm-audit` | the vulnerable packages above | #431, #433, #434 |

CI results on 2026-10-26: #432 passes everything except the three dependency gates;
#431, #433 and #434 pass their own checks and fail only the baseline jobs and the audit
for the packages another PR fixes. The four PRs were not run together.

Open Dependabot PRs (18, #398 to #430):
- Superseded by the PRs above: #415 (DRF), #411 and #412 (OpenTelemetry), #429 (vite), #430 (zod).
- Routine, expected to go green after #432 and a rebase: #399, #400, #402, #403, #404, #413,
  #414, #416, #417, #426, #427.
- **#398 Elasticsearch client 9.x: do not merge.** The server is 8.19.23 and, as far as I know,
  a 9.x client does not support an 8.x server (not verified).
- **#401 framer-motion 12 to 14** is a major bump and needs a UI check first.
- Dependabot's branches belong to the upstream repository; they get fixed by merging #432 and
  asking Dependabot to rebase, not by pushing to them.

## Backlog, suggested order

1. **Merge order for the open PRs:** #432 first, then #431, #433, #434. Re-run or rebase the
   others after each merge (#424, #425, #428 included), then comment `@dependabot rebase` on
   the routine Dependabot PRs.
2. **Branches not pushed yet** (all local, none opened as PRs): `feature/ciso-scope`,
   `feature/vault-tls`, `feature/analyzers-non-root`, `feature/chromium-mail-renderer`,
   `feature/bump-elasticsearch-8.19.23`. `feature/single-mail-bucket` has to be redone on stage 1
   first. `feature/ai-inference-server`, `feature/xsoar-setup-guide` and
   `impl/scoring-verdict-pilot` (20 commits, never reviewed) are parked.
3. **Exercise stage 1 live:** recreate the dev containers once (and reconnect the MISP networks),
   then check an avatar upload, a mail preview and a web submission.
4. **CISO: remaining decision.** Still open to a CISO in scope: redo-analysis, ticket push and
   comments. Decide whether they stay.
5. **Secrets in container environments.** A Docker socket proxy with `CONTAINERS=1` lets a
   compromised container read every container's environment (82 variables from the Django
   container, 14 secret-looking). Traefik no longer has Docker access (#428), so that exposure is
   gone there. Moving secrets out of container env is still worth doing for anything that can read
   container metadata. The Vault TLS upgrade (existing Vault with data) was verified in a throwaway
   spike; a full `make deploy` was not.
   **Cortex Docker access.** `docker_proxy_cortex` cannot filter request bodies. Options: rootless
   Docker daemon (cheapest, host setup only), a body-filtering proxy (rejects `Privileged`, host
   mounts, `--net=host`), or a dedicated analyzer host.
6. **Object storage stages 2 to 5** (table above), starting with the `gcs` provider.
7. **Dependencies:** Elasticsearch is bumped to 8.19.23 on `feature/bump-elasticsearch-8.19.23`
   (`595d8790`, verified on the dev stack); revisit chromadb when a release above 1.5.9 ships;
   `nginx:1.29-alpine` and `valkey/valkey:7.2` (MISP stack) also lag. Settings and CI items from
   the audit that are still open: the ruff config only selects `E4`, `E7`, `E9` and `F`, and the
   gitleaks job is disabled.
8. **Hardening left over:** `cap_drop` on the database services, Vault and Traefik.
