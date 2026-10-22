# Security plan status and backlog

Source: the "Audit de Sécurité & Posture d'Architecture" report of 2026-10-16
(v1.6.2, commit 00d6efe5), section 6 roadmap. Status checked against `main`
on 2026-10-22; "not re-tested" means the code change is merged but the report's
own payloads were not replayed.

## Roadmap status

| Report item | Finding | Status | Where |
|---|---|---|---|
| Phase 1.1 docker-socket-proxy | VULN-01 | Done. Only the two `docker_proxy_*` services mount the socket (Cortex: `CONTAINERS/IMAGES/INFO/POST=1`; Traefik: `CONTAINERS/EVENTS`, `POST=0`). Cortex analyzer launch tested on the dev stack; the Traefik proxy is **not tested** (no Traefik in dev). | `5232de22` |
| Phase 1.2 network segmentation | VULN-03 | Done: `data`, `storage` and `cortex` tiers beside the shared `suspicious_network`. The report names four networks (frontend/backend/data/cortex); the split differs but the UI and feeder are off the data tier. | `dd8d804d` |
| Phase 1.3 nltk >= 3.10.4 | VULN-02 (partly) | PR open | #424 |
| Phase 1.3 chromadb >= 1.5.10 | VULN-02 | **No fixed release exists** (1.5.9 is the latest on PyPI, Docker tags past it are `1.5.10.dev*`). Mitigated: the proxy forwards only the routes the app uses. The report cites CVE-2026-45829; Dependabot lists GHSA-36p7-vc44-83pf, GHSA-2wm9-hf6c-p5cr, GHSA-xph7-9rjv-w5fr. PR open. | #425 |
| Phase 1.4 database authentication | VULN-03 | Done: Redis, Elasticsearch and ChromaDB (token proxy). Harness: `deployment/scripts/ci/db_auth_harness.sh`, 25 checks. | `918c01bc`..`d8689e4a` |
| Phase 2.1 mail preview sanitiser | VULN-04 | Merged: `nh3` allow-list and rendering without network access (`eml2png_renderer.py`). Report payloads not re-tested. | `fix(preview)` 2026-10-21 |
| Phase 2.1 replace wkhtmltoimage | VULN-08 | **Open.** Still `imgkit` + `wkhtmltopdf`. | backlog |
| Phase 2.2 CISO fail-closed | VULN-07 | Done in `profiles_utils/scope.py` (no profile returns none). | main |
| Phase 2.2 align submission views with `scoped_case_queryset()` | VULN-07 | **Open.** `DEFAULT_SUBMISSION_ELEVATED_GROUPS` still contains `CISO` and the submission/comment views do not use the scoped queryset. | backlog |
| Phase 2.3 single MinIO bucket | VULN-09 | **Open.** Bucket names are now valid S3 names (`bucket_name_for`), but there is still one bucket per submission. | backlog |
| Phase 3.1 Vault TLS, unseal keys off the host | VULN-05 | **Open.** `tls_disable = 1`; keys still in `vault/unseal.keys`. | backlog |
| Phase 3.2 `no-new-privileges` + `cap_drop: ALL` | n/a | Done for `suspicious`, `suspicious_celery`, `suspicious_celery_beat`, `suspicious_ui`, `feeder`, `cortex`. Not applied to the database services, Vault or Traefik. | `5232de22` |
| Phase 3.2 non-root analyzers | VULN-06 | **Open.** No `USER` in `AIMailAnalyzer` or `MailHeaderAnalyzer` Dockerfiles. | backlog |

## Backlog, suggested order

1. **Analyzers run as root (VULN-06, CVSS 7.8).** Add a non-root `USER` to the
   AIMailAnalyzer and MailHeaderAnalyzer images; check Cortex can still write the
   mounted job directory.
2. **CISO scope on submission views (VULN-07).** Use `scoped_case_queryset()` in
   `api/views/submissions.py`, `comments.py` and `CanAccessSubmission`, and drop
   `CISO` from the elevated groups, with tests for a CISO outside their scope.
3. **Vault (VULN-05).** TLS on the listener and a plan for the unseal keys
   (auto-unseal or split custody).
4. **One MinIO bucket (VULN-09).** `mail-submissions` with per-submission prefixes;
   needs a migration path for existing buckets.
5. **Renderer (VULN-08).** Replace `wkhtmltoimage` with headless Chromium without
   root; replay the report's three SSRF payloads against the current renderer first.
6. **Verify, not build:** exercise the Traefik socket proxy on a Traefik-enabled
   stack; re-run the report's SSRF payloads against the `nh3` renderer.
7. **Dependencies:** merge #424 and #425; bump Elasticsearch (`8.19.7` in use,
   `8.19.23` is the newest 8.19.x tag) after checking its advisories; revisit
   chromadb when a release above 1.5.9 ships; `nginx:1.29-alpine` and
   `valkey/valkey:7.2` (MISP stack) also lag.
8. **Hardening left over:** `cap_drop` on the database services, Vault and Traefik.
