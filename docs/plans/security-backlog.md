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
| Phase 2.2 CISO scope on submissions | VULN-07 | Branch `feature/ciso-scope`. Submissions page lists a CISO's own submissions only; scope is on Investigations; a CISO can challenge for a user in scope (audit trail names the CISO) and cannot edit case details. Backend only: no challenge button on the Investigations page yet. Redo-analysis, ticket push and comments are still open to a CISO in scope (decision pending). | `724cdb1d` |
| Phase 2.3 single MinIO bucket | VULN-09 | Branch `feature/single-mail-bucket`. Web uploads go to `storage.s3.web_bucket` (default `mail-submissions`), one prefix per submission, untagged so the legacy scanner skips it. Existing buckets untouched. | `c350d308` |
| Phase 3.1 Vault TLS, unseal keys off the host | VULN-05 | Branch `feature/vault-tls`. TLS on the listener (Vault-only CA, SANs), `VAULT_CACERT` for clients; `make unseal` prompts for the keys, no file; auto-unseal documented as the production path. Not run: `make up`/`deploy` end to end or an upgrade of an existing Vault. | `4dac184e`, `f4665043` |
| Phase 3.2 `no-new-privileges` + `cap_drop: ALL` | n/a | Done for `suspicious`, `suspicious_celery`, `suspicious_celery_beat`, `suspicious_ui`, `feeder`, `cortex`. Not applied to the database services, Vault or Traefik. | `5232de22` |
| Phase 3.2 non-root analyzers | VULN-06 | Branch `feature/analyzers-non-root`. Both run as uid 1001; AIMailAnalyzer needed a writable `./tmp`. Verified through Cortex; AI image tested as a layer, not a full rebuild. Will conflict with `feature/ai-inference-server` (same Dockerfile). | `e5d1d775` |

## Backlog, suggested order

Done on branches, waiting for review and merge: VULN-05, VULN-06, VULN-07 (backend),
VULN-09, plus PRs #424 (nltk) and #425 (Chroma proxy).

1. **Renderer (VULN-08).** Replace `wkhtmltoimage` with headless Chromium without
   root; replay the report's three SSRF payloads against the current `nh3` renderer first.
2. **CISO challenge in the UI.** A challenge button on the Investigations page for a
   CISO in scope; decide whether redo-analysis, ticket push and comments stay open to
   a CISO.
3. **Verify, not build:** exercise the Traefik socket proxy on a Traefik-enabled
   stack; re-run the SSRF payloads; run `make up` / `make deploy` end to end with the
   Vault TLS change and an upgrade of an existing Vault.
4. **S3 client library.** `minio-py` 7.2.20 is current but its last release is
   2025-11-27 and the MinIO server repo is archived (2026-04-24); `boto3` has ~9.9k
   stars, a release on 2026-10-21 and 100+ commits in 2026. Migrating touches ~10 files
   plus the feeder; `boto3` needs `request_checksum_calculation="when_required"` for
   non-AWS stores, and must be tested against RustFS. Not a security fix; schedule it.
5. **Dependencies:** bump Elasticsearch (`8.19.7` in use, `8.19.23` is the newest 8.19.x
   tag) after checking its advisories; revisit chromadb when a release above 1.5.9
   ships; `nginx:1.29-alpine` and `valkey/valkey:7.2` (MISP stack) also lag.
6. **Hardening left over:** `cap_drop` on the database services, Vault and Traefik.
