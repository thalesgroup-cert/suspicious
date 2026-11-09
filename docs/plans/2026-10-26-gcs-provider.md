# Object Store Providers, Stage 2: the `gcs` Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `gcs` provider to the `ObjectStore` layer so production can run on a Google Cloud Storage bucket, selected with `storage.provider: gcs` or `STORAGE_PROVIDER=gcs`.

**Architecture:** `GcsStore` in `common/storage/gcs.py` implements the stage 1 `ObjectStore` ABC on the official `google-cloud-storage` client, with its own error mapping, registered in the existing registry. Credentials default to Application Default Credentials (workload identity), with an optional service-account JSON kept as a secret. No public endpoint: signed URLs are V4, signed with a key when one exists and through the IAM signBlob API when running keyless.

**Tech Stack:** Python 3.12, `google-cloud-storage` (pinned), `google.api_core.exceptions`, Django test runner via `ww test`, `fsouza/fake-gcs-server` for live verification.

**Spec:** `docs/specs/2026-10-23-object-store-providers-design.md` (stage 2). Stage 1 plan: `docs/plans/2026-10-23-object-store-providers.md` (done, on `main`).

## Global Constraints

- Provider exceptions never escape the provider: callers catch `StoreError`, with `.code` in `not_found`, `already_exists`, `access_denied`, `unavailable`, `invalid`.
- Providers never rewrite values (keys, labels, metadata); an invalid value raises `invalid`.
- `open()` returns a stream, never the whole object.
- No `storage.provider` means `s3`; `storage.s3` is untouched. A deployment that never sets `gcs` must not import the Google libraries at startup (lazy import in the factory).
- GCS has no `public_endpoint`; the `presign` flag of the factory is accepted and ignored.
- `storage.gcs` is backend scope only (never in the `shared` or `feeder` scope); `storage.gcs.service_account_json` is a secret (Vault when deployed, `settings.json` otherwise, as `get_section` does today).
- The `gcs` provider does NOT report `free_form_bucket_tags` (GCS labels are lowercase letters, digits, `-`, `_`), so the legacy bucket-tag scanner stays S3-only.
- `google-cloud-storage` is pinned to an exact version at least two weeks old: `3.17.0` (released 2026-10-08). Its core dependencies are light; no `grpc` extra.
- Tests run through `ww test backend --project suspicious <labels>`, from inside the worktree. The Django test image must contain the new dependency: rebuild it from this worktree with `SUSPICIOUS_PATH=$PWD/Suspicious docker compose --env-file /home/forensics/suspicious/suspicious/deployment/.env -f deployment/docker-compose.yml -f deployment/docker-compose.override.yml build suspicious` (run once after Task 1 changes `requirements.txt`; it changes the shared image tag).
- Commit only listed files with explicit `git add <paths>`; Conventional Commits, subject at most 72 characters, trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- Remove the root-owned stray `Suspicious/Suspicious/gunicorn.conf.py` (and an empty `settings.json`) after containerised runs, before committing.
- No em dashes in prose, docs or comments; comments only where the code does not already say it.

## What the spike established (against fake-gcs-server, library 3.17.0)

Works as needed: bucket create, `upload_from_file` (with `size`, with unknown length), `get_blob` (size, etag, tz-aware `updated`, `metadata` round trip, `content_type`), `blob.open("rb")` streaming, `list_blobs` with `prefix` and `delimiter` (`iterator.prefixes`), `download_to_filename`, `delete_blobs`, `list_buckets`, `bucket.exists()`.
Differences the provider must absorb:
- creating an existing bucket raises `Conflict` (409); a missing key or bucket raises `NotFound` (404), for `open`, `list_blobs` (on iteration) and `delete`; `get_blob` returns `None` for a missing key. `delete` of a missing key must be swallowed (S3 and the fake are idempotent).
- `generate_signed_url` raises `AttributeError` when the credentials cannot sign (anonymous). With a service-account key it signs offline (V4: `X-Goog-Algorithm`, `X-Goog-Credential`, `X-Goog-Date`, `X-Goog-Expires`, `X-Goog-SignedHeaders`, `X-Goog-Signature`; a PUT signs `content-type;host`). Keyless signing is `generate_signed_url(..., service_account_email=<email>, access_token=<token>)` and calls the IAM API; it needs `roles/iam.serviceAccountTokenCreator` on the service account and cannot be exercised without a real GCP project.
- the emulator does not persist bucket labels (a `patch` read back as `{}`): label behaviour is unit-tested with mocks and left to a real-GCS check.

## Review Focus

1. A missing key and a missing bucket raise `not_found` on `open`, `stat`, `list` and `list_prefixes` (lazy iterator errors included), and `delete` of a missing key does not raise.
2. `ensure_bucket` is idempotent: an existing bucket we can read succeeds, a 409 for a bucket we cannot access is `already_exists`/`access_denied`, never a raw `Conflict`.
3. A label or metadata value GCS would reject (`{"Status": "To Do"}`, an upper-case key, a `tags` key that duplicates a `metadata` key) raises `invalid` and is never rewritten.
4. Signing: a store with no signing capability raises a `StoreError`, not `AttributeError`; the keyless path passes `service_account_email` and `access_token` and refreshes an expired token.
5. A deployment on `s3` never imports `google.*` (registry import stays lazy), and an unknown provider message lists `gcs`.

---

### Task 1: Dependency, shared helper and the object operations

**Files:**
- Modify: `Suspicious/requirements.txt` (add `google-cloud-storage==3.17.0`), `Suspicious/Suspicious/common/storage/s3.py` (use the shared helper)
- Create: `Suspicious/Suspicious/common/storage/util.py`, `Suspicious/Suspicious/common/storage/gcs.py`
- Test: `Suspicious/Suspicious/common/tests/test_storage_gcs.py`, `Suspicious/Suspicious/common/tests/test_storage_util.py`

**Interfaces:**
- Produces, in `common.storage.util`: `content_disposition(filename: str) -> str` returning `attachment; filename*=UTF-8''<percent-encoded filename>` (the exact string `S3Store.presign_get` builds today); `S3Store` imports it, behaviour unchanged.
- Produces, in `common.storage.gcs`: `class GcsStore(ObjectStore)` with `__init__(self, *, client, signing=None, location: str | None = None, project: str | None = None)`; `client` is a `google.cloud.storage.Client` (tests inject a stand-in); `signing` is described in Task 3. Implements `put`, `open`, `download`, `stat`, `list`, `list_prefixes`, `delete`, `delete_many` in this task (the other abstract methods raise `NotImplementedError` until Tasks 2 and 3, so the class is not yet instantiable; use a test subclass that stubs them).
- Error mapping, a private `_map(exc, bucket=None, key=None) -> StoreError` used by one `_errors(bucket, key)` context manager: `NotFound` -> `not_found`; `Conflict` -> `already_exists`; `Forbidden`, `Unauthorized`, `google.auth.exceptions.DefaultCredentialsError`, `RefreshError` -> `access_denied`; `BadRequest`, `ValueError` from the library -> `invalid`; `TooManyRequests`, `ServiceUnavailable`, `InternalServerError`, `GatewayTimeout`, `DeadlineExceeded`, `RetryError`, `requests.ConnectionError`, `requests.Timeout`, `google.auth.exceptions.TransportError` -> `unavailable`; any other `google.api_core.exceptions.GoogleAPICallError` by `.code` (4xx other -> `invalid`, 408/429/5xx -> `unavailable`); anything else -> `unavailable`. `StoreError` passes through untouched. Messages never contain credentials.
- Object semantics: `put` accepts bytes-like or a file object; when `length` is given pass it as `size`; `content_type` is passed through; `metadata` and `tags` are both stored as custom object metadata and a key present in both raises `invalid`. `open` returns a context manager yielding an `ObjectStream` over `blob.open("rb", chunk_size=262144)`; errors on read are mapped. `list` yields `ObjectInfo(name, size, etag, last_modified, metadata)` for blobs and, when `recursive=False`, `ObjectInfo(name=<prefix ending in "/">, is_dir=True)` for each page's `prefixes`; `list_prefixes` yields the prefixes. `stat` raises `not_found` when `get_blob` returns `None`. `delete` swallows `NotFound`; `delete_many` uses `bucket.delete_blobs(blobs, on_error=<ignore NotFound>)`.

- [ ] **Step 1: Pin the dependency and rebuild the test image** (see Global Constraints), then verify `import google.cloud.storage` works inside the image.
- [ ] **Step 2: Write failing tests** in `test_storage_util.py` (`content_disposition("a b é.eml")` equals the S3 form) and `test_storage_gcs.py`: `test_error_mapping` (a table of exception -> code covering every row above), `test_put_rejects_duplicate_metadata_and_tags_keys`, `test_put_passes_size_content_type_and_metadata`, `test_open_streams_in_chunks_and_maps_not_found`, `test_stat_missing_is_not_found`, `test_list_recursive_and_delimiter` (blobs then prefixes, `is_dir`), `test_list_missing_bucket_is_not_found_on_iteration`, `test_delete_missing_key_is_silent`, `test_delete_many_ignores_missing`. The stand-in client is a small class recording calls and raising configured `google.api_core.exceptions` instances; assert on call arguments and on resulting `StoreError` codes. Run `ww test backend --project suspicious common.tests.test_storage_gcs common.tests.test_storage_util`; expect failure.
- [ ] **Step 3: Implement** `util.py`, the S3 import change and the operations above in `gcs.py`.
- [ ] **Step 4: Run** the two test labels plus `common.tests.test_storage_s3`; expect pass.
- [ ] **Step 5: Commit** `feat(storage): GCS object operations on google-cloud-storage` (files: `requirements.txt`, `util.py`, `s3.py`, `gcs.py`, both test files).

### Task 2: Buckets, labels, capabilities and health

**Files:**
- Modify: `Suspicious/Suspicious/common/storage/gcs.py`, `Suspicious/Suspicious/common/tests/storage_contract.py`
- Test: `Suspicious/Suspicious/common/tests/test_storage_gcs.py`, `Suspicious/Suspicious/common/tests/test_storage_fake.py`, `Suspicious/Suspicious/common/tests/test_storage_s3.py`

**Interfaces:**
- Consumes: Task 1.
- Produces: `GcsStore.bucket_exists(bucket) -> bool` (`bucket.exists()`; a 403 is `access_denied`), `ensure_bucket(bucket) -> None` (create with `location` when absent; on `Conflict` re-check `bucket_exists`: readable means success, otherwise raise `already_exists` for a bucket owned by someone else), `list_buckets() -> list[str]` (`client.list_buckets(project=...)` names), `get_bucket_labels(bucket) -> dict[str, str]` (`{}` when none), `set_bucket_labels(bucket, labels)` (validates first: at most 64 labels, keys and values at most 63 characters, keys start with a lowercase letter, keys and values only lowercase letters, digits, `-` and `_`; a violation raises `StoreError("invalid", ...)` naming the offending key; then `bucket.labels = labels; bucket.patch()`), `capabilities -> frozenset({OBJECT_TAGS, LIFECYCLE, PRESIGN_PUT})` (no `FREE_FORM_BUCKET_TAGS`, no `BATCH_DELETE`), `health() -> HealthStatus` (`list_buckets` through the mapper; a `StoreError` gives `HealthStatus(ok=False, detail="<code>: <message>")`).
- Contract change (closes the stage 1 deferred item): in `storage_contract.py` the label test runs `{"Status": "To Do"}` only when `FREE_FORM_BUCKET_TAGS in store.capabilities`, otherwise it runs a lowercase pair (`{"status": "to-do"}`); the contract mixin gains an overridable `labels_supported = True` class attribute so a live run against an emulator that does not persist labels can skip it. The fake and S3 contract classes keep running the original value.

- [ ] **Step 1: Write failing tests**: `test_ensure_bucket_idempotent_and_conflict_rechecks`, `test_label_validation_table` (upper-case key, space in value, key starting with a digit, 65 labels, 64-character value, empty key: each `invalid`, none sent to the client), `test_labels_roundtrip_through_patch`, `test_capabilities_exclude_free_form_bucket_tags`, `test_health_reports_access_denied`, `test_list_buckets_uses_project`; adjust the contract and re-run the fake and S3 test labels to prove they still pass. Run; expect failure.
- [ ] **Step 2: Implement** the methods and the contract change.
- [ ] **Step 3: Run** `ww test backend --project suspicious common.tests.test_storage_gcs common.tests.test_storage_fake common.tests.test_storage_s3`; expect pass.
- [ ] **Step 4: Commit** `feat(storage): GCS buckets, labels, capabilities and health`.

### Task 3: V4 signed URLs

**Files:**
- Modify: `Suspicious/Suspicious/common/storage/gcs.py`
- Test: `Suspicious/Suspicious/common/tests/test_storage_gcs.py`

**Interfaces:**
- Consumes: Tasks 1 and 2, `content_disposition`.
- Produces: `GcsStore.presign_get(bucket, key, expires, *, filename=None) -> str` (`method="GET"`, `version="v4"`, `response_disposition=content_disposition(filename)` when given) and `presign_put(bucket, key, expires, *, content_type=None) -> str` (`method="PUT"`, `content_type` passed so it is signed). `expires` is a `timedelta`.
- `signing` constructor argument: `None` (no signing capability: both methods raise `StoreError("invalid", "signing is not configured ...")` instead of letting `AttributeError` escape) or a `Signer` with two attributes: `credentials` (a `google.auth.credentials.Signing` instance, used as `credentials=`) or, for keyless runs, `service_account_email: str` plus a `token()` callable returning a fresh access token (refreshing the ADC credentials when expired); the keyless call passes `service_account_email=` and `access_token=`. A private `_signed_url(blob, **kwargs)` applies whichever form and maps errors (a failed IAM call is `access_denied` or `unavailable` by the mapper).

- [ ] **Step 1: Write failing tests**: `test_presign_get_with_key_signs_offline` (generate an RSA key in the test, build `service_account.Credentials.from_service_account_info`, assert the URL host is `storage.googleapis.com`, path contains the percent-encoded key, `X-Goog-Expires=300`, and `response-content-disposition` is present when a filename is given), `test_presign_put_signs_content_type` (`X-Goog-SignedHeaders` contains `content-type`), `test_presign_without_signing_raises_store_error`, `test_keyless_signer_passes_email_and_token_and_refreshes` (a stand-in credential whose token expires; assert `generate_signed_url` receives `service_account_email` and `access_token` and that the refresh callable ran once), `test_presign_never_calls_the_network_with_a_key` (no HTTP: the stand-in client's request methods fail the test if used).
- [ ] **Step 2: Implement** the signing helpers and methods.
- [ ] **Step 3: Run** `ww test backend --project suspicious common.tests.test_storage_gcs`; expect pass.
- [ ] **Step 4: Commit** `feat(storage): GCS V4 signed URLs with key and keyless signing`.

### Task 4: Configuration, registry, secrets and docs

**Files:**
- Modify: `Suspicious/Suspicious/common/storage/gcs.py` (`from_config`), `Suspicious/Suspicious/common/storage/registry.py`, `Suspicious/Suspicious/settings/config.py` (`SECRET_FIELDS`, `SCOPE_SECTIONS["backend"]`), `CONFIG.md`, `CHANGELOG.md`
- Test: `Suspicious/Suspicious/common/tests/test_storage_gcs.py`, `Suspicious/Suspicious/common/tests/test_storage_registry.py`

**Interfaces:**
- Consumes: Tasks 1 to 3.
- Produces: `GcsStore.from_config(cfg: dict, *, presign: bool = False) -> GcsStore` reading the `storage.gcs` section: `project` (optional), `location` (optional, bucket creation location), `api_endpoint` (optional; the emulator or a private endpoint, uses `AnonymousCredentials` when set together with `credentials: anonymous`), `credentials` (`"adc"` default, `"service_account"`, or `"anonymous"` for the emulator only), `service_account_json` (secret, required when `credentials` is `service_account`; a JSON string, parsed with `service_account.Credentials.from_service_account_info`; a parse failure raises `StorageConfigError` naming the key and never echoing the content), `signing_service_account_email` (optional override for keyless signing; default is the ADC credentials' `service_account_email`, refreshed first because a Compute credential reports `default` until it has been refreshed). The `presign` argument is ignored.
- Registry: `register_provider("gcs", factory)` where the factory imports `common.storage.gcs` inside the function; `get_section("storage.gcs")` supplies the config (the registry already does this by provider name). `SECRET_FIELDS["storage.gcs"] = ("service_account_json",)`; `SCOPE_SECTIONS["backend"]` gains `"storage.gcs"` (not `shared`, so the feeder never receives it).
- Docs: `CONFIG.md` gets the `storage.gcs` keys, the required IAM roles (object access on the bucket; `roles/iam.serviceAccountTokenCreator` on the service account for keyless signed URLs; bucket creation and listing need project-level permissions) and the labels rule; `CHANGELOG.md` gets one entry under Added.

- [ ] **Step 1: Write failing tests**: `test_from_config_adc_default`, `test_from_config_service_account_json_parsed_and_invalid_json_does_not_leak` (the error message must not contain the JSON text), `test_from_config_anonymous_with_api_endpoint`, `test_signing_email_defaults_to_adc_email_after_refresh`, in the registry tests `test_gcs_is_registered_and_lazy` (importing `common.storage.registry` does not import `google.cloud.storage`: check `sys.modules` in a subprocess or with the module removed), `test_unknown_provider_message_lists_gcs`, `test_get_store_builds_gcs_from_config`; a config test that `storage.gcs` is in the backend scope and not in `shared`/`feeder`, and that `service_account_json` is a secret field.
- [ ] **Step 2: Implement** `from_config`, the registry entry and the config registrations; write the docs.
- [ ] **Step 3: Run** `ww test backend --project suspicious common settings suspicious`; expect pass.
- [ ] **Step 4: Commit** `feat(storage): register the gcs provider and its configuration` and a separate `docs(storage): document storage.gcs` commit.

### Task 5: Live verification and the full suite

**Files:**
- Modify: `Suspicious/Suspicious/common/tests/test_storage_gcs.py` (add the live class)
- Test: same

**Interfaces:**
- Consumes: everything above.
- Produces: `LiveGcsContract(StoreContract, SimpleTestCase)` decorated `@skipUnless(os.environ.get("STORAGE_LIVE_GCS_ENDPOINT"), ...)`: it builds a `GcsStore` through `from_config({"api_endpoint": <endpoint>, "credentials": "anonymous", "project": "test"}, ...)`, uses a unique bucket per run and deletes it afterwards, sets `labels_supported = False` when `STORAGE_LIVE_GCS_LABELS` is not `1` (the emulator does not persist labels), and overrides the presign contract test to a no-op with a comment pointing at the offline signing tests in Task 3.

- [ ] **Step 1: Add the live class** and run the default suite for it (skipped): `ww test backend --project suspicious common.tests.test_storage_gcs`; expect pass with the live tests skipped.
- [ ] **Step 2: Live run against the emulator** (verification, not a test of record): start `fsouza/fake-gcs-server` with `-scheme http -port 4443 -backend memory` on a throwaway Docker network, run the new image on that network with `STORAGE_LIVE_GCS_ENDPOINT=http://<emulator>:4443` through `ww test` is not possible (the harness network), so run `python manage.py test common.tests.test_storage_gcs.LiveGcsContract` from a throwaway container of the rebuilt image with the worktree mounted; record the command and output in the PR description. Remove the emulator and network afterwards.
- [ ] **Step 3: Run the full suite** `ww test backend --project suspicious`; expect all pass, no errors.
- [ ] **Step 4: Commit** `test(storage): live contract for the GCS provider against an emulator`.

---

## Not in this plan

A CI job that runs the live contract against an emulator (needs a sidecar service in `ci.yml`; follow-up). Verification against a real GCS project (bucket labels, keyless signing through IAM, bucket creation permissions): none of it can be done from this environment and the PR must say so. The settings page, the feeder and the migration tools are stages 3 to 5.

## Self-review notes

- Spec coverage for stage 2: native client with ADC default and optional service-account JSON in secrets (Task 4), no `public_endpoint` and V4 signing with `signBlob` for workload identity (Task 3), labels rule and the missing `free_form_bucket_tags` capability (Task 2), tags as custom metadata (Task 1), registry and lazy import (Task 4), emulator testing (Task 5). The spec open item "confirm GCS label rules against the labels the legacy scanner sets" is settled by the capability gate; "detect" and the settings page are stage 3.
- Known unverified: keyless signing and label persistence on real GCS; both are unit-tested at the call boundary only.
