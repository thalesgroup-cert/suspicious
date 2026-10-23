# Object Store Providers, Stage 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put every backend use of object storage behind one `ObjectStore` interface with an `s3` provider on `boto3`, with no change in behaviour on RustFS.

**Architecture:** A new `common/storage/` package holds the interface, error type, a fake store for tests, the `s3` provider and a small registry (`get_store()`). Callers stop importing `minio` and `common.clients.get_s3_client`; they call the store. `minio` leaves the backend requirements. Stages 2 to 5 (GCS provider, settings page, feeder, migration tools) get their own plans after this one lands.

**Tech Stack:** Python 3.12, Django, `boto3` (pinned), `botocore.stub.Stubber` for unit tests, Django test runner via `ww test`.

**Spec:** `docs/specs/2026-10-23-object-store-providers-design.md`

## Global Constraints

- RustFS must keep working in the dev stack; the dev stack is the test bed.
- No `storage.provider` means `s3`, and `storage.s3` keeps its current keys (`endpoint`, `public_endpoint`, `access_key`, `secret_key`, `secure`, `region`, `media_bucket`). Existing deployments need no config change.
- Provider exceptions never escape the provider: callers catch `StoreError`, with `.code` in `not_found`, `already_exists`, `access_denied`, `unavailable`, `invalid`.
- Providers never rewrite values (keys, labels, metadata).
- `open()` returns a stream, never the whole object.
- The S3 provider uses path-style addressing, `signature_version="s3v4"`, the configured region, `request_checksum_calculation="when_required"` and `response_checksum_validation="when_required"`.
- Browser URLs are signed with `public_endpoint` (falling back to `endpoint`); the presign client never connects.
- `boto3` is pinned to an exact version at least two weeks old; `minio` leaves `Suspicious/requirements.txt`.
- Tests run through `ww test backend --project suspicious <labels>`, from inside the worktree.
- Commit only listed files with explicit `git add <paths>`; Conventional Commits, subject at most 72 characters, trailer `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- Remove the root-owned stray `Suspicious/Suspicious/gunicorn.conf.py` after containerised runs, before committing.
- No em dashes in prose, docs or comments; comments only where the code does not already say it.

## Review Focus

1. A large object read through `open()` is streamed in chunks, never loaded whole (Task 2 owns the test).
2. Keys with spaces, unicode, `+`, `#` and `%` round-trip through put, list, stat and presign (Task 1 contract test, run on the fake and, as verification, live on RustFS).
3. `list`, `stat` and `open` on a missing bucket raise `StoreError("not_found")`, not an empty result or a raw exception (Tasks 1 and 2).
4. `delete_many` with more than 1000 keys is split into batches of at most 1000 (Task 2).
5. `ensure_bucket` on an existing or already-owned bucket succeeds, and a second call is a no-op (Tasks 1 and 2).

---

### Task 1: Interface, error type and fake store

**Files:**
- Create: `Suspicious/Suspicious/common/storage/__init__.py`, `base.py`, `fake.py`
- Test: `Suspicious/Suspicious/common/tests/storage_contract.py` (a mixin, not collected), `Suspicious/Suspicious/common/tests/test_storage_fake.py`

**Interfaces:**
- Produces, in `common.storage.base`:
  - `CODES = ("not_found", "already_exists", "access_denied", "unavailable", "invalid")`
  - `class StoreError(Exception)` with `__init__(self, code: str, message: str = "", *, bucket: str | None = None, key: str | None = None)`; attributes `code`, `bucket`, `key`. An unknown code raises `ValueError`.
  - `@dataclass(frozen=True) class ObjectInfo: name: str; size: int = 0; etag: str | None = None; last_modified: datetime | None = None; metadata: dict[str, str] = field(default_factory=dict); is_dir: bool = False`
  - `@dataclass(frozen=True) class HealthStatus: ok: bool; detail: str = ""`
  - Capability names as module constants: `OBJECT_TAGS`, `FREE_FORM_BUCKET_TAGS`, `LIFECYCLE`, `OBJECT_LOCK`, `BATCH_DELETE`, `PRESIGN_PUT` (string values equal to the lowercase names in the spec).
  - `class ObjectStream(Protocol)`: `read(size: int = -1) -> bytes`, `iter_chunks(chunk_size: int = 1 << 20) -> Iterator[bytes]`, `close() -> None`.
  - `class ObjectStore(ABC)` with abstract methods exactly as in the spec: `put(bucket, key, data, *, length=None, content_type=None, metadata=None, tags=None) -> None`; `open(bucket, key) -> ContextManager[ObjectStream]`; `download(bucket, key, path) -> None`; `stat(bucket, key) -> ObjectInfo`; `list(bucket, prefix="", recursive=True) -> Iterator[ObjectInfo]`; `list_prefixes(bucket, prefix="") -> Iterator[str]`; `delete(bucket, key) -> None`; `delete_many(bucket, keys) -> None`; `bucket_exists(bucket) -> bool`; `ensure_bucket(bucket) -> None`; `list_buckets() -> list[str]`; `get_bucket_labels(bucket) -> dict[str, str]`; `set_bucket_labels(bucket, labels) -> None`; `presign_get(bucket, key, expires, *, filename=None) -> str`; `presign_put(bucket, key, expires, *, content_type=None) -> str`; property `capabilities -> frozenset[str]`; `health() -> HealthStatus`. `expires` is a `datetime.timedelta`.
  - `common.storage.fake.FakeObjectStore(capabilities=frozenset(...))`: an in-memory `ObjectStore` that honours the whole interface; `presign_*` return `fake://<bucket>/<key>?expires=<seconds>`.
- `common.storage.__init__` re-exports the names above (the registry joins in Task 3).

- [ ] **Step 1: Write `storage_contract.py`: `class StoreContract` (a plain mixin with `make_store()` and `bucket` provided by the subclass) with tests** `test_put_open_roundtrip`, `test_open_streams_in_chunks` (put 3 MiB, `iter_chunks(1 << 20)` yields 3 chunks), `test_stat_reports_size_and_etag`, `test_stat_missing_key_is_not_found`, `test_missing_bucket_is_not_found` (list, stat, open each raise `StoreError` with `code == "not_found"`), `test_list_prefix_and_recursive`, `test_list_prefixes_returns_folders`, `test_delete_and_delete_many`, `test_ensure_bucket_is_idempotent`, `test_bucket_labels_roundtrip` (`{"Status": "To Do"}` returns unchanged), `test_awkward_keys_roundtrip` (keys `"a b/ü+#%.eml"` through put, list, stat), `test_download_writes_file`, `test_presign_get_contains_key_and_expiry`.
- [ ] **Step 2: Write `test_storage_fake.py`** (`StoreContract` + `SimpleTestCase`, `make_store()` returns `FakeObjectStore()`), plus `test_unknown_error_code_rejected`. Run `ww test backend --project suspicious common.tests.test_storage_fake`; expect an import failure.
- [ ] **Step 3: Implement `base.py` and `fake.py`** to the signatures above.
- [ ] **Step 4: Run the same command**; expect all pass.
- [ ] **Step 5: Commit** `feat(storage): ObjectStore interface and in-memory fake` with the five files.

### Task 2: The `s3` provider on boto3

**Files:**
- Create: `Suspicious/Suspicious/common/storage/s3.py`
- Modify: `Suspicious/requirements.txt` (add pinned `boto3`; leave `minio` until Task 9)
- Test: `Suspicious/Suspicious/common/tests/test_storage_s3.py`

**Interfaces:**
- Consumes: Task 1 (`ObjectStore`, `StoreError`, `ObjectInfo`, `HealthStatus`, capability constants).
- Produces: `class S3Store(ObjectStore)` with `__init__(self, *, endpoint: str, access_key: str, secret_key: str, secure: bool = False, region: str = "us-east-1", client=None)`. `client` injects a boto3 client (tests). `endpoint` is `host:port` as in `storage.s3.endpoint`; the URL scheme comes from `secure`. `capabilities` is static: `{OBJECT_TAGS, FREE_FORM_BUCKET_TAGS, LIFECYCLE, BATCH_DELETE, PRESIGN_PUT}`.
- Produces: `S3Store.from_config(cfg: dict, *, presign: bool = False) -> S3Store` building from the `storage.s3` section; `presign=True` uses `public_endpoint` / `public_secure` with the `endpoint` / `secure` fallbacks and sets nothing that connects.

- [ ] **Step 1: Write failing tests with `botocore.stub.Stubber`**: `test_client_config_pins_path_style_sigv4_and_checksums` (assert on `client.meta.config`), `test_error_mapping` (table: `NoSuchKey`, `NoSuchBucket`, `404` on head → `not_found`; `BucketAlreadyOwnedByYou`, `BucketAlreadyExists` on create → success inside `ensure_bucket`; `AccessDenied`, `403` → `access_denied`; `EndpointConnectionError`, `ConnectTimeoutError` → `unavailable`; `InvalidArgument` → `invalid`), `test_open_streams_without_reading_whole_body` (stub body whose `read()` raises if called with no size; `iter_chunks` is used), `test_put_unknown_length_uses_upload_fileobj`, `test_delete_many_batches_of_1000` (2500 keys → three `delete_objects` calls of 1000, 1000, 500), `test_list_follows_continuation_tokens`, `test_list_prefixes_uses_delimiter`, `test_bucket_labels_map_to_bucket_tagging`, `test_presign_uses_public_endpoint_and_never_connects` (host of the URL is the public endpoint; Stubber records zero calls), `test_from_config_falls_back_to_endpoint`. Add `LiveS3Contract(StoreContract, SimpleTestCase)` decorated `@skipUnless(os.environ.get("STORAGE_LIVE_ENDPOINT"), ...)`, building the store from `STORAGE_LIVE_ENDPOINT`, `STORAGE_LIVE_ACCESS_KEY`, `STORAGE_LIVE_SECRET_KEY`, with a unique bucket per run that it deletes afterwards.
- [ ] **Step 2: Run** `ww test backend --project suspicious common.tests.test_storage_s3`; expect failure.
- [ ] **Step 3: Implement `S3Store`.** Errors are mapped in one private function used by every method. `ensure_bucket` calls `head_bucket` then `create_bucket`, treating the two "already" codes as success. `put` uses `put_object` when `data` is `bytes` or `length` is given, otherwise `upload_fileobj`; `tags` are sent as the URL-encoded `Tagging` argument. `open` wraps the response `Body`. Retries `max_attempts=2`, connect timeout 5 s, read timeout 15 s (the spike's values).
- [ ] **Step 4: Run the command again**; expect pass (the live class is skipped).
- [ ] **Step 5: Commit** `feat(storage): S3 provider on boto3` with `s3.py`, `test_storage_s3.py`, `requirements.txt`.

### Task 3: Registry and provider selection

**Files:**
- Create: `Suspicious/Suspicious/common/storage/registry.py`, `Suspicious/Suspicious/common/storage/checks.py`
- Modify: `Suspicious/Suspicious/common/storage/__init__.py`, `Suspicious/Suspicious/common/apps.py` (register the check in `ready()`; create the `AppConfig` if `common` has none)
- Test: `Suspicious/Suspicious/common/tests/test_storage_registry.py`

**Interfaces:**
- Consumes: Task 2 (`S3Store.from_config`).
- Produces: `class StorageConfigError(Exception)`; `register_provider(name: str, factory: Callable[[dict, bool], ObjectStore]) -> None`; `get_store() -> ObjectStore`; `get_presign_store() -> ObjectStore`; `reset_store_cache() -> None`; `configured_provider_name() -> str`. The `s3` provider is registered at import.
- Resolution order, evaluated lazily on first call and cached per process: runtime config `storage.provider` (via `settings.config.get_config`, DB failure tolerated), then env `STORAGE_PROVIDER`, then `"s3"`. An unknown name raises `StorageConfigError` naming the registered providers.
- `checks.py`: a Django system check (`Error`, id `storage.E001`) that fails when the env or `settings.json` value, read without the DB, names an unknown provider.

- [ ] **Step 1: Write failing tests**: `test_default_is_s3`, `test_env_overrides_default`, `test_runtime_setting_overrides_env`, `test_unknown_provider_raises_with_known_names`, `test_store_is_cached_until_reset`, `test_db_unavailable_falls_back_to_env` (patch `get_config` to raise), `test_presign_store_uses_public_endpoint`, `test_startup_check_reports_unknown_provider`.
- [ ] **Step 2: Run** `ww test backend --project suspicious common.tests.test_storage_registry`; expect failure.
- [ ] **Step 3: Implement the registry and check** to the signatures above. `get_store()` builds from `get_section("storage.s3")` so Vault-overlaid secrets work as today.
- [ ] **Step 4: Run again**; expect pass.
- [ ] **Step 5: Commit** `feat(storage): provider registry, get_store and startup check`.

### Task 4: Django media storage and avatars

**Files:**
- Modify: `Suspicious/Suspicious/suspicious/storage_backends.py`, `Suspicious/Suspicious/profiles/profiles_utils/avatar_storage.py`
- Test: `Suspicious/Suspicious/suspicious/tests/test_storage_backends.py`, plus the existing avatar tests (find with `grep -rl avatar_storage Suspicious/Suspicious --include=test*.py`)

**Interfaces:**
- Consumes: `get_store()`, `get_presign_store()`, `FakeObjectStore`, `StoreError`.
- `MinioMediaStorage` keeps its name and its `client` injection point (now an `ObjectStore`, default from `get_store()`); its `settings.py` entry does not change. `MINIO_STORAGE_*` settings stay as the source of the media bucket name and `auto_create`.

- [ ] **Step 1: Update the two test modules** to inject `FakeObjectStore` instead of mocking `Minio`; assert saved bytes, `exists`, `size`, `delete`, `listdir`, `url` (presigned) and the auto-create behaviour through the fake. Run them; expect failures on the old calls.
- [ ] **Step 2: Move both modules** onto the store; `S3Error` handlers become `StoreError` with `.code == "not_found"`.
- [ ] **Step 3: Run** `ww test backend --project suspicious suspicious.tests.test_storage_backends profiles`; expect pass.
- [ ] **Step 4: Commit** `refactor(storage): media storage and avatars use ObjectStore`.

### Task 5: API views

**Files:**
- Modify: `api/storage.py`, `api/views/downloads.py`, `api/views/mail_preview.py`, `api/views/case_report.py`, `api/views/case_screenshot.py` (all under `Suspicious/Suspicious/`)
- Test: `api/tests/test_case_report_screenshot.py`, `api/tests/test_mail_preview_view.py`, and the tests next to `downloads.py` and `api/storage.py` (find with grep)

**Interfaces:**
- Consumes: `get_store()`, `FakeObjectStore`, `StoreError`.
- Mapping rule used by Tasks 5 to 8: `client.get_object(b, k)` + `.read()/.close()/.release_conn()` becomes `with store.open(b, k) as s: s.read()` (or `iter_chunks` for responses streamed to the client); `stat_object` → `stat`; `list_objects(b, prefix=, recursive=)` → `list`; `.object_name` → `.name`; `S3Error` → `StoreError`; direct `Minio(...)` fallbacks are deleted (the registry is the only constructor).

- [ ] **Step 1: Change the existing tests' patch targets** from `<module>.get_s3_client` / `common.clients.Minio` to `<module>.get_store`, returning a `FakeObjectStore` pre-loaded with the objects each test needs; keep every assertion on HTTP status, body and headers. Run them; expect failures.
- [ ] **Step 2: Move the five modules** per the mapping rule. File downloads and the preview view stream with `iter_chunks`.
- [ ] **Step 3: Run** `ww test backend --project suspicious api`; expect pass.
- [ ] **Step 4: Commit** `refactor(storage): API views use ObjectStore`.

### Task 6: Mail preview pipeline

**Files:**
- Modify: `mail_feeder/utils/email_preview/eml2png_renderer.py`, `preview_jobs.py`, `retention.py`; any file in `mail_feeder/minio_submission/` and `mail_feeder/global_submission/` that still touches the client (find with `grep -rnE "get_s3_client|Minio|S3Error" Suspicious/Suspicious/mail_feeder`)
- Test: `mail_feeder/tests/test_preview_jobs.py`, `mail_feeder/tests/test_username_variants.py`, `mail_feeder/minio_submission/tests_resilience.py`, `mail_feeder/global_submission/tests.py`, and the renderer and retention tests

**Interfaces:**
- Consumes: `get_store()`, `FakeObjectStore`, `StoreError`, the mapping rule from Task 5.
- `retention.py` reads `ObjectInfo.last_modified` (UTC-aware `datetime`); the S3 provider must supply it that way, and the test asserts it with a fake object older than the cutoff.

- [ ] **Step 1: Update tests** to the fake store; keep every behavioural assertion (retention cutoff, resilience on `unavailable`, preview put).
- [ ] **Step 2: Move the modules**; delete `eml2png_renderer._get_client`'s `MINIO_STORAGE_*` fallback construction.
- [ ] **Step 3: Run** `ww test backend --project suspicious mail_feeder`; expect pass.
- [ ] **Step 4: Commit** `refactor(storage): mail preview pipeline uses ObjectStore`.

### Task 7: Mail ingestion and the scanner

**Files:**
- Modify: `case_handler/case_utils/form_handlers/mail/minio.py`, `case_handler/case_utils/form_handlers/mail/mail_form.py`, `case_handler/case_utils/form_handlers/mail/email_processing/utils.py`, `tasp/cron/fetch_emails.py`, `tasp/cron/prefix_source.py`, `tasp/cron/utils.py`
- Test: `case_handler/tests/test_minio_manager.py`, `case_handler/tests/test_mail_form_bucket.py`, `tasp/tests/test_prefix_ingest.py`, `tasp/tests/test_handoff.py`, `tasp/tests/test_bucket_lifecycle.py`, `connectors/contrib/thehive/tests/test_campaign_sync.py` only if it patches these

**Interfaces:**
- Consumes: `get_store()`, `get_presign_store()`, `FakeObjectStore`, `StoreError`, `FREE_FORM_BUCKET_TAGS`.
- Bucket tags (`Tags.new_bucket_tags()` and `Status` values such as `Processing`, `To Do`) become `set_bucket_labels(bucket, {"Status": ...})`; the legacy tag scanner in `fetch_emails.py` runs only when `FREE_FORM_BUCKET_TAGS in store.capabilities`, otherwise it logs once and returns.
- `fget_object` becomes `download`; `presigned_put_object` / `presigned_get_object` become `presign_put` / `presign_get` on the presign store.

- [ ] **Step 1: Update the tests**: fake store in, same assertions on prefixes, `_status.json` handling, tag values, upload tag-skipping (`tag_bucket=False`), and a new `test_legacy_scanner_skipped_without_free_form_labels`.
- [ ] **Step 2: Move the modules.**
- [ ] **Step 3: Run** `ww test backend --project suspicious case_handler tasp`; expect pass.
- [ ] **Step 4: Commit** `refactor(storage): mail ingestion and scanner use ObjectStore`.

### Task 8: Scoring and connectors

**Files:**
- Modify: `score_process/scoring/cortex_analyzers/contrib/ai_minio_utils.py`, `score_process/scoring/screenshots/registry.py`, `connectors/contrib/thehive/connector.py`, `challenge.py`, `campaign_material.py`, `campaign_sync.py`; `scripts/ci/gen_company.py` and its test only if they run inside the Django image (otherwise leave them on their own dependency and say so in the commit body)
- Test: `score_process/tests/test_ai_minio_utils.py`, the screenshot registry tests, `connectors/contrib/thehive/tests/*`

**Interfaces:**
- Consumes: `get_store()`, `FakeObjectStore`, `StoreError`, the mapping rule from Task 5. `ai_minio_utils` functions that took a `Minio` argument take an `ObjectStore`; their signatures change only in the type of that parameter.

- [ ] **Step 1: Update tests** (`patch("...get_s3_client")` becomes `get_store`; the TheHive tests pass a fake store where they passed a mock client). Run them; expect failures.
- [ ] **Step 2: Move the modules.**
- [ ] **Step 3: Run** `ww test backend --project suspicious score_process connectors`; expect pass.
- [ ] **Step 4: Commit** `refactor(storage): scoring and connectors use ObjectStore`.

### Task 9: Remove `minio`, docs, live check and full suite

**Files:**
- Modify: `common/clients.py` (delete `get_s3_client`, `get_s3_presign_client`, `ensure_bucket`, the `Minio` import and `_DEFAULT_S3_REGION`; keep the Chroma helpers), `common/tests/test_clients.py`, `Suspicious/requirements.txt` (remove `minio`), `CONFIG.md`, `CHANGELOG.md`, `docs/getting-started/examples/Suspicious-settings.example.json` (only if a new key is documented)
- Test: `common/tests/test_clients.py`

**Interfaces:**
- Consumes: everything above.
- Produces: no `minio` import left in `Suspicious/Suspicious` outside migrations.

- [ ] **Step 1: Verify nothing is left:** `grep -rnE "^\s*(from|import) minio|get_s3_client|get_s3_presign_client" Suspicious/Suspicious --include=*.py` returns only migration text; fix any hit by moving it to the store.
- [ ] **Step 2: Remove the old factories and `minio`**; trim `test_clients.py` to the Chroma helpers.
- [ ] **Step 3: Document** in `CONFIG.md` (new `storage.provider` key, default `s3`, `STORAGE_PROVIDER`, the `StorageConfigError` and `storage.E001` messages) and add a `CHANGELOG.md` entry: backend moves from `minio-py` to `boto3` behind `ObjectStore`, no config change.
- [ ] **Step 4: Live verification on the dev RustFS** (labelled verification, not a test of record): run `LiveS3Contract` with `STORAGE_LIVE_ENDPOINT=rustfs:9000` and the dev credentials, from a throwaway container on the `suspicious_storage` network, and record the output in the PR description. Then rebuild the Django image from this branch, recreate `suspicious` and `suspicious_celery`, and confirm an avatar upload, a mail preview and a web submission still work in the running app.
- [ ] **Step 5: Run the full suite** `ww test backend --project suspicious`; expect pass with 0 errors.
- [ ] **Step 6: Commit** `refactor(storage): drop minio-py from the backend` and the docs in a separate `docs(storage): ...` commit.

---

## Follow-on plans (not in this plan)

Stage 2 `gcs` provider (adds `google-cloud-storage`, `fake-gcs-server`); stage 3 settings page Storage section; stage 4 feeder presigned uploads with the commit endpoint; stage 5 read fallback, `verify_storage_copy` and the runbook. Each is written when the one before it merges.

## Self-review notes

- Spec coverage for stage 1: interface and capabilities (Task 1), `s3` provider with the pinned client config and presign split (Task 2), selection order, lazy resolution, unknown-provider failure at startup (Task 3), media storage kept under `storage.backend` (Task 4), the legacy tag scanner gated on `FREE_FORM_BUCKET_TAGS` (Task 7), `minio` removed (Task 9). Spec items belonging to stages 2 to 5 are listed above and have no task here by design.
- Capabilities for `s3` are static in stage 1; probing the connected store is left for the settings-page test endpoint (stage 3).
