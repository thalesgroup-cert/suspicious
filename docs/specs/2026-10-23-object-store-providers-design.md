# Object Storage Providers: Design

## Context

Suspicious talks to object storage through `minio-py`, directly, from about 25
files: the Django backend, the Celery mail scanner, the AI analyzer helper and
the email feeder. Production is moving from RustFS to a Google Cloud Storage
(GCS) bucket. Three facts shape the work:

- GCS is reachable through its S3-compatible XML API with HMAC keys, but that
  path has gaps (Google documents `x-amz-*` handling only for headers that have
  an `x-goog-*` equivalent; tagging, batch delete and list V2 behaviour are
  unverified) and it needs long-lived secret keys. GCS's native client uses
  workload identity or application default credentials, so no stored key.
- `minio-py` 7.2.20 works but is slowing down (last release 2025-11-27, the
  MinIO server repo was archived 2026-04-24). A spike showed `boto3` works
  against the dev RustFS for every operation the code uses, with either
  `request_checksum_calculation` setting.
- The feeder is a separate image. It already fetches its config from
  `/api/config/feeder/` at startup (with a token and a last-good cache), and it
  holds storage credentials only to upload mail.

## Goals

- One storage interface (`ObjectStore`) that all application code uses, with two
  providers: `s3` (boto3; RustFS, MinIO, AWS) and `gcs` (`google-cloud-storage`).
- Existing deployments keep working with no config change: no `storage.provider`
  means `s3`, and `storage.s3` keeps its current keys.
- Production on GCS authenticates without a stored key by default (application
  default credentials, which covers workload identity on GKE and VM service
  accounts). A service-account JSON key is an option, kept in Vault.
- An administrator can pick the provider, fill in its fields, test it and see
  what it supports from the settings page.
- The feeder holds no storage credentials and needs no storage SDK.
- Moving existing data from RustFS to GCS is documented and verifiable, and the
  application can read from the old store while the copy finishes.

## Non-goals

- No multi-store routing in this work (named stores such as `primary` and
  `archive`). One active store, with a bucket name per purpose. The registry
  must make adding more stores an additive change later.
- No Azure provider. A third provider must fit the interface, but is not built.
- No change to what is stored or to bucket and prefix layout. This is a swap of
  the client layer, not of the storage model.
- No use of lifecycle rules, object lock, SSE or checksums in this work. The
  interface reports them as capabilities; features that use them come later.
- No S3 bucket-per-user redesign. That is `feature/single-mail-bucket` (VULN-09).

## Anti-goals

- Choosing a provider silently. Detection only suggests; the explicit setting
  wins. A wrong guess would write evidence to the wrong store.
- Secrets in the database or the settings JSON. Provider secrets go to Vault,
  as connector secrets do.
- A "switch" that strands data. Changing the provider in the UI must warn that
  existing objects are not copied.
- Hiding a real difference between providers behind one API that lies about it.
  When a provider lacks a feature, the capability is false and callers cope.

## Constraints

- RustFS must keep working in the dev stack; the dev stack is the test bed.
- Tests run through `ww test`. About 30 existing test files mock the client;
  they must keep passing or be updated in the same change that breaks them.
- New dependencies are pinned: `boto3`, `google-cloud-storage`. `minio` leaves
  `requirements.txt` for the backend once the last caller moves.
- The settings page, the connector registry and `ConfigField` are the pattern
  for provider-specific forms.
- Pull requests are small and stacked, one per stage below.

## Design

### The interface

`common/storage/` holds the interface, the registry and the providers.

```
ObjectStore
  # objects
  put(bucket, key, data, *, length=None, content_type=None, metadata=None, tags=None)
  open(bucket, key)            -> context manager with read(), iter_chunks(), close()
  download(bucket, key, path)
  stat(bucket, key)            -> ObjectInfo(name, size, etag, last_modified, metadata)
  list(bucket, prefix="", recursive=True) -> iterator of ObjectInfo
  list_prefixes(bucket, prefix="")        -> iterator of str
  delete(bucket, key)
  delete_many(bucket, keys)
  # buckets
  bucket_exists(bucket) / ensure_bucket(bucket) / list_buckets()
  get_bucket_labels(bucket) / set_bucket_labels(bucket, labels)
  # URLs
  presign_get(bucket, key, expires, *, filename=None)
  presign_put(bucket, key, expires, *, content_type=None)
  # introspection
  capabilities -> frozenset of {"object_tags", "lifecycle", "object_lock",
                                "batch_delete", "presign_put"}
  health()     -> HealthStatus(ok, detail)
```

Errors are normalised to `StoreError` with `.code` in `not_found`,
`already_exists`, `access_denied`, `unavailable`, `invalid`. The call sites that
catch `S3Error` today catch `StoreError` instead. Provider exceptions never
escape the provider.

`open()` returns a stream, never the whole object, so a large mail does not need
to fit in memory. `ensure_bucket` treats "already exists" as success.

Bucket labels exist because the legacy mail scanner tags buckets
(`set_bucket_tags` today). S3 maps them to bucket tags, GCS to bucket labels,
which have stricter character rules (lowercase letters, digits, `-`, `_`). The
provider validates and raises `invalid` rather than rewriting values.

### Providers

**`s3`** uses `boto3` with path-style addressing, `signature_version="s3v4"`,
the configured region, `request_checksum_calculation="when_required"` and
`response_checksum_validation="when_required"` (both verified against RustFS).
Presigned URLs for browsers are signed with `public_endpoint`, the same split
that `get_s3_presign_client()` has today; the presign client never connects.
`capabilities` reports what the connected store supports; on RustFS
alpha.90 that is `object_tags`, `lifecycle` and `batch_delete`.

**`gcs`** uses `google-cloud-storage`. Credentials: application default
credentials by default; optionally a service-account JSON from Vault. Signed
URLs are V4. If the runtime has no private key (workload identity), signing goes
through the IAM `signBlob` API, which needs the `iam.serviceAccountTokenCreator`
role on the service account; `health()` reports that when it is missing.
Object tags map to custom metadata. There is no `public_endpoint` setting.

Provider differences that surface to callers: tags versus metadata, lifecycle
format, presign host. They are handled inside the provider.

### Selecting a provider

Resolved once per process, in this order:

1. `storage.provider` from runtime settings (the settings page writes it).
2. `STORAGE_PROVIDER` environment variable, for first boot before anyone opens
   the UI.
3. Default `s3`.

`get_store()` returns the configured `ObjectStore`. `get_s3_client()` and
`get_s3_presign_client()` go away once their callers move. An unknown provider
name raises at startup, not on first use.

Detection is a settings-page action, not a startup step: "Detect" probes the
endpoint and proposes a provider and region, and the administrator confirms.
Which response headers separate RustFS, MinIO and GCS has not been verified;
the plan must test that against the dev RustFS and, if possible, a real GCS
endpoint, and drop the button if no reliable signal exists.

### Settings page

A Storage section, administrator only, in the settings UI:

- provider dropdown; the fields below it come from the provider's schema
  (`ConfigField`, the way connectors render);
- `GET/PATCH /api/settings/storage/` (non-secret fields to the DB runtime
  tier, secret fields to Vault);
- `POST /api/settings/storage/test/`: connect, check bucket access, put, get
  and delete a probe object, and return the capabilities;
- a change-provider confirmation that states existing objects are not copied;
- the secret fields are write-only in the UI.

`storage.s3` stays in the `shared` config scope for now. `storage.gcs` is
backend scope only, so the feeder never receives it.

### Email feeder

Feeder uploads move to presigned PUT URLs.

- A feeder-scope endpoint returns, for one submission, the bucket, the prefix
  and a presigned PUT URL per file. The feeder cannot choose the bucket or the
  prefix pattern.
- The feeder uploads with plain `requests`. The `minio` dependency and the
  storage credentials leave the feeder, and it can leave the `storage` network.
  Its `network-check.sh` rule changes accordingly.
- The URL host must be reachable from the feeder: the S3 provider signs for the
  internal endpoint when the caller is the feeder; GCS signs for its public
  host.
- A PUT cannot cap object size. The backend `stat`s each object after upload
  and rejects the submission over the configured limit.
- The prefix-mode `_status.json` marker the feeder and scanner use today stays;
  the plan must say who writes it once the feeder has no credentials.

The feeder still reads `/api/config/feeder/` at startup and keeps the last-good
cache. It stops reading `s3.access_key` and `s3.secret_key`.

### Migrating RustFS data to GCS

The application does not copy data. Bulk copy uses Storage Transfer Service (or
`rclone`). The application provides:

- `storage.fallback_provider` (read-only): when an object is not found in the
  active store, `open` and `stat` try the fallback. Writes never go there.
- `manage.py verify_storage_copy`: lists both stores and compares key sets,
  sizes and checksums, and exits non-zero on any difference.

Cutover: copy, verify, switch `storage.provider`, keep the fallback until
verified again, then retire it. Source data is never deleted by the application.

## Staged delivery

Each stage is its own branch and pull request, in order.

1. `ObjectStore`, the registry, the `s3` provider and the backend callers.
   Behaviour unchanged; RustFS is the check.
2. The `gcs` provider, tested against `fake-gcs-server` and, if available, a
   real bucket.
3. The settings page Storage section, test connection and (if viable) detect.
4. The feeder on presigned URLs, with the scanner and `network-check.sh` changes.
5. Fallback read and `verify_storage_copy`, plus the migration runbook.

## Decisions

Made by the person who asked:
- Production moves to GCS; the design must cover both RustFS and GCS.
- Provider is chosen in settings or environment, not silently detected.
- A storage section in the settings page, with the feeder getting its setup
  from the backend at startup.

My calls (to be checked):
- Native `google-cloud-storage` for GCS, boto3 for S3, behind our own
  interface; `obstore` is a possible later replacement, not evaluated against
  RustFS.
- Application default credentials by default; HMAC keys remain possible through
  the `s3` provider.
- One active store; multi-store later.
- Feeder through presigned PUT URLs, not a duplicated SDK and not an upload
  through Django.
- Migration is an external bulk copy plus a read fallback and a verify command.

## Left to the builder

Module layout inside `common/storage/`, the exact settings keys for `gcs`, how
streaming reads wrap each SDK, retry and timeout values, the presign URL expiry,
how the 25 call sites are grouped into commits, and the shape of the
test doubles (a fake `ObjectStore` for unit tests is encouraged).

## Open items

- Verify a reliable detection signal, or drop "Detect".
- Confirm GCS bucket-label rules against the labels the legacy scanner sets.
- Confirm the feeder-to-scanner `_status.json` flow in the plan.
- Re-test every RustFS capability on the version deployed, not alpha.90.
