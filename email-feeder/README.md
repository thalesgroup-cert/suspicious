# Email Feeder

The email feeder is a standalone Python service (Pydantic v2) that turns
forwarded emails into Suspicious submissions. It polls one or more IMAP
mailboxes, extracts the reported mail and its attachments, uploads them to
S3-compatible storage (RustFS), and sends an acknowledgement mail through SMTP.
Case creation and analysis are done by the Django backend, which picks the
uploaded submissions up (`tasp.cron.fetch_emails`).

## Flow

1. A user forwards a suspicious mail to the mailbox watched by the feeder
   (`mail-connectors` in `config.json`).
2. The feeder fetches `UNSEEN` messages, parses headers, body and attachments
   (including `message/rfc822` and `.msg` attachments) and applies the size caps.
3. The submission is uploaded to the object store. A message is marked as seen
   only once it was handled; a failed upload leaves it `UNSEEN` for the next cycle.
4. An acknowledgement mail is sent to the reporter through the configured SMTP
   server. Mails that cannot be processed get a "bad mail" acknowledgement
   (`classes/templates/acknowledge_bad_mail.jinja2`).

Upload layouts:

- Prefix contract (when `s3.feeder_bucket` is set): one bucket, one prefix per
  submission (`<submission_id>/...`), with `_status.json` written last so the
  consumer never sees a partial submission.
- Legacy mode (`feeder_bucket` empty): one bucket per submission.

## Configuration

The feeder reads a JSON file (default `config.json` in the working directory,
override with `FEEDER_CONFIG_PATH`). Start from `config-sample.json`.

### Local file keys

| Key | Default | Meaning |
|---|---|---|
| `mail-connectors.imap.<name>` | none | Plain IMAP connectors |
| `mail-connectors.imaps.<name>` | none | Implicit-TLS IMAP connectors (`use_ssl` is forced on) |
| `working-path` | `/app/case` | Scratch directory for submissions being processed |
| `timer-inbox-emails` | `10` | Seconds between mailbox refreshes (must be > 0, else the default is used) |
| `imap-idle` | `true` | Wait with IMAP IDLE instead of sleeping (see below) |
| `caps.max_attachment_bytes` | `26214400` (25 MiB) | Per-attachment limit |
| `caps.max_attachments` | `50` | Attachment count limit |
| `caps.max_total_bytes` | `52428800` (50 MiB) | Total submission size limit |

Each connector takes `enable`, `host`, `port`, `login`, `password`,
`mailbox_to_monitor`, and for `imaps` the optional TLS files `certfile`,
`keyfile`, `rootcafile`. Disabled connectors are skipped.

`imap-idle`: when exactly one mailbox is enabled and the server advertises IDLE,
the loop blocks in IMAP IDLE so new mail wakes it immediately; the wait is capped
at `timer-inbox-emails` so the loop still polls and reacts to SIGHUP. With
several mailboxes, a server without IDLE, or `"imap-idle": false`, it falls back
to interval polling.

### S3 and mail settings come from the backend

In a deployed stack the `s3` and `mail` blocks are not in `config.json`. When
both `BACKEND_URL` and `FEEDER_API_TOKEN` are set, the feeder calls
`GET {BACKEND_URL}/api/config/feeder/` with `Authorization: Token <token>`
(5 attempts, 2 s apart), builds the `s3` and `mail` blocks from the response and
merges them with the local file (connectors, working path, timers, caps). The
merged result is cached next to the config file as `.config-cache.json`
(mode 0600) and used if the backend is unreachable at the next start or reload.
With no cache and no backend, startup fails.

Mapping from the backend `settings.json` (see `CONFIG.md` at the repository root):

| Feeder key | Source in settings |
|---|---|
| `s3.endpoint`, `access_key`, `secret_key`, `secure` | `storage.s3.*` |
| `mail.server`, `port`, `username`, `password`, `tls` | `email.smtp.*` |
| `mail.footer` | `email.content.footer` |
| `mail.group` | `email.content.team_name` |
| `mail.company_name` | `email.content.global_domain` |
| `mail.company_url` | `email.content.website` |
| `mail.suspicious_web` | `email.links.submissions` |
| `mail.glossary`, `inquiry`, `inquiry_text` | `email.links.glossary`, `inquiry`, `inquiry_text` |
| `mail.security`, `security_msg` | `email.links.security_contact`, `security_text` |
| `mail.socials`, `mail.logos` | `email.socials`, `email.logos` |

In API mode the whole `s3` block is replaced by the API values, so a local
`s3.feeder_bucket` is not carried over and the feeder uses legacy
bucket-per-submission mode.

Without `BACKEND_URL`/`FEEDER_API_TOKEN` (standalone or development), put the
`s3` and `mail` blocks in `config.json` yourself:

```json
{
  "s3": {
    "endpoint": "localhost:9000",
    "access_key": "minioadmin",
    "secret_key": "minioadmin",
    "secure": false,
    "feeder_bucket": "suspicious-feeder"
  },
  "mail": {
    "server": "localhost",
    "port": 3025,
    "username": "SUSPICIOUS",
    "password": "imap_password",
    "tls": false,
    "footer": "Limited Distribution",
    "group": "Your Cybersecurity Team Name",
    "company_name": "test.com",
    "company_url": "https://www.test.com/en",
    "suspicious_web": "https://suspicious.test/submissions/",
    "glossary": "https://glossary.example",
    "inquiry": "mailto:inquiry@example.com",
    "inquiry_text": "inquiry@example.com",
    "security": "mailto:security@example.com",
    "security_msg": "security@example.com",
    "socials": {"linkedin": "https://www.linkedin.com/company/test"},
    "logos": {
      "company": "data:image/png;base64,...",
      "acknowledge-badmail": "data:image/png;base64,..."
    }
  }
}
```

`s3` requires `endpoint`, `access_key`, `secret_key`; `mail` requires `server`,
`password` and `tls` (the other keys have the defaults shown in
`classes/models/configs/internals/mail.py`).

### Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `BACKEND_URL` | unset | Backend base URL (`http://suspicious:9020` in compose) |
| `FEEDER_API_TOKEN` | unset | Service token for `/api/config/feeder/`; create it with the `create_service_token` management command in the backend |
| `FEEDER_CONFIG_PATH` | `config.json` | Path of the local config file |
| `FEEDER_CA_BUNDLE` | `/etc/private/rootcafile.pem` | Compose-level variable, passed to the container as `REQUESTS_CA_BUNDLE` so the config call trusts the internal CA |
| `LOG_LEVEL` | `INFO` | Log level |
| `LOG_FORMAT` | `json` | Console format: `json` or `plain` (files stay JSON) |
| `LOG_DIR` | `/app/log` | Directory for the log files |
| `FEEDER_TESTING` | unset | `1` disables file handlers (tests) |
| `OTEL_ENABLED` | `true` | Set `false` to disable OpenTelemetry export |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://tempo:4318` | OTLP target; failures never block startup |

## Operations

- Health: `GET :9091/health` returns JSON status (`ok` or `degraded`) with IMAP
  and S3 freshness; it is the container healthcheck.
- Reload: `kill -HUP <pid>` (or `docker kill -s HUP feeder`) reloads the config
  on the next cycle, so mailboxes can be added or disabled without a restart.
- Logs: JSON on stdout plus rotating files (10 MiB x 5) in `LOG_DIR`:
  `feeder.log`, `imap.log`, `minio.log`, `smtp.log`. Records carry `trace_id`
  and `span_id`. The compose stack mounts `${FEEDER_PATH}/logs` on `/app/log`;
  create that directory yourself as the host user before the first start,
  otherwise Docker creates it as root and the feeder cannot write.
- Non-root: the image runs as the `feeder` user (UID/GID 1000, build args
  `APP_UID`/`APP_GID`), with `no-new-privileges` and all capabilities dropped in
  compose. The mailbox content is attacker-controlled, so do not run it as root.
  `working-path` and `/app/log` must be writable by that UID.

## Tests

```bash
cd email-feeder
pip install -r requirements-dev.txt
pytest tests
```

The default suite is offline. The end-to-end test
(`tests/test_feeder_e2e_bucket.py`) deposits a real report mail in GreenMail and
checks the prefix-contract layout in a real RustFS bucket. It needs the e2e stack
and is skipped unless `SUSPICIOUS_E2E=1`:

```bash
docker compose -f docker-compose.e2e.yaml up -d
SUSPICIOUS_E2E=1 pytest tests/test_feeder_e2e_bucket.py
docker compose -f docker-compose.e2e.yaml down
```

`docker-compose.e2e.yaml` publishes SMTP 3025, IMAP 3143 and the S3 API 9000 on
127.0.0.1 (user `imap_user` / `imap_password`, S3 `minioadmin` / `minioadmin`).

## Manual testing

`docker-compose.dev.yaml` starts GreenMail and RustFS for running the feeder by
hand without the full stack:

```bash
docker compose -f docker-compose.dev.yaml up -d
```

| Port | Service |
|---|---|
| 3025 / 3465 | SMTP / SMTPS |
| 3110 / 3995 | POP3 / POP3S |
| 3143 / 3993 | IMAP / IMAPS |
| 9000 / 9001 | RustFS S3 API / admin console |

Default credentials: IMAP `imap_user@localhost` / `imap_password`; RustFS
`minioadmin` / `minioadmin`. Edit them in the compose file if needed. For this
setup, use the `mail-connectors` of `config-sample.json` and the `s3`/`mail`
blocks above, then run `python3 main.py`. Stop the services with
`docker compose -f docker-compose.dev.yaml down`.
