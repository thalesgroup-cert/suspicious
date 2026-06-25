"""End-to-end: a real user submission mail -> real S3 bucket via the feeder.

Exercises the whole prefix-contract path with NO mocks: deposit a phishing
report (a wrapper email forwarding a suspicious .eml) into GreenMail over SMTP,
run the feeder's real ingestion against a real IMAP poll, and assert the
submission lands in a freshly created bucket as the portable prefix contract
(`<id>/...` objects + a valid `_status.json` written last).

Requires the docker stack from `docker-compose.e2e.yaml`:

    docker compose -f docker-compose.e2e.yaml up -d
    SUSPICIOUS_E2E=1 pytest tests/test_feeder_e2e_bucket.py

Skipped unless SUSPICIOUS_E2E=1 so the default suite stays offline-green.
"""
import email.message
import json
import logging
import os
import pathlib
import smtplib
import tempfile
import time
import uuid

import pytest

import classes.models.submission_contract as sc
import classes.models.configs.main_config as main_config
import classes.services.acknowledge_bad_mail_service as ack_service
import classes.services.mailbox_setup_service as setup
import classes.services.minio_service as minio_service_mod
import main as feeder_main

pytestmark = pytest.mark.skipif(
    os.environ.get("SUSPICIOUS_E2E") != "1",
    reason="needs docker-compose.e2e.yaml stack; set SUSPICIOUS_E2E=1",
)

LOG = logging.getLogger("test-e2e")

IMAP_HOST, IMAP_PORT = "127.0.0.1", 3143
SMTP_HOST, SMTP_PORT = "127.0.0.1", 3025
S3_ENDPOINT = "127.0.0.1:9000"
S3_KEY, S3_SECRET = "minioadmin", "minioadmin"


def _config(bucket: str, working_path: pathlib.Path) -> main_config.MainConfig:
    return main_config.MainConfig.from_json({
        "mail-connectors": {
            "imap": {
                "greenmail": {
                    "enable": True, "host": IMAP_HOST, "port": IMAP_PORT,
                    "login": "imap_user", "password": "imap_password",
                    "mailbox_to_monitor": "INBOX",
                },
            },
        },
        "s3": {
            "endpoint": S3_ENDPOINT, "access_key": S3_KEY, "secret_key": S3_SECRET,
            "secure": False, "feeder_bucket": bucket,
        },
        "mail": {"server": SMTP_HOST, "port": SMTP_PORT, "tls": False, "password": "x"},
        "working-path": str(working_path),
        "imap-idle": False,
    })


def _deposit_submission(subject: str) -> None:
    """Send a wrapper mail forwarding a suspicious .eml as an attachment."""
    inner = email.message.EmailMessage()
    inner["From"] = "attacker@evil.test"
    inner["To"] = "victim@corp.com"
    inner["Subject"] = "You won a prize, click here"
    inner.set_content("http://phish.evil.test/login please verify your account")

    wrapper = email.message.EmailMessage()
    wrapper["From"] = "reporter@corp.com"
    wrapper["To"] = "imap_user@localhost"
    wrapper["Subject"] = subject
    wrapper.set_content("Forwarding this suspicious email for analysis.")
    wrapper.add_attachment(
        inner.as_bytes(), maintype="message", subtype="rfc822",
        filename="suspicious.eml",
    )

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.send_message(wrapper)


def _fresh_minio_client():
    import minio
    return minio.Minio(S3_ENDPOINT, access_key=S3_KEY, secret_key=S3_SECRET, secure=False)


def test_user_submission_lands_in_bucket_as_prefix_contract():
    bucket = f"feeder-e2e-{uuid.uuid4().hex[:10]}"
    subject = f"Fwd: phish {uuid.uuid4().hex[:6]}"

    with tempfile.TemporaryDirectory() as d:
        working = pathlib.Path(d)
        config = _config(bucket, working)

        # 1) deposit the submission over SMTP
        _deposit_submission(subject)
        # GreenMail commits the delivery asynchronously; give it a moment.
        time.sleep(1.0)

        # 2) run the real feeder ingestion once
        minio_service = minio_service_mod.MinioService(config.minio)
        minio_service.connect()
        mailboxes = setup.setup_mailboxes(config=config, logger=LOG)
        assert mailboxes, "feeder failed to connect to GreenMail IMAP"
        sink = feeder_main.choose_sink(config, minio_service)
        assert sink is not None, "feeder_bucket set -> PrefixSink expected"
        acker = ack_service.AcknowledgeBadMailService(config=config.mail, logger=LOG)

        feeder_main.process_emails_from_mailboxes(
            config=config, acknowledge_bad_mail_service=acker,
            mailboxes=mailboxes, minio_service=minio_service, sink=sink,
        )

    # 3) inspect the real bucket
    client = _fresh_minio_client()
    assert client.bucket_exists(bucket), "feeder did not create the bucket"

    objects = [o.object_name for o in client.list_objects(bucket, recursive=True)]
    assert objects, "no objects written to bucket"

    status_objs = [o for o in objects if o.endswith(sc.STATUS_OBJECT_NAME)]
    assert len(status_objs) == 1, f"expected one _status.json, got {status_objs}"
    prefix = status_objs[0][: -len(sc.STATUS_OBJECT_NAME)]

    # every object lives under the single submission prefix
    assert all(o.startswith(prefix) for o in objects), objects

    # 4) the manifest is valid against the contract model
    raw = client.get_object(bucket, status_objs[0]).read()
    manifest = json.loads(raw)
    model = sc.SubmissionStatus.model_validate(manifest)
    assert model.status == sc.STATUS_TODO
    assert model.schema_version == sc.CONTRACT_SCHEMA
    assert model.emails_to_analyze, "forwarded .eml should be queued for analysis"
    assert model.reported_by == "reporter@corp.com"

    # the queued email object actually exists in the bucket
    for ref in model.emails_to_analyze:
        assert ref in objects, f"manifest references missing object {ref}"

    # cleanup
    for o in objects:
        client.remove_object(bucket, o)
    client.remove_bucket(bucket)
