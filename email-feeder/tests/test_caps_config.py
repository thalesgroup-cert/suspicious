import classes.models.configs.main_config as mc


def _base():
    return {
        "s3": {"endpoint": "e", "access_key": "a", "secret_key": "s", "feeder_bucket": "feeder"},
        "mail": {"server": "x", "password": "", "tls": True},
        "mail-connectors": {"imap": {}, "imaps": {}},
    }


def test_feeder_bucket_parsed():
    conf = mc.MainConfig.from_json(_base())
    assert conf.minio.feeder_bucket == "feeder"


def test_caps_defaults_when_absent():
    conf = mc.MainConfig.from_json(_base())
    assert conf.caps.max_attachments == 50
    assert conf.caps.max_attachment_bytes == 26214400
    assert conf.caps.max_total_bytes == 52428800


def test_caps_overridden():
    j = _base()
    j["caps"] = {"max_attachments": 3, "max_attachment_bytes": 10, "max_total_bytes": 20}
    conf = mc.MainConfig.from_json(j)
    assert conf.caps.max_attachments == 3
    assert conf.caps.max_total_bytes == 20


def test_legacy_no_feeder_bucket_defaults_empty():
    j = _base()
    del j["s3"]["feeder_bucket"]
    conf = mc.MainConfig.from_json(j)
    assert conf.minio.feeder_bucket == ""
