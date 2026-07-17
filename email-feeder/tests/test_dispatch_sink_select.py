from unittest import mock
import main


class _Minio:
    pass


def test_choose_sink_prefix_when_bucket_set():
    cfg = mock.Mock()
    cfg.minio.feeder_bucket = "feeder"
    sink = main.choose_sink(cfg, _Minio())
    assert sink is not None
    assert sink.__class__.__name__ == "PrefixSink"


def test_choose_sink_none_when_bucket_empty():
    cfg = mock.Mock()
    cfg.minio.feeder_bucket = ""
    assert main.choose_sink(cfg, _Minio()) is None


def test_upload_valid_prefix_calls_sink():
    sink = mock.Mock()
    main.upload_valid_submission(sink, _Minio(), "/w/sub-a", "260326141159-aaa", "u@x")
    sink.store.assert_called_once()


def test_upload_valid_legacy_calls_upload_directory():
    minio = mock.Mock()
    main.upload_valid_submission(None, minio, "/w/Sub_A", "Sub_A", "u@x")
    minio.upload_directory.assert_called_once()
    args, kwargs = minio.upload_directory.call_args
    assert "sub-a" in (list(args) + list(kwargs.values()))
