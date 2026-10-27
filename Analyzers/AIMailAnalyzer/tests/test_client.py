"""
Tests for the thin Cortex client (ai_mail_classifier.py) and its HTTP contract
with the inference server. Needs neither torch nor numpy: the client image
ships neither, and these tests run against a stub server on a loopback port.
"""
import json
import subprocess
import sys
import tarfile
import textwrap
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import ai_mail_classifier as client

AIMAIL_DIR = Path(__file__).resolve().parent.parent

GOOD_RESULT = {
    "malscore": "7.0",
    "classification": "DANGEROUS",
    "confidence": "0.61",
    "classification_probabilities": "[0.1 0.2 0.7]",
    "classification_breakdown": {"SAFE": 0.1, "UNWANTED": 0.2, "DANGEROUS": 0.7},
    "sub_classification": "CLASSIC_PHISHING",
    "sub_classification_confidence": "0.5",
    "sub_classification_probabilities": "[0. 0. 0. 0. 0.5 0.1 0.05 0.05]",
    "sub_classification_breakdown": {"CLASSIC_PHISHING": 0.5},
    "contributing_phrases": [{"text": "Click here", "impact": 0.12}],
    "main_probabilities": {"SAFE": "10.00%", "UNWANTED": "20.00%", "DANGEROUS": "70.00%"},
    "sub_probabilities": {"CLASSIC_PHISHING": "50.00%"},
    "email_embedding": "[0.1, 0.2, 0.3]",
}


class StubServer:
    """Loopback HTTP server that replays a script of (status, json-body) answers
    to POST /classify (the last entry repeats) and records what it received."""

    def __init__(self, script):
        self.script = list(script)
        self.requests = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 (http.server naming)
                length = int(self.headers.get("Content-Length", 0))
                stub.requests.append((self.path, json.loads(self.rfile.read(length) or b"{}")))
                status, body = stub.script[0] if len(stub.script) == 1 else stub.script.pop(0)
                payload = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):  # silence test output
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def stub_server():
    servers = []

    def make(script):
        servers.append(StubServer(script))
        return servers[-1]

    yield make
    for server in servers:
        server.close()


# --- classify_remote ---------------------------------------------------------


def test_classify_remote_posts_body_and_variant_and_returns_result(stub_server):
    server = stub_server([(200, GOOD_RESULT)])
    result = client.classify_remote(client.build_session(), server.url, "hello body", "public")
    assert result == GOOD_RESULT
    assert server.requests == [("/classify", {"mail_body": "hello body", "variant": "public"})]


def test_classify_remote_tolerates_trailing_slash_in_url(stub_server):
    server = stub_server([(200, GOOD_RESULT)])
    client.classify_remote(client.build_session(), server.url + "/", "b", "personal")
    assert server.requests[0][0] == "/classify"


def test_http_error_surfaces_the_servers_detail_not_a_bare_status(stub_server):
    server = stub_server([(503, {"detail": "Required models unavailable for variant 'public': a.pth"})])
    with pytest.raises(RuntimeError, match=r"HTTP 503.*Required models unavailable for variant 'public'"):
        client.classify_remote(client.build_session(), server.url, "b", "public")


def test_non_json_error_body_is_still_reported(stub_server):
    server = stub_server([(500, b"<html>boom</html>")])
    with pytest.raises(RuntimeError, match=r"HTTP 500.*boom"):
        client.classify_remote(client.build_session(), server.url, "b", "personal")


def test_non_json_success_body_is_reported(stub_server):
    server = stub_server([(200, b"not json")])
    with pytest.raises(RuntimeError, match="non-JSON"):
        client.classify_remote(client.build_session(), server.url, "b", "personal")


def test_response_missing_keys_is_a_clear_error_not_a_keyerror(stub_server):
    partial = {k: v for k, v in GOOD_RESULT.items() if k not in ("email_embedding", "main_probabilities")}
    server = stub_server([(200, partial)])
    with pytest.raises(RuntimeError, match=r"missing .*main_probabilities.*email_embedding"):
        client.classify_remote(client.build_session(), server.url, "b", "personal")


def test_unreachable_server_is_reported_with_the_url(monkeypatch):
    monkeypatch.setattr(client, "INFERENCE_RETRIES", 0)
    with pytest.raises(RuntimeError, match=r"cannot reach inference server at http://127\.0\.0\.1:1/classify"):
        client.classify_remote(client.build_session(), "http://127.0.0.1:1", "b", "personal", timeout=2)


def test_retries_503_while_the_server_is_still_loading(stub_server):
    """The server answers 503 until weights are loaded after a restart; the
    first Cortex job after that must not fail on the very first attempt."""
    server = stub_server([(503, {"detail": "still loading"}), (200, GOOD_RESULT)])
    result = client.classify_remote(client.build_session(), server.url, "b", "personal")
    assert result["classification"] == "DANGEROUS"
    assert len(server.requests) == 2


def test_gives_up_after_the_configured_retries(stub_server, monkeypatch):
    monkeypatch.setattr(client, "INFERENCE_RETRIES", 1)
    server = stub_server([(503, {"detail": "down for good"})])
    with pytest.raises(RuntimeError, match="down for good"):
        client.classify_remote(client.build_session(), server.url, "b", "personal")
    assert len(server.requests) == 2  # first attempt + 1 retry


def test_session_ignores_proxy_env_by_default(stub_server, monkeypatch):
    """Corporate hosts inject HTTP(S)_PROXY into containers; a proxy cannot
    reach the private bridge-gateway IP, so the call must bypass it."""
    server = stub_server([(200, GOOD_RESULT)])
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    assert client.build_session().trust_env is False
    assert client.classify_remote(client.build_session(), server.url, "b", "personal") == GOOD_RESULT


def test_session_can_opt_back_in_to_proxy_env(monkeypatch):
    monkeypatch.setenv("INFERENCE_USE_PROXY", "1")
    assert client.build_session().trust_env is True


# --- the client's import closure --------------------------------------------


def test_client_imports_without_the_ml_stack():
    """The Cortex client image installs only requirements-client.txt. If
    ai_mail_classifier (or anything it imports) pulls in numpy/torch/
    sentence_transformers again, that image breaks at runtime with an
    ImportError no unit test in this folder would otherwise notice."""
    probe = textwrap.dedent(
        """
        import sys

        class Block:
            def find_spec(self, name, path=None, target=None):
                if name.split(".")[0] in {"numpy", "torch", "sentence_transformers", "fastapi"}:
                    raise ImportError(f"{name} must not be imported by the client")

        sys.meta_path.insert(0, Block())
        import ai_mail_classifier, health  # noqa: F401
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", probe], cwd=AIMAIL_DIR, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr


# --- full analyzer run through cortexutils -----------------------------------


def make_job(tmp_path, *, members, config=None):
    """Build a Cortex job directory the way Cortex hands it to an analyzer."""
    job = tmp_path / "job"
    (job / "input").mkdir(parents=True)
    (job / "output").mkdir()
    archive = job / "input" / "mail.tar"
    with tarfile.open(archive, "w") as tar:
        for name, content in members.items():
            src = tmp_path / f"src_{name}"
            src.write_text(content, encoding="utf-8")
            tar.add(src, arcname=name)
    (job / "input" / "input.json").write_text(json.dumps({
        "dataType": "file", "file": "mail.tar", "filename": "mail.tar",
        "tlp": 2, "pap": 2, "config": config or {},
    }))
    return job


@pytest.fixture
def run_job(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    def run(members, config=None, expect_exit=False):
        job = make_job(tmp_path, members=members, config=config)
        analyzer = client.AIMailClassifier(job_directory=str(job))
        if expect_exit:
            with pytest.raises(SystemExit):
                analyzer.run()
        else:
            analyzer.run()
        return json.loads((job / "output" / "output.json").read_text())

    return run


MAIL = {
    "mail.txt": "Dear user, verify your account now.",
    "mail.headers": "From: a@evil.example\nSubject: urgent\n",
}


def test_analyzer_builds_the_cortex_report_from_the_server_result(run_job, stub_server):
    server = stub_server([(200, GOOD_RESULT)])
    out = run_job(MAIL, config={"inference_url": server.url})

    assert out["success"] is True
    assert out["summary"] == {"classification": "DANGEROUS", "malscore": "7.0", "confidence": "0.61"}
    full = out["full"]
    assert full["classification"] == "DANGEROUS"
    assert full["malscore"] == "7.0"
    assert full["contributing_phrases"] == GOOD_RESULT["contributing_phrases"]
    report = full["report"]
    assert report["analyzed_mail_content"] == MAIL["mail.txt"]
    assert report["email_embedding"] == GOOD_RESULT["email_embedding"]
    # downstream: chromadb_utils does json.loads(report["email_embedding"])
    assert json.loads(report["email_embedding"]) == [0.1, 0.2, 0.3]
    assert server.requests[0][1] == {"mail_body": MAIL["mail.txt"], "variant": "personal"}


def test_analyzer_forwards_the_configured_variant(run_job, stub_server):
    server = stub_server([(200, GOOD_RESULT)])
    run_job(MAIL, config={"inference_url": server.url, "variant": "public"})
    assert server.requests[0][1]["variant"] == "public"


def test_analyzer_reports_a_clear_error_when_the_server_is_down(run_job, monkeypatch):
    monkeypatch.setattr(client, "INFERENCE_RETRIES", 0)
    out = run_job(MAIL, config={"inference_url": "http://127.0.0.1:1"}, expect_exit=True)
    assert out["success"] is False
    assert "Error calling inference server" in out["errorMessage"]
    assert "cannot reach inference server" in out["errorMessage"]


def test_analyzer_reports_the_servers_reason_for_a_503(run_job, stub_server, monkeypatch):
    monkeypatch.setattr(client, "INFERENCE_RETRIES", 0)
    server = stub_server([(503, {"detail": "Required models unavailable for variant 'public'"})])
    out = run_job(MAIL, config={"inference_url": server.url, "variant": "public"}, expect_exit=True)
    assert out["success"] is False
    assert "Required models unavailable for variant 'public'" in out["errorMessage"]


def test_analyzer_rejects_an_archive_without_headers(run_job):
    out = run_job({"mail.txt": "body only"}, expect_exit=True)
    assert out["success"] is False
    assert "missing the expected" in out["errorMessage"]
