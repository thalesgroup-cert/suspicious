import importlib.util, pathlib, os
os.environ.setdefault("WEBHOOK_SECRET", "sek"); os.environ.setdefault("BACKEND_URL", "http://backend:9020")
os.environ.setdefault("ANALYZERS_JSON", '[{"id":"a1","name":"FileInfo_8_0","dataType":"file","verdict":"info"}]')
ROOT = pathlib.Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("stub_app", ROOT / "scripts/ci/stub_cortex/app.py")
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)

def test_search_lists_configured_analyzers():
    status, body = mod.route("POST", "/api/analyzer/_search", {"query": {}})
    assert status == 200
    names = [a["name"] for a in body]
    assert "FileInfo_8_0" in names
    assert all({"id", "name", "dataTypeList"} <= set(a) for a in body)

def test_run_creates_job_and_webhooks(monkeypatch):
    posted = {}
    monkeypatch.setattr(mod, "post_webhook", lambda jid: posted.__setitem__("jid", jid))
    monkeypatch.setattr(mod, "WEBHOOK_DELAY", 0)
    status, body = mod.route("POST", "/api/analyzer/a1/run", {"dataType": "file"})
    assert status == 200
    jid = body["id"]
    mod.deliver_pending()
    assert posted["jid"] == jid

def test_webhook_request_shape(monkeypatch):
    captured = {}
    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        status = 202
    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["data"] = req.data
        captured["auth"] = req.get_header("Authorization")
        return FakeResp()
    monkeypatch.setattr(mod.urllib.request, "urlopen", fake_urlopen)
    mod.post_webhook("JID123")
    assert captured["url"].endswith("/api/cortex/webhook/")
    assert captured["data"] == b'{"jobId": "JID123"}'
    assert captured["auth"] == "Bearer sek"

def test_job_and_report_shapes():
    _, run = mod.route("POST", "/api/analyzer/a1/run", {"dataType": "file"})
    jid = run["id"]
    _, job = mod.route("GET", f"/api/job/{jid}", {})
    assert job["status"] == "Success"
    assert {"id", "status", "dataType", "analyzerName"} <= set(job)
    _, rep = mod.route("GET", f"/api/job/{jid}/report", {})
    assert rep["status"] == "Success"
    assert "taxonomies" in rep["report"]["summary"]
