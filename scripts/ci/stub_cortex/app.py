"""Minimal Cortex API stub: deterministic canned reports + Bearer webhook.
Pure stdlib (http.server + urllib). Implements only the cortex4py surface
the backend calls. Logic in route() so it is testable without a socket."""
from __future__ import annotations
import json, os, re, threading, time, uuid
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BACKEND_URL = os.environ.get("BACKEND_URL", "http://suspicious:9020")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
WEBHOOK_DELAY = float(os.environ.get("WEBHOOK_DELAY", "0.2"))
ANALYZERS = json.loads(os.environ.get("ANALYZERS_JSON", "[]"))
PORT = int(os.environ.get("PORT", "9001"))

_jobs: dict[str, dict] = {}
_pending: list[str] = []
_JOB_RE = re.compile(r"^/api/job/([^/]+)(/report)?$")
_RUN_RE = re.compile(r"^/api/analyzer/([^/]+)/run$")


def _analyzer_entry(a: dict) -> dict:
    return {
        "id": a["id"], "name": a["name"], "version": a.get("version", "1.0"),
        "dataTypeList": [a["dataType"]], "workerDefinitionId": a["name"],
        "dockerImage": a.get("image", "stub"), "type": "analyzer",
    }


def make_report(analyzer_name: str, verdict: str) -> dict:
    return {
        "summary": {"taxonomies": [
            {"level": verdict, "namespace": analyzer_name.split("_")[0],
             "predicate": "verdict", "value": verdict}
        ]},
        "full": {"results": {"verdict": verdict}},
    }


def post_webhook(jid: str) -> None:
    data = json.dumps({"jobId": jid}).encode()
    req = urllib.request.Request(
        f"{BACKEND_URL}/api/cortex/webhook/", data=data, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {WEBHOOK_SECRET}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8):
            pass
    except Exception:
        pass  # ponytail: stub; delivery failures surface in the smoke assertions


def deliver_pending() -> None:
    while _pending:
        post_webhook(_pending.pop(0))


def route(method: str, path: str, body: dict):
    """Pure request handler: (method, path, parsed-body) -> (status, json-able)."""
    if method == "POST" and path == "/api/analyzer/_search":
        return 200, [_analyzer_entry(a) for a in ANALYZERS]
    m = _RUN_RE.match(path)
    if method == "POST" and m:
        aid = m.group(1)
        spec = (next((a for a in ANALYZERS if a["id"] == aid), None)
                or next((a for a in ANALYZERS if a["name"] == aid), None)
                or ANALYZERS[0])
        jid = uuid.uuid4().hex
        _jobs[jid] = {
            "id": jid, "status": "Success",
            "dataType": body.get("dataType", spec["dataType"]),
            "analyzerName": spec["name"], "workerName": spec["name"],
            "date": int(time.time() * 1000), "_verdict": spec.get("verdict", "info"),
        }
        _pending.append(jid)
        if WEBHOOK_DELAY:
            threading.Timer(WEBHOOK_DELAY, deliver_pending).start()
        return 200, {k: v for k, v in _jobs[jid].items() if not k.startswith("_")}
    m = _JOB_RE.match(path)
    if method == "GET" and m:
        jid, is_report = m.group(1), m.group(2)
        j = _jobs.get(jid)
        if not j:
            return 404, {"error": "not found"}
        public = {k: v for k, v in j.items() if not k.startswith("_")}
        if is_report:
            return 200, {**public, "report": make_report(j["analyzerName"], j["_verdict"])}
        return 200, public
    return 404, {"error": "not found"}


class Handler(BaseHTTPRequestHandler):
    def _do(self, method):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {}
        status, payload = route(method, self.path, body)
        out = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_GET(self): self._do("GET")
    def do_POST(self): self._do("POST")
    def log_message(self, *a): pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
