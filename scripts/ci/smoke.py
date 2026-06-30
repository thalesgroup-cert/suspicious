"""Drive one email through the running stack and assert every hop.
Run after bootstrap.sh has the stack healthy. Exits non-zero with the
offending state printed on the first failed hop."""
from __future__ import annotations
import email.message, json, os, pathlib, smtplib, subprocess, sys, time, uuid

RT = json.loads((pathlib.Path(__file__).parent / ".runtime.json").read_text())
COMPOSE = os.environ.get("COMPOSE", "").split()
if not COMPOSE:
    sys.exit("COMPOSE env var is required (set by bootstrap.sh)")


def _dj(code: str) -> str:
    """Run a Django snippet in the suspicious container; return combined output."""
    out = subprocess.run(
        COMPOSE + ["exec", "-T", "suspicious", "python", "manage.py", "shell", "-c", code],
        capture_output=True, text=True, timeout=120,
    )
    return (out.stdout or "") + (out.stderr or "")


def inject_email() -> str:
    tag = uuid.uuid4().hex[:6]
    inner = email.message.EmailMessage()
    inner["From"] = "attacker@evil.test"
    inner["To"] = f"victim@{RT['domain']}"
    inner["Subject"] = "verify your account"
    inner.set_content("http://phish.evil.test/login verify now")
    w = email.message.EmailMessage()
    w["From"] = f"reporter@{RT['domain']}"
    w["To"] = RT["smtp_user"]
    w["Subject"] = f"Fwd: smoke {tag}"
    w.set_content("Forwarding suspicious email.")
    w.add_attachment(inner.as_bytes(), maintype="message", subtype="rfc822", filename="s.eml")
    with smtplib.SMTP("127.0.0.1", RT["ports"]["smtp"]) as s:
        s.send_message(w)
    return tag


def _poll(fn, timeout=240, every=6, what=""):
    end = time.time() + timeout
    last = ""
    while time.time() < end:
        ok, last = fn()
        if ok:
            return last
        time.sleep(every)
    sys.exit(f"TIMEOUT waiting for {what}; last state:\n{last}")


def _check_bucket():
    code = (
        "from common.clients import get_s3_client\n"
        f"c=get_s3_client();b='{RT['feeder_bucket']}'\n"
        "ks=[o.object_name for o in c.list_objects(b,recursive=True)] if c.bucket_exists(b) else []\n"
        "import json;print('OBJS',json.dumps([k for k in ks if k.endswith('email.json')]))"
    )
    out = _dj(code)
    return ("email.json" in out, out)


def _check_case():
    code = (
        "from case_handler.models import Case\n"
        "c=Case.objects.order_by('-id').first()\n"
        "print('CASE', c.id if c else 'none')"
    )
    out = _dj(code)
    for line in out.splitlines():
        if line.startswith("CASE ") and line.split()[1].isdigit():
            return True, line.split()[1]
    return False, out


def _check_finalised(case_id):
    code = (
        "from case_handler.models import Case\n"
        "from cortex_job.models import CaseAnalyzerJob as J, Analyzer\n"
        f"c=Case.objects.get(id={case_id})\n"
        f"jobs=list(J.objects.filter(case_id={case_id}).values_list('analyzer__name','status'))\n"
        f"p=J.objects.filter(case_id={case_id},status__in=J.PENDING_STATUSES).count()\n"
        "print('STATE',c.status,c.results,'pending',p,'jobs',jobs,'analyzers_registered',Analyzer.objects.count())"
    )
    out = _dj(code)
    return ("STATE Done" in out and "pending 0" in out, out)


def _check_preview(case_id):
    code = (
        "from rest_framework.test import APIRequestFactory, force_authenticate\n"
        "from django.contrib.auth import get_user_model\n"
        "from api.views.mail_preview import MailPreviewView\n"
        f"u=get_user_model().objects.get(username='{RT['admin_user']}')\n"
        "rf=APIRequestFactory(); req=rf.get('/x'); force_authenticate(req,user=u)\n"
        f"r=MailPreviewView.as_view()(req,case_id={case_id})\n"
        "print('PREVIEW',r.status_code,r.get('Content-Type'))"
    )
    out = _dj(code)
    return ("PREVIEW 200 image/png" in out, out)


def main() -> None:
    print("1) inject email"); inject_email()
    print("2) feeder -> S3 prefix contract (email.json present)")
    _poll(_check_bucket, what="submission email.json in feeder bucket")
    print("3) backend Case created")
    case_id = _poll(_check_case, what="Case row")
    print(f"4) case {case_id}: ledger synced + finalised (stub webhooks)")
    _poll(lambda: _check_finalised(case_id), what="case Done + ledger pending 0")
    print("5) mail preview 200")
    _poll(lambda: _check_preview(case_id), what="preview 200 image/png")
    print(f"SMOKE OK (case {case_id})")


if __name__ == "__main__":
    main()
