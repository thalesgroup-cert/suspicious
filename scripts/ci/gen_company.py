"""Generate a randomized fake-company identity and write the config files
the deployment stack reads. Mutates the existing real config files so the
schema never drifts. With --seed the output is deterministic (debugging)."""
from __future__ import annotations
import argparse, json, pathlib, random, string, secrets


def _rand(r: random.Random, n: int) -> str:
    return "".join(r.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def generate(seed: int | None, repo_root: pathlib.Path) -> dict:
    r = random.Random(seed)
    tag = _rand(r, 6)
    company = f"acme-{tag}"
    domain = f"{company}.example"
    # secrets: deterministic under seed, strong otherwise
    def tok(n):
        return _rand(r, n) if seed is not None else secrets.token_hex(n // 2)
    rt = {
        "company": company,
        "domain": domain,
        "admin_user": "admin",
        "admin_pass": tok(20),
        "secret_key": tok(50),
        "minio_access": f"minio{tag}",
        "minio_secret": tok(32),
        "webhook_secret": tok(48),
        "svc_prefix": f"sus-{tag}-",
        "project_name": f"sus{tag}",
        "feeder_bucket": "suspicious-feeder",
        "smtp_user": f"suspicious@{domain}",
        "ports": {"smtp": 3025, "imap": 3143, "s3": 9000},
    }

    sp = repo_root / "Suspicious/settings.json"
    settings = json.loads(sp.read_text())
    settings.setdefault("app", {})["secret_key"] = rt["secret_key"]
    s3 = settings.setdefault("storage", {}).setdefault("s3", {})
    s3["access_key"] = rt["minio_access"]; s3["secret_key"] = rt["minio_secret"]
    s3["feeder_bucket"] = rt["feeder_bucket"]
    settings["storage"]["backend"] = "local"
    cx = settings.setdefault("integrations", {}).setdefault("cortex", {})
    cx["url"] = "http://stub-cortex:9001"; cx["webhook_secret"] = rt["webhook_secret"]
    settings.setdefault("branding", {})["company_name"] = company
    sp.write_text(json.dumps(settings, indent=2))

    fp = repo_root / "email-feeder/config.json"
    feeder = json.loads(fp.read_text())
    fs3 = feeder.setdefault("s3", {})
    fs3["access_key"] = rt["minio_access"]; fs3["secret_key"] = rt["minio_secret"]
    fs3["feeder_bucket"] = rt["feeder_bucket"]
    fp.write_text(json.dumps(feeder, indent=2))

    ep = repo_root / "deployment/.env"
    env_lines = [l for l in ep.read_text().splitlines() if not l.startswith((
        "DOMAIN=", "SVC_PREFIX=", "COMPOSE_PROJECT_NAME=", "WEBHOOK_SECRET=",
        "MINIO_ACCESS_KEY=", "MINIO_SECRET_KEY="))]
    env_lines += [
        f"DOMAIN={domain}", f"SVC_PREFIX={rt['svc_prefix']}",
        f"COMPOSE_PROJECT_NAME={rt['project_name']}",
        f"WEBHOOK_SECRET={rt['webhook_secret']}",
        f"MINIO_ACCESS_KEY={rt['minio_access']}", f"MINIO_SECRET_KEY={rt['minio_secret']}",
    ]
    ep.write_text("\n".join(env_lines) + "\n")

    (repo_root / "scripts/ci/.runtime.json").write_text(json.dumps(rt, indent=2))
    return rt


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--repo-root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[2])
    a = ap.parse_args()
    rt = generate(a.seed, a.repo_root)
    print(json.dumps(rt, indent=2))


if __name__ == "__main__":
    main()
