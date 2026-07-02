import json, importlib.util, pathlib, tempfile, shutil
ROOT = pathlib.Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("gen_company", ROOT / "scripts/ci/gen_company.py")
gen_company = importlib.util.module_from_spec(spec); spec.loader.exec_module(gen_company)

def _fixture_repo(tmp):
    # minimal real-shaped config files the generator mutates
    (tmp / "Suspicious").mkdir(parents=True)
    (tmp / "email-feeder").mkdir(parents=True)
    (tmp / "deployment").mkdir(parents=True)
    (tmp / "scripts/ci").mkdir(parents=True)
    (tmp / "Suspicious/settings.json").write_text(json.dumps({
        "app": {"secret_key": "x"},
        "storage": {"backend": "local", "s3": {"access_key": "a", "secret_key": "b", "feeder_bucket": "suspicious-feeder"}},
        "integrations": {"cortex": {"url": "http://cortex:9001", "api_key": "k", "webhook_secret": "w", "analyzers": {}}},
        "email": {"host": "greenmail"},
        "branding": {"company_name": "old"},
    }))
    (tmp / "email-feeder/config.json").write_text(json.dumps({
        "mail-connectors": {"imap": {"imap-dev": {"login": "suspicious", "password": "p", "host": "greenmail"}}},
        "s3": {"access_key": "a", "secret_key": "b", "feeder_bucket": "suspicious-feeder"},
        "mail": {"server": "greenmail"},
    }))
    (tmp / "deployment/.env").write_text("DOMAIN=old.example\n")

def test_seed_is_deterministic():
    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d); _fixture_repo(root)
        a = gen_company.generate(seed=42, repo_root=root)
        # second call reads the already-mutated files; same seed -> same output
        b = gen_company.generate(seed=42, repo_root=root)
        assert a == b
        assert a["domain"].endswith(".example")
        assert a["svc_prefix"] and a["project_name"]

def test_writes_consistent_secrets_across_files():
    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d); _fixture_repo(root)
        rt = gen_company.generate(seed=1, repo_root=root)
        settings = json.loads((root / "Suspicious/settings.json").read_text())
        feeder = json.loads((root / "email-feeder/config.json").read_text())
        runtime = json.loads((root / "scripts/ci/.runtime.json").read_text())
        # webhook secret identical in settings + runtime
        assert settings["integrations"]["cortex"]["webhook_secret"] == rt["webhook_secret"]
        # minio creds shared between backend + feeder
        assert settings["storage"]["s3"]["access_key"] == feeder["s3"]["access_key"]
        assert runtime == rt
        # cortex points at the stub service name
        assert settings["integrations"]["cortex"]["url"] == "http://stub-cortex:9001"
