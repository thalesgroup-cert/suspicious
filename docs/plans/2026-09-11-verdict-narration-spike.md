# Verdict Narration Spike Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the deterministic verdict-lock validator plus a one-off spike command that prompts a local Ollama model with synthetic case fixtures, so an analyst can judge whether prompting alone is good enough to make training unnecessary.

**Architecture:** Two small pure modules (`verdict_lock.py`, `prompt.py`) with no ORM dependency, six hand-written JSON fixtures, and a Django management command that wires them together against a locally-running Ollama server. Nothing here touches the live scoring pipeline.

**Tech Stack:** Python, Django management commands, `requests` (already a dependency), Ollama (external, dev-only service).

**Spec:** `docs/specs/2026-09-11-verdict-narration-spike-design.md`

## Global Constraints

- No new Python dependencies — `requests` is already in `requirements.txt`; use only it and the stdlib.
- `verdict_lock.py` and `prompt.py` must not import any Django models or do any ORM/DB access — pure functions only, same discipline as `score_process/scoring/observable_engine.py`.
- The exact band vocabulary is `"Safe"`, `"Suspicious"`, `"Dangerous"`, `"Inconclusive"` (from `score_process/scoring/observable_engine.py`'s `_BAND_ORDER`) — no other band strings are valid.
- `narration_spike` must never be wired into `apply.py`, `reports.py`, or any live case-finalization path — it is a standalone command operating only on fixture files.
- Fixtures contain synthetic data only — no real case content, no real domains/IPs/hashes that resolve to anything live. Any IP address in a fixture must come from an RFC 5737 documentation range (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) — never a real allocated IP, even one already known-malicious, since those still resolve to real infrastructure.

---

### Task 1: Verdict lock module

**Files:**
- Create: `Suspicious/Suspicious/score_process/scoring/narration/__init__.py`
- Create: `Suspicious/Suspicious/score_process/scoring/narration/verdict_lock.py`
- Test: `Suspicious/Suspicious/score_process/tests/test_narration_verdict_lock.py`

**Interfaces:**
- Produces: `ValidationResult(passed: bool, reasons: list[str])`, `render_fixed_facts(verdict: dict) -> str`, `validate_narration(text: str, verdict: dict) -> ValidationResult`. `verdict` is a plain dict with keys `"band"` (str), `"score"` (float), `"confidence"` (float), `"rule"` (str).

- [ ] **Step 1: Write the failing tests**

```python
# Suspicious/Suspicious/score_process/tests/test_narration_verdict_lock.py
from django.test import SimpleTestCase

from score_process.scoring.narration.verdict_lock import (
    render_fixed_facts,
    validate_narration,
)


class RenderFixedFactsTest(SimpleTestCase):
    def test_includes_all_facts_verbatim(self):
        verdict = {"band": "Dangerous", "score": 9.5, "confidence": 85, "rule": "malicious-count"}
        text = render_fixed_facts(verdict)
        self.assertIn("Dangerous", text)
        self.assertIn("9.5", text)
        self.assertIn("85", text)
        self.assertIn("malicious-count", text)


class ValidateNarrationTest(SimpleTestCase):
    def test_matching_band_passes(self):
        verdict = {"band": "Dangerous", "score": 9.5, "confidence": 85, "rule": "malicious-count"}
        text = "This case is Dangerous. Multiple analyzers flagged the URL as malicious."
        result = validate_narration(text, verdict)
        self.assertTrue(result.passed)
        self.assertEqual(result.reasons, [])

    def test_contradicting_band_fails(self):
        verdict = {"band": "Dangerous", "score": 9.5, "confidence": 85, "rule": "malicious-count"}
        text = "Overall, this case appears Safe and no action is required."
        result = validate_narration(text, verdict)
        self.assertFalse(result.passed)
        self.assertTrue(any("Safe" in r for r in result.reasons))

    def test_no_verdict_language_passes(self):
        verdict = {"band": "Suspicious", "score": 5.0, "confidence": 60, "rule": "weighted-malicious-share"}
        text = "VirusTotal reported 3 of 70 engines flagged this domain. GTI found no prior reputation data."
        result = validate_narration(text, verdict)
        self.assertTrue(result.passed)

    def test_fabricated_confidence_fails(self):
        verdict = {"band": "Dangerous", "score": 9.5, "confidence": 90, "rule": "malicious-count"}
        text = "We are Dangerous with 40% confidence based on the available evidence."
        result = validate_narration(text, verdict)
        self.assertFalse(result.passed)
        self.assertTrue(any("40" in r for r in result.reasons))

    def test_close_confidence_within_tolerance_passes(self):
        verdict = {"band": "Dangerous", "score": 9.5, "confidence": 90, "rule": "malicious-count"}
        text = "This is Dangerous with roughly 88% confidence."
        result = validate_narration(text, verdict)
        self.assertTrue(result.passed)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python manage.py test score_process.tests.test_narration_verdict_lock -v 2`
Expected: FAIL / errors — `score_process.scoring.narration` module does not exist yet.

- [ ] **Step 3: Write the implementation**

```python
# Suspicious/Suspicious/score_process/scoring/narration/__init__.py
```
(empty file)

```python
# Suspicious/Suspicious/score_process/scoring/narration/verdict_lock.py
"""Deterministic verdict-lock: renders a case's verdict as fixed, literal
facts for a narration prompt, and validates generated text never asserts a
different band/confidence than the facts it was given.

Pure. No ORM. Never imports Django models — see observable_engine.py for
the same discipline on the scoring side.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_BAND_WORDS = ("Safe", "Suspicious", "Dangerous", "Inconclusive")
_CONFIDENCE_TOLERANCE = 10  # percentage points


@dataclass(frozen=True)
class ValidationResult:
    passed: bool
    reasons: list = field(default_factory=list)


def render_fixed_facts(verdict: dict) -> str:
    """Literal, non-model-authored block of the case's verdict facts."""
    return (
        "FIXED CASE FACTS (do not alter, restate exactly as given):\n"
        f"- Verdict band: {verdict['band']}\n"
        f"- Score: {verdict['score']}\n"
        f"- Confidence: {verdict['confidence']}\n"
        f"- Decisive rule: {verdict.get('rule', 'unknown')}\n"
    )


def validate_narration(text: str, verdict: dict) -> ValidationResult:
    """Fails if `text` asserts a band other than verdict['band'], or a
    confidence percentage that differs from verdict['confidence'] by more
    than _CONFIDENCE_TOLERANCE points. Passes on silence — omitting verdict
    language entirely is not a contradiction."""
    reasons = []
    band = verdict["band"]

    for word in _BAND_WORDS:
        if word == band:
            continue
        if re.search(rf"\b{re.escape(word)}\b", text, re.IGNORECASE):
            reasons.append(f"narration mentions contradicting band '{word}' (verdict is '{band}')")

    confidence = verdict.get("confidence")
    if confidence is not None:
        for match in re.finditer(r"(\d{1,3})\s?%", text):
            pct = int(match.group(1))
            if abs(pct - round(float(confidence))) > _CONFIDENCE_TOLERANCE:
                reasons.append(
                    f"narration states {pct}% confidence, verdict confidence is {confidence}"
                )

    return ValidationResult(passed=not reasons, reasons=reasons)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python manage.py test score_process.tests.test_narration_verdict_lock -v 2`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/score_process/scoring/narration/ Suspicious/Suspicious/score_process/tests/test_narration_verdict_lock.py
git commit -m "feat(narration): add deterministic verdict-lock validator"
```

---

### Task 2: Prompt builder

**Files:**
- Create: `Suspicious/Suspicious/score_process/scoring/narration/prompt.py`
- Test: `Suspicious/Suspicious/score_process/tests/test_narration_prompt.py`

**Interfaces:**
- Consumes: `render_fixed_facts(verdict: dict) -> str` from Task 1 (`score_process.scoring.narration.verdict_lock`).
- Produces: `build_prompt(verdict: dict, analyzer_reports: list[dict]) -> str`. Each item in `analyzer_reports` is a dict with keys `"analyzer"` (str) and `"report_full"` (dict).

- [ ] **Step 1: Write the failing tests**

```python
# Suspicious/Suspicious/score_process/tests/test_narration_prompt.py
from django.test import SimpleTestCase

from score_process.scoring.narration.prompt import build_prompt


class BuildPromptTest(SimpleTestCase):
    def test_includes_fixed_facts_and_reports_and_instructions(self):
        verdict = {"band": "Suspicious", "score": 5.0, "confidence": 60, "rule": "weighted-malicious-share"}
        reports = [
            {"analyzer": "VirusTotal_v3", "report_full": {"positives": 3, "total": 70}},
            {"analyzer": "GTI", "report_full": {"reputation": "unknown"}},
        ]
        prompt = build_prompt(verdict, reports)

        self.assertIn("Suspicious", prompt)
        self.assertIn("VirusTotal_v3", prompt)
        self.assertIn("GTI", prompt)
        self.assertIn("positives", prompt)
        self.assertIn("do not restate them differently", prompt.lower())

    def test_empty_reports_still_produces_valid_prompt(self):
        verdict = {"band": "Safe", "score": 0.0, "confidence": 95, "rule": "no-malicious-sources"}
        prompt = build_prompt(verdict, [])
        self.assertIn("Safe", prompt)
        self.assertIn("ANALYZER REPORTS", prompt)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python manage.py test score_process.tests.test_narration_prompt -v 2`
Expected: FAIL — `score_process.scoring.narration.prompt` does not exist yet.

- [ ] **Step 3: Write the implementation**

```python
# Suspicious/Suspicious/score_process/scoring/narration/prompt.py
"""Assembles the full narration prompt: fixed verdict facts + full analyzer
reports + generation instructions. Pure — no ORM, no Django models."""
from __future__ import annotations

import json

from score_process.scoring.narration.verdict_lock import render_fixed_facts

_INSTRUCTIONS = (
    "You are writing a plain-language incident report for a non-technical "
    "reader. Use the fixed case facts above exactly as given — do not "
    "restate them differently, soften them, or draw your own conclusion "
    "about whether this case is safe or dangerous. Explain what the "
    "analyzer findings below mean in plain language, and how they support "
    "the given verdict."
)


def build_prompt(verdict: dict, analyzer_reports: list) -> str:
    facts = render_fixed_facts(verdict)

    if analyzer_reports:
        reports_block = "\n\n".join(
            f"### {report.get('analyzer', 'unknown analyzer')}\n"
            f"{json.dumps(report.get('report_full', {}), indent=2)}"
            for report in analyzer_reports
        )
    else:
        reports_block = "(no analyzer reports available)"

    return (
        f"{facts}\n"
        f"ANALYZER REPORTS:\n{reports_block}\n\n"
        f"INSTRUCTIONS:\n{_INSTRUCTIONS}\n"
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python manage.py test score_process.tests.test_narration_prompt -v 2`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/score_process/scoring/narration/prompt.py Suspicious/Suspicious/score_process/tests/test_narration_prompt.py
git commit -m "feat(narration): add prompt builder for verdict narration spike"
```

---

### Task 3: Synthetic case fixtures

**Files:**
- Create: `Suspicious/Suspicious/score_process/tests/fixtures/narration/mail_safe.json`
- Create: `Suspicious/Suspicious/score_process/tests/fixtures/narration/mail_suspicious.json`
- Create: `Suspicious/Suspicious/score_process/tests/fixtures/narration/mail_dangerous.json`
- Create: `Suspicious/Suspicious/score_process/tests/fixtures/narration/ioc_safe.json`
- Create: `Suspicious/Suspicious/score_process/tests/fixtures/narration/ioc_suspicious_multi.json`
- Create: `Suspicious/Suspicious/score_process/tests/fixtures/narration/ioc_dangerous_single.json`
- Test: `Suspicious/Suspicious/score_process/tests/test_narration_fixtures.py`

**Interfaces:**
- Produces: fixture files, each a JSON object `{"verdict": {"band": str, "score": float, "confidence": float, "rule": str}, "analyzer_reports": [{"analyzer": str, "report_full": dict}, ...]}`, matching what `build_prompt` (Task 2) and `narration_spike` (Task 4) expect.

- [ ] **Step 1: Write the failing test**

```python
# Suspicious/Suspicious/score_process/tests/test_narration_fixtures.py
import json
from pathlib import Path

from django.test import SimpleTestCase

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "narration"
FIXTURE_NAMES = [
    "mail_safe.json",
    "mail_suspicious.json",
    "mail_dangerous.json",
    "ioc_safe.json",
    "ioc_suspicious_multi.json",
    "ioc_dangerous_single.json",
]


class FixtureShapeTest(SimpleTestCase):
    def test_all_fixtures_exist_and_have_required_shape(self):
        for name in FIXTURE_NAMES:
            path = FIXTURES_DIR / name
            with self.subTest(fixture=name):
                self.assertTrue(path.exists(), f"missing fixture {path}")
                data = json.loads(path.read_text())
                self.assertIn("verdict", data)
                verdict = data["verdict"]
                for key in ("band", "score", "confidence", "rule"):
                    self.assertIn(key, verdict)
                self.assertIn(verdict["band"], ("Safe", "Suspicious", "Dangerous", "Inconclusive"))
                self.assertIn("analyzer_reports", data)
                for report in data["analyzer_reports"]:
                    self.assertIn("analyzer", report)
                    self.assertIn("report_full", report)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python manage.py test score_process.tests.test_narration_fixtures -v 2`
Expected: FAIL — fixture files don't exist yet.

- [ ] **Step 3: Write the fixtures**

```json
// docs/research/fixtures/mail_safe.json
{
  "verdict": {"band": "Safe", "score": 0.5, "confidence": 92, "rule": "no-malicious-sources"},
  "analyzer_reports": [
    {"analyzer": "AI_Mail_Analyzer", "report_full": {"classification": "legitimate", "confidence": 0.92, "language": "en"}},
    {"analyzer": "SPF_DKIM_DMARC", "report_full": {"spf": "pass", "dkim": "pass", "dmarc": "pass"}}
  ]
}
```

```json
// docs/research/fixtures/mail_suspicious.json
{
  "verdict": {"band": "Suspicious", "score": 5.5, "confidence": 58, "rule": "weighted-malicious-share"},
  "analyzer_reports": [
    {"analyzer": "AI_Mail_Analyzer", "report_full": {"classification": "possible_phishing", "confidence": 0.61, "language": "fr"}},
    {"analyzer": "SPF_DKIM_DMARC", "report_full": {"spf": "softfail", "dkim": "none", "dmarc": "none"}},
    {"analyzer": "URLhaus", "report_full": {"url": "hxxp://update-billing-portal.example-cdn.net/login", "listed": false}}
  ]
}
```

```json
// docs/research/fixtures/mail_dangerous.json
{
  "verdict": {"band": "Dangerous", "score": 9.2, "confidence": 88, "rule": "embedded-ioc-escalation"},
  "analyzer_reports": [
    {"analyzer": "AI_Mail_Analyzer", "report_full": {"classification": "phishing", "confidence": 0.94, "language": "en"}},
    {"analyzer": "SPF_DKIM_DMARC", "report_full": {"spf": "fail", "dkim": "fail", "dmarc": "fail"}},
    {"analyzer": "VirusTotal_v3", "report_full": {"url": "hxxp://secure-hr-portal-update.example-fake.com/reset", "positives": 41, "total": 70}}
  ]
}
```

```json
// docs/research/fixtures/ioc_safe.json
{
  "verdict": {"band": "Safe", "score": 0.0, "confidence": 90, "rule": "no-malicious-sources"},
  "analyzer_reports": [
    {"analyzer": "VirusTotal_v3", "report_full": {"observable": "docs.example-cloud.com", "positives": 0, "total": 72}},
    {"analyzer": "GTI", "report_full": {"reputation": "clean", "categories": ["cloud storage"]}}
  ]
}
```

```json
// docs/research/fixtures/ioc_suspicious_multi.json
{
  "verdict": {"band": "Suspicious", "score": 4.8, "confidence": 55, "rule": "group-worst-of"},
  "analyzer_reports": [
    {"analyzer": "VirusTotal_v3", "report_full": {"observable": "203.0.113.42", "positives": 4, "total": 88}},
    {"analyzer": "VirusTotal_v3", "report_full": {"observable": "auth-verify-secure.example-net.org", "positives": 6, "total": 72}},
    {"analyzer": "GTI", "report_full": {"reputation": "suspicious", "first_seen": "2026-08-30"}},
    {"analyzer": "MISP", "report_full": {"matches": 0}}
  ]
}
```

```json
// docs/research/fixtures/ioc_dangerous_single.json
{
  "verdict": {"band": "Dangerous", "score": 9.7, "confidence": 91, "rule": "malicious-count"},
  "analyzer_reports": [
    {"analyzer": "VirusTotal_v3", "report_full": {"observable": "198.51.100.77", "positives": 57, "total": 90}},
    {"analyzer": "GTI", "report_full": {"reputation": "malicious", "threat_labels": ["c2", "trojan"]}},
    {"analyzer": "MISP", "report_full": {"matches": 3, "events": ["APT-fake-campaign-2026-08"]}}
  ]
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python manage.py test score_process.tests.test_narration_fixtures -v 2`
Expected: PASS (1 test, 6 subtests)

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/score_process/tests/fixtures/narration/ Suspicious/Suspicious/score_process/tests/test_narration_fixtures.py
git commit -m "test(narration): add synthetic case fixtures for the narration spike"
```

---

### Task 4: `narration_spike` management command

**Files:**
- Create: `Suspicious/Suspicious/score_process/management/commands/narration_spike.py`
- Test: `Suspicious/Suspicious/score_process/tests/test_narration_spike_command.py`

**Interfaces:**
- Consumes: `build_prompt(verdict, analyzer_reports)` (Task 2), `validate_narration(text, verdict)` (Task 1).
- Produces: a Django management command runnable as `python manage.py narration_spike <fixture_path> [--ollama-url URL] [--model NAME]`, which writes `<fixture_path>.result.txt`.

- [ ] **Step 1: Write the failing test**

```python
# Suspicious/Suspicious/score_process/tests/test_narration_spike_command.py
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from django.core.management import call_command
from django.test import SimpleTestCase


class NarrationSpikeCommandTest(SimpleTestCase):
    def _write_fixture(self, tmp_dir, band="Dangerous"):
        fixture = {
            "verdict": {"band": band, "score": 9.0, "confidence": 85, "rule": "malicious-count"},
            "analyzer_reports": [{"analyzer": "VirusTotal_v3", "report_full": {"positives": 50, "total": 70}}],
        }
        path = Path(tmp_dir) / "fixture.json"
        path.write_text(json.dumps(fixture))
        return path

    @patch("score_process.management.commands.narration_spike.requests.post")
    def test_writes_pass_result_when_narration_matches_verdict(self, mock_post):
        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {"response": "This case is Dangerous based on strong evidence."},
        )
        mock_post.return_value.raise_for_status = lambda: None

        with tempfile.TemporaryDirectory() as tmp_dir:
            fixture_path = self._write_fixture(tmp_dir)
            call_command("narration_spike", str(fixture_path))

            result_path = fixture_path.with_suffix(fixture_path.suffix + ".result.txt")
            self.assertTrue(result_path.exists())
            content = result_path.read_text()
            self.assertIn("STATUS: PASS", content)
            self.assertIn("This case is Dangerous", content)

    @patch("score_process.management.commands.narration_spike.requests.post")
    def test_writes_fail_result_when_narration_contradicts_verdict(self, mock_post):
        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {"response": "This case looks Safe, no action needed."},
        )
        mock_post.return_value.raise_for_status = lambda: None

        with tempfile.TemporaryDirectory() as tmp_dir:
            fixture_path = self._write_fixture(tmp_dir)
            call_command("narration_spike", str(fixture_path))

            result_path = fixture_path.with_suffix(fixture_path.suffix + ".result.txt")
            content = result_path.read_text()
            self.assertIn("STATUS: FAIL", content)
            self.assertIn("contradicting band 'Safe'", content)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python manage.py test score_process.tests.test_narration_spike_command -v 2`
Expected: FAIL — command `narration_spike` does not exist yet.

- [ ] **Step 3: Write the implementation**

```python
# Suspicious/Suspicious/score_process/management/commands/narration_spike.py
"""Spike command: prompt a local Ollama model with a synthetic case fixture
and validate the output against the fixed verdict. Never call this against
real case data — see docs/specs/2026-09-11-verdict-narration-spike-design.md.
"""
import json
from pathlib import Path

import requests
from django.core.management.base import BaseCommand, CommandError

from score_process.scoring.narration.prompt import build_prompt
from score_process.scoring.narration.verdict_lock import validate_narration


class Command(BaseCommand):
    help = "Prompt a local Ollama model with a synthetic case fixture; validate output against the fixed verdict."

    def add_arguments(self, parser):
        parser.add_argument("fixture_path", type=str)
        parser.add_argument("--ollama-url", default="http://localhost:11434")
        parser.add_argument("--model", default="qwen2.5:7b-instruct")

    def handle(self, *args, **options):
        fixture_path = Path(options["fixture_path"])
        try:
            fixture = json.loads(fixture_path.read_text())
            verdict = fixture["verdict"]
            analyzer_reports = fixture["analyzer_reports"]
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            raise CommandError(f"invalid fixture {fixture_path}: {exc}")

        prompt = build_prompt(verdict, analyzer_reports)

        try:
            response = requests.post(
                f"{options['ollama_url']}/api/generate",
                json={"model": options["model"], "prompt": prompt, "stream": False},
                timeout=120,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise CommandError(f"Ollama request failed: {exc}")

        narration = response.json().get("response", "")
        result = validate_narration(narration, verdict)

        result_path = fixture_path.with_suffix(fixture_path.suffix + ".result.txt")
        status = "PASS" if result.passed else "FAIL"
        lines = [f"STATUS: {status}"]
        if result.reasons:
            lines.append("REASONS:")
            lines.extend(f"  - {reason}" for reason in result.reasons)
        lines.append("")
        lines.append("NARRATION:")
        lines.append(narration)
        result_path.write_text("\n".join(lines))

        self.stdout.write(f"{status}: wrote {result_path}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python manage.py test score_process.tests.test_narration_spike_command -v 2`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add Suspicious/Suspicious/score_process/management/commands/narration_spike.py Suspicious/Suspicious/score_process/tests/test_narration_spike_command.py
git commit -m "feat(narration): add narration_spike management command"
```

---

### Task 5: Ollama dev environment + runbook

**Files:**
- Modify: `deployment/docker-compose.dev-extras.yml`
- Create: `docs/research/2026-09-11-verdict-narration-spike-runbook.md`

**Interfaces:**
- Consumes: nothing from earlier tasks (documentation/infra only).
- Produces: an opt-in `ollama` service reachable at `http://localhost:11434` from the host, and a runbook a human follows to run the spike.

- [ ] **Step 1: Add the `ollama` service**

Add this service block to `deployment/docker-compose.dev-extras.yml`, inside the existing `services:` key, following the same style as the `greenmail`/`openldap` entries already there:

```yaml
  ollama:
    image: ollama/ollama:latest
    container_name: ${SVC_PREFIX:-}ollama
    restart: unless-stopped
    volumes:
      - ollama_models:/root/.ollama
    ports:
      - "127.0.0.1:11434:11434"
    networks:
      - suspicious_network
```

Add the named volume at the bottom of the file (create a `volumes:` top-level key if one doesn't already exist there):

```yaml
volumes:
  ollama_models:
```

- [ ] **Step 2: Write the runbook**

```markdown
<!-- docs/research/2026-09-11-verdict-narration-spike-runbook.md -->
# Verdict Narration Spike: Runbook

Companion to `docs/specs/2026-09-11-verdict-narration-spike-design.md`. Follow
this to actually run the spike and produce the analyst-reviewable results.

## 1. Start Ollama

```bash
docker compose -f deployment/docker-compose.yml -f deployment/docker-compose.dev-extras.yml up -d ollama
```

## 2. Pull the model (one-time, several GB download)

```bash
docker exec -it ollama ollama pull qwen2.5:7b-instruct
```

## 3. Run the spike against every fixture

Fixtures live at `Suspicious/Suspicious/score_process/tests/fixtures/narration/`
(inside the Django app tree, not under `docs/`, so they're always reachable
under a container mount — see Task 3's ledger ruling). There's no local
Python/Django environment in this repo's dev setup, so run each fixture
through the `suspicious` container, from `deployment/`:

```bash
cd deployment
for name in mail_safe mail_suspicious mail_dangerous ioc_safe ioc_suspicious_multi ioc_dangerous_single; do
  docker compose --env-file .env run --rm --no-deps \
    -v "$(cd .. && pwd)/Suspicious/Suspicious:/app" -w /app \
    suspicious python manage.py narration_spike \
    "score_process/tests/fixtures/narration/${name}.json" \
    --ollama-url http://ollama:11434
done
```

`--ollama-url http://ollama:11434` addresses the `ollama` service by its
Docker Compose service name over `suspicious_network` — `localhost` would
not resolve to the Ollama container from inside the `suspicious` container.

Each run writes `<fixture>.result.txt` next to the fixture it read — since
the container bind-mounts the same directory, the result files also appear
on the host at `Suspicious/Suspicious/score_process/tests/fixtures/narration/`.

## 4. Read the results

Open each `.result.txt` file. For every fixture, note:
- Did `verdict_lock` mark it PASS or FAIL? A FAIL means the model contradicted
  the given verdict in prose — that's a real finding regardless of narration
  quality, and worth its own follow-up regardless of the spike's overall
  outcome.
- For the PASS results: is the narration actually good? Would a
  non-technical reader understand what happened and why? Does it read as
  generic filler, or does it meaningfully use the analyzer report content?

## 5. Report back

The spike's deliverable is a judgment call, not a test suite: is prompting
alone (given this validator as a safety net) good enough to skip training?
Write that judgment down — one paragraph — as the answer to the question the
LLM Council posed. That answer decides whether
`docs/specs/2026-09-11-verdict-narration-spike-design.md`'s "Open Questions"
section becomes the next spec.
```

- [ ] **Step 3: Commit**

```bash
git add deployment/docker-compose.dev-extras.yml docs/research/2026-09-11-verdict-narration-spike-runbook.md
git commit -m "docs(narration): add Ollama dev service and spike runbook"
```
