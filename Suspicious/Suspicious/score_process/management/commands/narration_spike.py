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
