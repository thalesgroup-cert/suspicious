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
