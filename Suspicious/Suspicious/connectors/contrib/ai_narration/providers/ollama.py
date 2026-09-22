"""Local Ollama provider -- plain HTTP, no SDK. Mirrors
score_process/management/commands/narration_spike.py's own Ollama call."""
import requests


def generate(prompt: str, config: dict) -> str:
    url = config.get("ollama_url") or "http://localhost:11434"
    model = config.get("ollama_model") or "qwen2.5:7b-instruct"
    response = requests.post(
        f"{url}/api/generate",
        json={
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {"num_ctx": 8192},
        },
        # Must stay under Celery's task_soft_time_limit=540s (suspicious/celery.py) --
        # this call now runs inside connectors.tasks.deliver_event, so a value at or
        # above 540 would let the soft limit fire first and this timeout never trigger.
        timeout=300,
    )
    response.raise_for_status()
    return response.json().get("response", "")
