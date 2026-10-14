"""Operator-declared OpenAI-compatible Chat Completions endpoint (vLLM, an
internal gateway, a vendor-hosted compatible API such as GLM) -- plain HTTP,
no SDK. The base URL carries the version prefix (``.../v1``,
``.../api/paas/v4``); this module appends ``/chat/completions``. It has no
default URL and no default model on purpose: see
docs/specs/2026-10-14-ai-narration-openai-compatible-design.md."""
import requests


def generate(prompt: str, config: dict) -> str:
    base = (config.get("openai_compatible_base_url") or "").strip().rstrip("/")
    if not base:
        raise ValueError("openai_compatible_base_url is not set")
    if not base.startswith(("http://", "https://")):
        raise ValueError("openai_compatible_base_url must be http(s)")
    model = config.get("openai_compatible_model") or ""
    if not model:
        raise ValueError("openai_compatible_model is not set")
    headers = {}
    if config.get("openai_compatible_api_key"):
        headers["Authorization"] = f"Bearer {config['openai_compatible_api_key']}"
    response = requests.post(
        f"{base}/chat/completions",
        headers=headers,
        json={"model": model, "messages": [{"role": "user", "content": prompt}]},
        # Must stay under Celery's task_soft_time_limit=540s (see ollama.py).
        timeout=120,
    )
    response.raise_for_status()
    content = response.json()["choices"][0]["message"]["content"]
    if not content:
        raise ValueError("openai_compatible endpoint returned empty content")
    return content
