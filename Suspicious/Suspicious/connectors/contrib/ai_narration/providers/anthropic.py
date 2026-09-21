"""Anthropic provider -- plain HTTP, no SDK."""
import requests

_API_VERSION = "2023-06-01"


def generate(prompt: str, config: dict) -> str:
    api_key = config["anthropic_api_key"]
    model = config.get("anthropic_model", "claude-haiku-4-5-20251001")
    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": _API_VERSION,
        },
        json={
            "model": model,
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=120,
    )
    response.raise_for_status()
    return response.json()["content"][0]["text"]
