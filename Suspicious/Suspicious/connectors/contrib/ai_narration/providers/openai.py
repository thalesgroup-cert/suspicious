"""OpenAI provider -- plain HTTP, no SDK."""
import requests


def generate(prompt: str, config: dict) -> str:
    api_key = config["openai_api_key"]
    model = config.get("openai_model") or "gpt-4o-mini"
    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"model": model, "messages": [{"role": "user", "content": prompt}]},
        timeout=120,
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]
