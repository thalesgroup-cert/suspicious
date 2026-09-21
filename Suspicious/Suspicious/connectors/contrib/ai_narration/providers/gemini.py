"""Google Gemini provider -- plain HTTP, no SDK."""
import requests


def generate(prompt: str, config: dict) -> str:
    api_key = config["gemini_api_key"]
    model = config.get("gemini_model", "gemini-2.5-flash")
    response = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        headers={"x-goog-api-key": api_key},
        json={"contents": [{"parts": [{"text": prompt}]}]},
        timeout=120,
    )
    response.raise_for_status()
    return response.json()["candidates"][0]["content"]["parts"][0]["text"]
