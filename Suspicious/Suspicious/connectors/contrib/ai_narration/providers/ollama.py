"""Local Ollama provider -- plain HTTP, no SDK. Mirrors
score_process/management/commands/narration_spike.py's own Ollama call."""
import requests


def generate(prompt: str, config: dict) -> str:
    url = config.get("ollama_url", "http://localhost:11434")
    model = config.get("ollama_model", "qwen2.5:7b-instruct")
    response = requests.post(
        f"{url}/api/generate",
        json={"model": model, "prompt": prompt, "stream": False},
        timeout=600,
    )
    response.raise_for_status()
    return response.json().get("response", "")
