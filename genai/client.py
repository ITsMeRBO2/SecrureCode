"""Client minimal pour l'API locale Ollama."""
from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class OllamaError(RuntimeError):
    """Erreur explicite de communication ou de réponse Ollama."""


class OllamaClient:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434",
        model: str = "qwen2.5-coder:7b",
        timeout: float = 120.0,
        num_predict: int = 4096,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.num_predict = num_predict

    def check_connection(self) -> tuple[bool, str]:
        """Vérifie rapidement si Ollama est joignable et si le modèle est présent."""
        urls = [self.base_url]
        if "localhost" in self.base_url:
            urls.append(self.base_url.replace("localhost", "127.0.0.1"))
        elif "127.0.0.1" in self.base_url:
            urls.append(self.base_url.replace("127.0.0.1", "localhost"))

        for url in urls:
            try:
                req = Request(f"{url}/api/tags", method="GET")
                with urlopen(req, timeout=3.0) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    models = [m.get("name") for m in data.get("models", [])]
                    model_base = self.model.split(":")[0]
                    model_found = any(m == self.model or m.startswith(model_base) for m in models)
                    if not model_found:
                        return False, (
                            f"Ollama répond sur {url} mais le modèle '{self.model}' n'est pas installé. "
                            f"Modèles présents : {', '.join(models) or 'aucun'}. "
                            f"Installez-le avec : ollama pull {self.model}"
                        )
                    self.base_url = url
                    return True, f"Connecté à Ollama ({self.model})"
            except Exception:
                continue

        return False, (
            "Ollama est inaccessible sur 127.0.0.1:11434. "
            "Assurez-vous qu'Ollama est démarré (ex: lancez 'ollama serve' dans un terminal "
            "ou démarrez l'application Ollama sous Windows)."
        )

    def generate(self, prompt: str) -> str:
        payload = json.dumps(
            {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {
                    "temperature": 0.1,
                    "repeat_penalty": 1.1,
                    "repeat_last_n": 128,
                    "num_predict": self.num_predict,
                },
            }
        ).encode("utf-8")

        urls_to_try = [self.base_url]
        if "localhost" in self.base_url:
            urls_to_try.append(self.base_url.replace("localhost", "127.0.0.1"))
        elif "127.0.0.1" in self.base_url:
            urls_to_try.append(self.base_url.replace("127.0.0.1", "localhost"))

        last_exc: Exception | None = None
        body = None

        for url in urls_to_try:
            request = Request(
                f"{url}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    body = json.loads(response.read().decode("utf-8"))
                    self.base_url = url
                    break
            except HTTPError as exc:
                detail = exc.read().decode("utf-8", errors="replace").strip()
                message = f"HTTP {exc.code}"
                if detail:
                    message += f" : {detail[:1000]}"
                raise OllamaError(f"Ollama a refusé la requête ({message}).") from exc
            except (URLError, TimeoutError, OSError) as exc:
                last_exc = exc
                continue

        if body is None:
            raise OllamaError(
                f"Ollama est inaccessible sur {self.base_url} ({last_exc}). "
                "Vérifiez qu'Ollama est démarré en arrière-plan (ex: lancez 'ollama serve' dans un terminal "
                "ou ouvrez l'application Ollama sous Windows)."
            ) from last_exc

        if not isinstance(body, dict) or not isinstance(body.get("response"), str):
            raise OllamaError("Réponse Ollama invalide : champ 'response' absent.")
        return body["response"]
