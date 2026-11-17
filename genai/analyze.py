"""Analyse GenAI structurée, indépendante du serveur Ollama pour les tests."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

PROMPT_PATH = Path(__file__).with_name("prompts") / "explain_and_fix.txt"
CWES = {"CWE-89", "CWE-79", "CWE-22"}


class TextGenerator(Protocol):
    def generate(self, prompt: str) -> str: ...


def build_prompt(code: str) -> str:
    return PROMPT_PATH.read_text(encoding="utf-8").replace("{code}", code)


def parse_response(raw: str) -> dict:
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("La réponse GenAI n'est pas un JSON valide.") from exc
    required = {"cwe", "vulnerable_line", "explanation", "fixed_code"}
    if not isinstance(result, dict) or set(result) != required:
        raise ValueError("La réponse GenAI doit contenir exactement les quatre champs attendus.")
    if result["cwe"] not in CWES:
        raise ValueError(f"CWE non supportée : {result['cwe']!r}.")
    if not isinstance(result["vulnerable_line"], int) or result["vulnerable_line"] < 1:
        raise ValueError("vulnerable_line doit être un entier positif.")
    if not all(isinstance(result[key], str) and result[key].strip() for key in ("explanation", "fixed_code")):
        raise ValueError("explanation et fixed_code doivent être des chaînes non vides.")
    return result


def analyze(code: str, generator: TextGenerator) -> dict:
    """Génère et valide une proposition GenAI sans exécuter le code produit."""
    return parse_response(generator.generate(build_prompt(code)))
