"""Analyse GenAI structurée, indépendante du serveur Ollama pour les tests."""
from __future__ import annotations

import json
import re as _re
from pathlib import Path
from typing import Protocol

PROMPT_PATH = Path(__file__).with_name("prompts") / "explain_and_fix.txt"
CWES = {"CWE-89", "CWE-79", "CWE-22"}


class TextGenerator(Protocol):
    def generate(self, prompt: str) -> str: ...


def build_prompt(code: str, expected_cwes: set[str] | None = None) -> str:
    prompt = PROMPT_PATH.read_text(encoding="utf-8").replace("{code}", code)
    if expected_cwes:
        expected = ", ".join(sorted(expected_cwes))
        prompt += (
            f"\n\nDes détecteurs statiques indépendants (Semgrep) ont signalé les CWE suivantes"
            f" dans ce code : {expected}.\n"
            "Pour chaque CWE signalée, fournis une explication pédagogique (champ 'explanation')"
            " dans 'findings' et produis le code Java complet corrigé dans 'fixed_code'.\n"
            "Les numéros de ligne ('vulnerable_line') doivent correspondre aux lignes réelles"
            " du code fourni (indexation 1-based). Ne pas inventer de nouvelles vulnérabilités"
            " absentes de la liste ci-dessus."
        )
    return prompt


def auto_repair_unclosed_strings(code: str) -> str:
    """Si une chaîne déclarée avec un seul guillemet s'étend sur plusieurs lignes,
    la convertit proprement en Text Block Java 17 (\"\"\").
    """
    lines = code.splitlines()
    repaired: list[str] = []
    in_broken_string = False
    buffer: list[str] = []
    for line in lines:
        stripped = line.strip()
        if in_broken_string:
            if stripped.endswith('";') or stripped.endswith('",') or stripped == '"':
                idx = line.rfind('"')
                content = line[:idx]
                tail = line[idx + 1 :]
                if content:
                    buffer.append(content)
                repaired.extend(buffer)
                repaired.append('"""' + tail)
                buffer = []
                in_broken_string = False
            else:
                buffer.append(line)
        else:
            if '"""' not in line:
                quotes = [m.start() for m in _re.finditer(r'(?<!\\)"', line)]
                if len(quotes) % 2 != 0:
                    last_quote = quotes[-1]
                    prefix = line[:last_quote]
                    rest = line[last_quote + 1 :]
                    repaired.append(prefix + '"""')
                    buffer = [rest] if rest else []
                    in_broken_string = True
                    continue
            repaired.append(line)
    return "\n".join(repaired) if not in_broken_string else code


def _clean_code(code: str) -> str:
    """Nettoie le code Java retourné par le LLM."""
    code = code.strip()
    # Supprimer les blocs markdown éventuels
    code = _re.sub(r'^```\w*\n?', '', code)
    code = _re.sub(r'\n?```$', '', code.strip())
    # Supprimer BOM et caractères invisibles
    code = code.replace('\ufeff', '').replace('\u200b', '')
    # Réparer les chaînes multilignes non fermées
    code = auto_repair_unclosed_strings(code)
    return code.strip()


def _extract_and_parse_json(raw: str) -> dict:
    text = raw.strip()
    # 1. Si la réponse globale est enveloppée dans un bloc markdown ```json ... ```
    if text.startswith("```"):
        match = _re.match(r"^```(?:json)?\s*([\s\S]*?)\s*```$", text)
        if match:
            text = match.group(1).strip()

    # 2. Essai direct avec strict=False (tolère les retours à la ligne littéraux dans les chaînes)
    try:
        return json.loads(text, strict=False)
    except json.JSONDecodeError:
        pass

    # 3. Si du texte entoure le JSON (ex: "Voici le JSON : {...}"), extraire entre le premier '{' et dernier '}'
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = text[start : end + 1]
        try:
            return json.loads(candidate, strict=False)
        except json.JSONDecodeError:
            pass

    # 4. Essai après nettoyage des virgules traînantes (trailing commas)
    cleaned = _re.sub(r",\s*([\]}])", r"\1", text)
    try:
        return json.loads(cleaned, strict=False)
    except json.JSONDecodeError:
        pass

    # 5. Essai de réparation si tronqué en fin de chaîne
    repaired = text.strip()
    if not repaired.endswith("}"):
        if repaired.count('"') % 2 != 0:
            repaired += '"'
        if not repaired.endswith("}"):
            repaired += "}"
        try:
            return json.loads(repaired, strict=False)
        except json.JSONDecodeError:
            pass

    raise ValueError("La réponse GenAI n'est pas un JSON valide.")


def parse_response(raw: str) -> dict:
    result = _extract_and_parse_json(raw)
    required = {"cwes", "findings", "fixed_code"}
    if not isinstance(result, dict) or set(result) != required:
        raise ValueError("La réponse GenAI doit contenir cwes, findings et fixed_code.")
    if not isinstance(result["cwes"], list) or not result["cwes"]:
        raise ValueError("cwes doit être une liste non vide de CWE supportées et uniques.")
    if any(cwe not in CWES and cwe != "SAFE" for cwe in result["cwes"]):
        raise ValueError("cwes contient une valeur non supportée.")
    if len(set(result["cwes"])) != len(result["cwes"]):
        raise ValueError("cwes doit contenir des valeurs uniques.")
    if "SAFE" in result["cwes"] and result["cwes"] != ["SAFE"]:
        raise ValueError("SAFE ne peut pas être combiné avec une CWE.")
    if not isinstance(result["findings"], list):
        raise ValueError("findings doit être une liste non vide.")
    for finding in result["findings"]:
        if not isinstance(finding, dict):
            raise ValueError("Chaque finding doit être un objet JSON.")
        line = finding.get("line") if "line" in finding else finding.get("vulnerable_line")
        exp = finding.get("explication") if "explication" in finding else finding.get("explanation")
        cwe = finding.get("cwe")
        if not cwe or not isinstance(cwe, str):
            raise ValueError("Chaque finding doit contenir cwe.")
        if cwe not in result["cwes"]:
            raise ValueError("Chaque finding doit appartenir à la liste cwes.")
        if not isinstance(line, int) or line < 1:
            raise ValueError("line / vulnerable_line doit être un entier positif.")
        if not isinstance(exp, str) or not exp.strip():
            raise ValueError("Chaque explanation / explication doit être une chaîne non vide.")
        finding["line"] = line
        finding["vulnerable_line"] = line
        finding["explanation"] = exp
        finding["explication"] = exp
    if result["cwes"] == ["SAFE"] and result["findings"]:
        raise ValueError("Un résultat SAFE ne doit pas contenir de finding.")
    if result["cwes"] != ["SAFE"] and not result["findings"]:
        raise ValueError("Une analyse vulnérable doit contenir au moins un finding.")
    if not isinstance(result["fixed_code"], str) or not result["fixed_code"].strip():
        raise ValueError("fixed_code doit être une chaîne non vide.")
    result["fixed_code"] = _clean_code(result["fixed_code"])
    return result


def analyze(
    code: str,
    generator: TextGenerator,
    expected_cwes: set[str] | None = None,
    retry_hint: str = "",
) -> dict:
    """Génère et valide une proposition GenAI sans exécuter le code produit."""
    prompt = build_prompt(code, expected_cwes)
    if retry_hint:
        prompt += retry_hint
    result = parse_response(generator.generate(prompt))
    if expected_cwes and not expected_cwes.issubset(set(result["cwes"])):
        missing = ", ".join(sorted(expected_cwes - set(result["cwes"])))
        raise ValueError(f"Réponse GenAI incomplète : CWE manquantes {missing}.")
    return result
