"""Orchestration des analyses baseline, ML et GenAI."""
from __future__ import annotations

import csv
import json
import logging
import re
import tempfile
from pathlib import Path
from typing import Callable

from baseline.run_semgrep import deduplicate_findings, run_semgrep
from genai.analyze import analyze as genai_analyze
from genai.validator import validate_fix
from ml.ml_model import SAFE, explain, load_model
from pipeline.signatures import detect_signatures

LOGGER = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = ROOT / "ml" / "models" / "securecode_ml.joblib"

# Seuil de confiance ML : en dessous, le ML ne confirme pas une alerte
ML_CONFIDENCE_THRESHOLD = 0.40


def looks_like_javascript(code: str) -> bool:
    """Détecte quelques marqueurs non ambigus de JavaScript/Node.js."""
    return bool(
        re.search(r"\brequire\s*\(", code)
        or re.search(r"\breq\.body\b", code)
        or re.search(r"\b(?:const|let)\s+[A-Za-z_$]", code)
        or "=>" in code
    )


def extract_snippet_from_code(
    code: str,
    line_start: int,
    line_end: int | None = None,
    context_lines: int = 2,
) -> tuple[str, str]:
    """Extrait la ligne vulnérable et son contexte avec numéros (1-based).

    Garde-fou infaillible si Semgrep renvoie 'requires login' ou du vide.
    """
    lines = code.splitlines()
    if not lines:
        return "", ""
    start = max(1, min(line_start, len(lines)))
    end = min(max(line_end or line_start, start), len(lines))
    snippet = "\n".join(lines[start - 1 : end])

    ctx_start = max(1, start - context_lines)
    ctx_end = min(len(lines), end + context_lines)
    ctx_lines = []
    for idx in range(ctx_start, ctx_end + 1):
        prefix = ">" if start <= idx <= end else " "
        ctx_lines.append(f"{prefix} {idx:4d} | {lines[idx - 1]}")
    return snippet, "\n".join(ctx_lines)


def _error(approach: str, exc: Exception) -> dict:
    LOGGER.error("%s a échoué : %s", approach, exc)
    return {"approach": approach, "status": "error", "error": str(exc)}


def analyze(
    code: str,
    *,
    generator=None,
    model_path: Path = DEFAULT_MODEL,
    baseline_runner: Callable[[Path], list[dict]] = run_semgrep,
    ml_confidence_threshold: float = ML_CONFIDENCE_THRESHOLD,
) -> dict:
    """Analyse du code avec les trois approches et retourne un résultat sérialisable.

    Règles de décision :
    - La source de vérité pour les findings et lignes est UNIQUEMENT Semgrep (baseline).
    - Les snippets ne proviennent JAMAIS de 'extra.lines' (évite 'requires login').
    - Dédoublonnage défensif : 1 seul finding par (CWE, plage de lignes).
    - Le ML confirme la présence de vulnérabilité avec un seuil de confiance.
    - Le GenAI n'est appelé que si Semgrep trouve des vulnérabilités.
    - Boucle de réparation (max 3 essais) si javac échoue ou si le re-scan trouve des failles.
    """
    result: dict = {"findings": [], "errors": []}
    detected_cwes: set[str] = set()

    # ── Rejet des langages non supportés ────────────────────────────────────
    if looks_like_javascript(code):
        error = {
            "approach": "input",
            "status": "unsupported_language",
            "error": "Code JavaScript détecté. Le projet analyse uniquement le code Java.",
        }
        result.update(
            {
                "baseline": {"status": "skipped", "error": error["error"]},
                "ml": {"status": "skipped", "error": error["error"]},
                "genai": {"status": "skipped", "error": error["error"]},
                "errors": [error],
                "status": "unsupported_language",
                "overall": "unsupported",
            }
        )
        return result

    # ── ÉTAPE 1 : BASELINE (Semgrep + fallback signatures) ──────────────────
    try:
        baseline_findings = []
        semgrep_ok = False
        try:
            with tempfile.TemporaryDirectory() as tmp:
                source = Path(tmp) / "SecureCodeSnippet.java"
                source.write_text(code, encoding="utf-8")
                baseline_findings = baseline_runner(source)
                semgrep_ok = True
        except Exception as semgrep_err:
            LOGGER.warning(
                "Semgrep a échoué ou absent (%s), utilisation des signatures déterministes.",
                semgrep_err,
            )

        # Signatures déterministes utilisées UNIQUEMENT si Semgrep a échoué
        signature_findings = detect_signatures(code) if not semgrep_ok else []

        # Dédoublonnage défensif dès la collecte baseline
        raw_baseline = baseline_findings if semgrep_ok else signature_findings
        deduped_baseline = deduplicate_findings(raw_baseline)

        detected_cwes.update(finding["cwe"] for finding in deduped_baseline)

        # Construction des findings avec vérification stricte du snippet
        for finding in deduped_baseline:
            approach_name = "baseline" if semgrep_ok else "deterministic"
            line_start = finding.get("line_start") or finding.get("line") or 1
            line_end = finding.get("line_end") or line_start

            snippet = finding.get("snippet", "")
            context_snippet = finding.get("context_snippet", "")

            # Garde-fou absolu contre "requires login" ou extrait vide
            if not snippet or "requires login" in str(snippet).lower():
                snippet, context_snippet = extract_snippet_from_code(code, line_start, line_end)

            result["findings"].append(
                {
                    "approach": approach_name,
                    "status": "detected",
                    "cwe": finding["cwe"],
                    "line": line_start,
                    "line_start": line_start,
                    "line_end": line_end,
                    "severity": finding.get("severity", "ERROR"),
                    "snippet": snippet,
                    "context_snippet": context_snippet,
                    "confidence": None,
                    "explanation": finding.get("message", "Vulnérabilité détectée."),
                    "genai_explanation": None,
                    "fixed_code": None,
                    "validation": None,
                }
            )

        result["baseline"] = {
            "status": "ok",
            "count": len(result["findings"]),
            "deterministic_count": len(signature_findings) if not semgrep_ok else 0,
            "cwes": sorted(detected_cwes),
            "semgrep_ok": semgrep_ok,
        }
    except Exception as exc:
        result["baseline"] = _error("Baseline", exc)
        result["errors"].append(result["baseline"])

    # ── ÉTAPE 2 : ML ────────────────────────────────────────────────────────
    ml_confirms_vulnerability = False
    try:
        prediction = explain(load_model(model_path), code)
        ml_label = prediction["label"]
        ml_confidence = prediction["confidence"]
        ml_confirms_vulnerability = (
            ml_label != SAFE
            and ml_confidence >= ml_confidence_threshold
            and prediction["cwe"] in detected_cwes
        )
        result["ml"] = {
            "status": "ok",
            **prediction,
            "threshold": ml_confidence_threshold,
            "confirms_vulnerability": ml_confirms_vulnerability,
        }
    except Exception as exc:
        result["ml"] = _error("ML", exc)
        result["errors"].append(result["ml"])

    # ── ÉTAPE 3 : GENAI (uniquement si Semgrep a trouvé des findings) ────────
    if generator is None:
        result["genai"] = {
            "status": "skipped",
            "error": "Aucun générateur GenAI fourni.",
        }
    elif not detected_cwes:
        result["genai"] = {
            "status": "skipped",
            "error": "Aucune vulnérabilité détectée par Semgrep : GenAI non appelé.",
        }
    else:
        try:
            max_attempts = 3
            proposal = None
            validation = None
            retry_hint = ""

            for attempt in range(1, max_attempts + 1):
                try:
                    proposal = genai_analyze(
                        code,
                        generator,
                        expected_cwes=detected_cwes,
                        retry_hint=retry_hint,
                    )
                    from genai.analyze import auto_repair_unclosed_strings
                    fixed_candidate = auto_repair_unclosed_strings(proposal.get("fixed_code", ""))
                    proposal["fixed_code"] = fixed_candidate
                    validation = validate_fix(code, fixed_candidate)

                    javac_info = validation.get("javac", {}) if isinstance(validation, dict) else {}
                    baseline_info = validation.get("baseline", {}) if isinstance(validation, dict) else {}
                    ml_info = validation.get("ml", {}) if isinstance(validation, dict) else {}

                    # Tout est validé (javac OK, Semgrep re-scan 0, ML SAFE)
                    if validation.get("validated", False) or (
                        javac_info.get("ok", True)
                        and baseline_info.get("ok", True)
                        and ml_info.get("ok", True)
                    ):
                        break

                    # Préparer le feedback ciblé pour la tentative suivante
                    feedback_parts = []
                    if not javac_info.get("ok", True):
                        javac_msg = javac_info.get('message', '')
                        string_literal_hint = ""
                        if "unclosed string literal" in javac_msg:
                            string_literal_hint = (
                                "\n- ERREUR 'unclosed string literal' : en Java standard, une chaîne entre guillemets "
                                "doubles simples \"...\" ne peut PAS s'étendre sur plusieurs lignes. Utilise un Text Block "
                                "\"\"\" ... \"\"\" (trois guillemets) ou la concaténation (\"ligne 1\\n\" + \"ligne 2\")."
                            )
                        class_hint = ""
                        if "is public, should be declared in a file named" in javac_msg:
                            class_hint = "\n- Conserver le nom EXACT de la classe d'origine, ne pas la renommer."

                        feedback_parts.append(
                            f"ERREUR DE COMPILATION JAVAC (tentative {attempt}/{max_attempts}) :\n"
                            f"{javac_msg}\n\n"
                            f"Voici le code que tu as généré et qui ne compile pas :\n"
                            f"```java\n{fixed_candidate}\n```\n"
                            "Consigne impérative : Corrige UNIQUEMENT ces erreurs de compilation javac.\n"
                            "- Ne jamais appeler de méthode levant une exception vérifiée (ex: toRealPath()) "
                            "dans un initialiseur direct de champ statique ou d'instance.\n"
                            "- Utilise Paths.get(BASE_DIR).toAbsolutePath().normalize() "
                            "ou un bloc static { try { ... } catch (IOException e) { throw new ExceptionInInitializerError(e); } }.\n"
                            f"- Conserver le même nom de classe publique et les mêmes imports.{string_literal_hint}{class_hint}"
                        )
                    elif not baseline_info.get("ok", True):
                        feedback_parts.append(
                            f"VULNÉRABILITÉS RÉSIDUELLES DÉTECTÉES PAR LE RE-SCAN (tentative {attempt}/{max_attempts}) :\n"
                            f"{baseline_info.get('message', '')}\n\n"
                            f"Voici le code qui contient encore des vulnérabilités :\n"
                            f"```java\n{fixed_candidate}\n```\n"
                            "Consigne impérative : Sécurise ces points résiduels (PreparedStatement avec setXxx, "
                            "escapeHtml() sur les sorties HTML, normalize() + startsWith() sur les chemins) "
                            "et renvoie le code Java complet corrigé."
                        )
                    elif not ml_info.get("ok", True):
                        feedback_parts.append(
                            f"AVERTISSEMENT DU CLASSIFICATEUR ML :\n{ml_info.get('message', '')}"
                        )

                    retry_hint = "\n\n" + "\n".join(feedback_parts)

                except ValueError as exc:
                    if attempt == max_attempts:
                        raise
                    retry_hint = (
                        f"\n\nATTENTION : ta réponse précédente a échoué ({exc}).\n"
                        "Réponds STRICTEMENT avec un JSON valide contenant les champs 'cwes', 'findings' et 'fixed_code'."
                    )

            confirmed_cwes = [cwe for cwe in proposal["cwes"] if cwe in detected_cwes]

            # Index des explications GenAI par CWE
            genai_explanation_by_cwe: dict[str, str] = {}
            for gf in proposal.get("findings", []):
                cwe = gf.get("cwe")
                if cwe and cwe in detected_cwes:
                    exp = gf.get("explanation") or gf.get("explication") or ""
                    if exp and cwe not in genai_explanation_by_cwe:
                        genai_explanation_by_cwe[cwe] = exp

            result["genai"] = {
                "status": "ok",
                **proposal,
                "confirmed_cwes": confirmed_cwes,
                "unconfirmed_cwes": [
                    cwe for cwe in proposal.get("cwes", []) if cwe not in detected_cwes
                ],
                "validation": validation,
            }

            # Enrichir les findings baseline avec l'explication GenAI et le code corrigé
            for finding in result["findings"]:
                cwe = finding.get("cwe")
                if cwe in genai_explanation_by_cwe and finding.get("genai_explanation") is None:
                    finding["genai_explanation"] = genai_explanation_by_cwe[cwe]
                if finding.get("fixed_code") is None:
                    finding["fixed_code"] = proposal.get("fixed_code")
                if finding.get("validation") is None:
                    finding["validation"] = validation

        except Exception as exc:
            result["genai"] = _error("GenAI", exc)
            result["errors"].append(result["genai"])

    # ── STATUT GLOBAL ────────────────────────────────────────────────────────
    # Règles claires :
    # - "safe" si aucun finding Semgrep initial, ou si le correctif est entièrement validé
    # - "partial_fix" si javac échoue ou si des failles subsistent
    # - "uncertain" en cas de désaccord entre approches
    # - "vulnerable" si non corrigé
    if not detected_cwes:
        overall = "safe"
    elif result.get("genai", {}).get("validation"):
        v = result["genai"]["validation"]
        j_ok = v.get("javac", {}).get("ok", False)
        b_ok = v.get("baseline", {}).get("ok", False)
        m_ok = v.get("ml", {}).get("ok", False)

        if j_ok and b_ok and m_ok:
            overall = "safe"
        elif not j_ok:
            overall = "compilation_failed"
        elif not b_ok:
            overall = "partial_fix"
        elif not m_ok:
            overall = "uncertain"
        else:
            overall = "partial_fix"
    elif ml_confirms_vulnerability:
        overall = "vulnerable"
    elif result.get("ml", {}).get("label") == SAFE and detected_cwes:
        overall = "uncertain"
    else:
        overall = "vulnerable"

    result["overall"] = overall
    result["status"] = "ok" if not result["errors"] else "partial_error"
    return result


def export_json(result: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def export_csv(result: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["approach", "status", "cwe", "line", "confidence", "explanation", "validated"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for finding in result.get("findings", []):
            validation = finding.get("validation") or {}
            writer.writerow(
                {
                    key: finding.get(key)
                    for key in fields[:-1]
                }
                | {"validated": validation.get("validated") if validation else None}
            )
