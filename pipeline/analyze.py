"""Orchestration des analyses baseline, ML et GenAI."""
from __future__ import annotations

import csv
import json
import logging
import tempfile
from pathlib import Path
from typing import Callable

from baseline.run_semgrep import run_semgrep
from genai.analyze import analyze as genai_analyze
from genai.validator import validate_fix
from ml.ml_model import SAFE, explain, load_model

LOGGER = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = ROOT / "ml" / "models" / "securecode_ml.joblib"


def _error(approach: str, exc: Exception) -> dict:
    LOGGER.exception("%s a échoué", approach)
    return {"approach": approach, "status": "error", "error": str(exc)}


def analyze(
    code: str,
    *,
    generator=None,
    model_path: Path = DEFAULT_MODEL,
    baseline_runner: Callable[[Path], list[dict]] = run_semgrep,
) -> dict:
    """Analyse du code avec les trois approches et retourne un résultat sérialisable."""
    result: dict = {"findings": [], "errors": []}

    try:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "SecureCodeSnippet.java"
            source.write_text(code, encoding="utf-8")
            baseline_findings = baseline_runner(source)
        for finding in baseline_findings:
            result["findings"].append(
                {
                    "approach": "baseline",
                    "status": "detected",
                    "cwe": finding["cwe"],
                    "line": finding["line_start"],
                    "confidence": None,
                    "explanation": finding["message"],
                    "fixed_code": None,
                    "validation": None,
                }
            )
        result["baseline"] = {"status": "ok", "count": len(baseline_findings)}
    except Exception as exc:
        result["baseline"] = _error("Baseline", exc)
        result["errors"].append(result["baseline"])

    try:
        prediction = explain(load_model(model_path), code)
        result["ml"] = {"status": "ok", **prediction}
        if prediction["label"] != SAFE:
            result["findings"].append(
                {
                    "approach": "ml",
                    "status": "detected",
                    "cwe": prediction["cwe"],
                    "line": None,
                    "confidence": prediction["confidence"],
                    "explanation": "Classe prédite par le modèle ML.",
                    "fixed_code": None,
                    "validation": None,
                }
            )
    except Exception as exc:
        result["ml"] = _error("ML", exc)
        result["errors"].append(result["ml"])

    if generator is None:
        result["genai"] = {
            "status": "skipped",
            "error": "Aucun générateur GenAI fourni.",
        }
    else:
        try:
            proposal = genai_analyze(code, generator)
            validation = validate_fix(code, proposal["fixed_code"])
            result["genai"] = {"status": "ok", **proposal, "validation": validation}
            result["findings"].append(
                {
                    "approach": "genai",
                    "status": "detected",
                    "cwe": proposal["cwe"],
                    "line": proposal["vulnerable_line"],
                    "confidence": None,
                    "explanation": proposal["explanation"],
                    "fixed_code": proposal["fixed_code"],
                    "validation": validation,
                }
            )
        except Exception as exc:
            result["genai"] = _error("GenAI", exc)
            result["errors"].append(result["genai"])

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
