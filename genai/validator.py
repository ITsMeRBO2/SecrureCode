"""Validation déterministe des correctifs Java proposés par GenAI."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import re
from pathlib import Path

from ml.ml_model import SAFE, explain, load_model

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "ml" / "models" / "securecode_ml.joblib"


def compile_java(code: str) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory() as tmp:
        class_match = re.search(r"\bpublic\s+class\s+([A-Za-z_][A-Za-z0-9_]*)", code)
        class_name = class_match.group(1) if class_match else "SecureCodeSnippet"
        source = Path(tmp) / f"{class_name}.java"
        source.write_text(code, encoding="utf-8")
        proc = subprocess.run(
            ["javac", "-proc:none", str(source)],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    return proc.returncode == 0, (proc.stderr or proc.stdout).strip()


def baseline_clear(code: str) -> tuple[bool, str]:
    if shutil.which("semgrep") is None:
        return False, "Semgrep est absent de l'environnement."
    from baseline.run_semgrep import run_semgrep

    with tempfile.TemporaryDirectory() as tmp:
        source = Path(tmp) / "SecureCodeSnippet.java"
        source.write_text(code, encoding="utf-8")
        findings = run_semgrep(source)
    return not findings, f"{len(findings)} finding(s) Semgrep restant(s)."


def ml_safe(code: str) -> tuple[bool, str]:
    if not MODEL_PATH.exists():
        return False, f"Modèle ML absent : {MODEL_PATH}"
    result = explain(load_model(MODEL_PATH), code)
    return result["label"] == SAFE, f"Classe ML : {result['label']}."


def validate_fix(code: str, fixed_code: str) -> dict:
    javac_ok, javac_message = compile_java(fixed_code)
    baseline_ok, baseline_message = baseline_clear(fixed_code)
    ml_ok, ml_message = ml_safe(fixed_code)
    return {
        "validated": javac_ok and baseline_ok and ml_ok,
        "javac": {"ok": javac_ok, "message": javac_message},
        "baseline": {"ok": baseline_ok, "message": baseline_message},
        "ml": {"ok": ml_ok, "message": ml_message},
    }
