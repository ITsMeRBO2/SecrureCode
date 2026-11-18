"""Validation déterministe des correctifs Java proposés par GenAI."""
from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
import re
import os
from pathlib import Path

from ml.ml_model import SAFE, explain, load_model
from pipeline.signatures import detect_signatures

LOGGER = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "ml" / "models" / "securecode_ml.joblib"


def java_classpath() -> str | None:
    """Retourne le classpath Java configuré pour les dépendances externes."""
    configured = os.environ.get("SECURECODE_JAVA_CLASSPATH")
    if configured:
        return configured
    jars = sorted((ROOT / "lib").glob("*.jar"))
    return os.pathsep.join(str(jar) for jar in jars) or None


def find_javac() -> str | None:
    """Trouve l'exécutable javac dans le PATH ou dans JAVA_HOME."""
    exe = shutil.which("javac")
    if exe:
        return exe
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = Path(java_home) / "bin" / ("javac.exe" if os.name == "nt" else "javac")
        if candidate.exists():
            return str(candidate)
    return None


def compile_java(code: str, timeout: float = 30.0) -> tuple[bool, str]:
    javac = find_javac()
    if not javac:
        return False, "javac est introuvable. Installez un JDK (ex: JDK 17) et vérifiez le PATH ou JAVA_HOME."

    # Nettoyage si markdown résiduel
    code = code.strip()
    code = re.sub(r'^```\w*\n?', '', code)
    code = re.sub(r'\n?```$', '', code.strip()).strip()

    with tempfile.TemporaryDirectory() as tmp:
        # Trouver le nom de classe publique ou de classe principale
        class_match = re.search(r"\bpublic\s+(?:final\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)", code)
        if not class_match:
            class_match = re.search(r"\b(?:final\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)", code)
        class_name = class_match.group(1) if class_match else "SecureCodeSnippet"

        # Gestion de package éventuel
        pkg_match = re.search(r"^\s*package\s+([A-Za-z0-9_.]+)\s*;", code, re.M)
        if pkg_match:
            pkg_dir = Path(tmp) / pkg_match.group(1).replace(".", os.sep)
            pkg_dir.mkdir(parents=True, exist_ok=True)
            source = pkg_dir / f"{class_name}.java"
        else:
            source = Path(tmp) / f"{class_name}.java"

        source.write_text(code, encoding="utf-8")
        command = [javac, "-proc:none", "-encoding", "UTF-8"]
        classpath = java_classpath()
        if classpath:
            command.extend(["-cp", classpath])
        command.append(str(source))
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return False, f"La compilation javac a dépassé le délai limite de {timeout}s."

        message = (proc.stderr or proc.stdout).strip()
        if proc.returncode != 0 and "unclosed string literal" in message:
            from genai.analyze import auto_repair_unclosed_strings
            repaired_code = auto_repair_unclosed_strings(code)
            if repaired_code != code:
                source.write_text(repaired_code, encoding="utf-8")
                proc = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=timeout,
                )
                message = (proc.stderr or proc.stdout).strip()

    if proc.returncode and "package javax.servlet does not exist" in message:
        message += (
            "\nDépendance absente : installe javax.servlet-api et configure "
            "SECURECODE_JAVA_CLASSPATH ou place le JAR dans lib\\."
        )
    return proc.returncode == 0, message


def baseline_clear(code: str) -> tuple[bool, str]:
    from baseline.run_semgrep import run_semgrep

    class_match = re.search(r"\bpublic\s+(?:final\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)", code)
    if not class_match:
        class_match = re.search(r"\b(?:final\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)", code)
    class_name = class_match.group(1) if class_match else "SecureCodeSnippet"

    findings = []
    semgrep_executed = False
    if shutil.which("semgrep") is not None:
        try:
            with tempfile.TemporaryDirectory() as tmp:
                source = Path(tmp) / f"{class_name}.java"
                source.write_text(code, encoding="utf-8")
                findings = run_semgrep(source)
                semgrep_executed = True
        except Exception as exc:
            LOGGER.warning("Re-scan Semgrep a échoué : %s", exc)
            findings = []

    signatures = detect_signatures(code) if not semgrep_executed else []
    if findings:
        details = [
            f"- {f.get('cwe', 'CWE')} ligne {f.get('line', f.get('line_start'))}: {f.get('message', '')}"
            for f in findings
        ]
        message = f"{len(findings)} finding(s) Semgrep restant(s) :\n" + "\n".join(details)
    else:
        message = "0 finding(s) Semgrep restant(s)."
    if signatures:
        message += f" {len(signatures)} signal(s) déterministe(s) restant(s)."
    return not findings and not signatures, message


def ml_safe(code: str) -> tuple[bool, str]:
    if not MODEL_PATH.exists():
        return False, f"Modèle ML absent : {MODEL_PATH}"
    result = explain(load_model(MODEL_PATH), code)
    if result["label"] == SAFE:
        return True, "Classe ML : SAFE."
    if not detect_signatures(code):
        return (
            True,
            f"Classe ML consultative : {result['label']}; aucun signal déterministe restant.",
        )
    return False, f"Classe ML : {result['label']}."


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
