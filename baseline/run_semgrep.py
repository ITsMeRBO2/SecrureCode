"""Baseline SAST : exécute les règles Semgrep sur le dataset et écrit les prédictions.

Usage :
    python baseline/run_semgrep.py
    python baseline/run_semgrep.py --dataset data/processed/dataset.csv

Sorties (dans eval/results/) :
    baseline_predictions.csv   une ligne par fichier : test_name, split, cwe, vulnerable, pred_cwes
    baseline_findings.json     findings détaillés (CWE, lignes, message) pour l'application
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "baseline" / "rules"


def semgrep_cmd() -> list[str]:
    exe = shutil.which("semgrep")
    return [exe] if exe else [sys.executable, "-m", "semgrep"]


def run_semgrep(target: Path, rules: Path = RULES_DIR) -> list[dict]:
    """Lance Semgrep sur un fichier ou un dossier et retourne la liste de findings."""
    cmd = semgrep_cmd() + [
        "--config", str(rules), "--json", "--metrics=off", "--quiet",
        "--disable-version-check", "--no-git-ignore", "--timeout", "30", str(target),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if proc.returncode not in (0, 1) or not proc.stdout.strip():
        raise RuntimeError(f"Semgrep a échoué (code {proc.returncode}) :\n{proc.stderr[-2000:]}")
    findings = []
    for r in json.loads(proc.stdout)["results"]:
        findings.append(
            {
                "file": Path(r["path"]).stem,
                "rule_id": r["check_id"].split(".")[-1],
                "cwe": r["extra"]["metadata"]["cwe"],
                "line_start": r["start"]["line"],
                "line_end": r["end"]["line"],
                "message": " ".join(r["extra"]["message"].split()),
            }
        )
    return findings


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", default=str(ROOT / "data/processed/dataset.csv"))
    p.add_argument("--out-dir", default=str(ROOT / "eval/results"))
    args = p.parse_args()

    df = pd.read_csv(args.dataset)
    with tempfile.TemporaryDirectory() as tmp:
        for name, code in zip(df["test_name"], df["code_raw"]):
            (Path(tmp) / f"{name}.java").write_text(code, encoding="utf-8")
        findings = run_semgrep(Path(tmp))

    by_file: dict[str, set[str]] = {}
    for f in findings:
        by_file.setdefault(f["file"], set()).add(f["cwe"])
    df["pred_cwes"] = df["test_name"].map(lambda n: ";".join(sorted(by_file.get(n, set()))))

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    df[["test_name", "split", "cwe", "vulnerable", "pred_cwes"]].to_csv(
        out / "baseline_predictions.csv", index=False
    )
    (out / "baseline_findings.json").write_text(
        json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"{len(df)} fichiers analysés, {len(findings)} findings -> {out}")


if __name__ == "__main__":
    main()
