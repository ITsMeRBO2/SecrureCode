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


def repair_mojibake(text: str) -> str:
    """Répare uniquement les textes UTF-8 déjà décodés par erreur en Latin-1."""
    if not any(marker in text for marker in ("Ã", "Â", "â")):
        return text
    try:
        return text.encode("latin-1").decode("utf-8")
    except UnicodeError:
        return text


def semgrep_cmd() -> list[str]:
    exe = shutil.which("semgrep")
    return [exe] if exe else [sys.executable, "-m", "semgrep"]


def extract_snippet_from_source(
    file_path: Path,
    line_start: int,
    line_end: int,
    context_lines: int = 2,
) -> tuple[str, str]:
    """Extrait l'extrait exact (snippet) et le contexte avec numéros de lignes

    directement depuis le fichier source analysé (indexation 1-based).
    Ne dépend JAMAIS du champ extra.lines de Semgrep.
    """
    if not file_path.exists():
        return "", ""
    try:
        content = file_path.read_text(encoding="utf-8")
        lines = content.splitlines()
        total_lines = len(lines)
        if total_lines == 0 or line_start < 1 or line_start > total_lines:
            return "", ""

        actual_end = min(max(line_end, line_start), total_lines)
        exact_snippet = "\n".join(lines[line_start - 1 : actual_end])

        ctx_start = max(1, line_start - context_lines)
        ctx_end = min(total_lines, actual_end + context_lines)

        context_rows = []
        for i in range(ctx_start, ctx_end + 1):
            line_content = lines[i - 1]
            marker = ">" if line_start <= i <= actual_end else " "
            context_rows.append(f"{marker} {i:4d} | {line_content}")

        context_snippet = "\n".join(context_rows)
        return exact_snippet, context_snippet
    except Exception:
        return "", ""


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Dédoublonne et fusionne les findings :

    - Une seule entrée par (CWE, ligne ou plage de lignes qui se chevauchent/adjacentes).
    - Si plusieurs règles matchent la même ligne et le même CWE, fusionne en un seul finding
      (garde la sévérité la plus haute, concatène les rule_ids).
    - Conserve intacts deux CWE distincts sur la même ligne (ce ne sont pas des doublons).
    """
    severity_order = {"ERROR": 3, "WARNING": 2, "INFO": 1}

    def sort_key(f):
        cwe = f.get("cwe", "")
        start = f.get("line_start") or f.get("line") or 0
        end = f.get("line_end") or start
        return (cwe, start, end)

    sorted_findings = sorted(findings, key=sort_key)
    merged: list[dict] = []

    for f in sorted_findings:
        cwe = f.get("cwe")
        start = f.get("line_start") or f.get("line") or 0
        end = f.get("line_end") or start

        if merged:
            last = merged[-1]
            last_cwe = last.get("cwe")
            last_start = last.get("line_start") or last.get("line") or 0
            last_end = last.get("line_end") or last_start

            # Même CWE et chevauchement, même ligne ou lignes adjacentes
            if cwe == last_cwe and (
                (start <= last_end and end >= last_start)
                or (start == last_start)
                or (abs(start - last_end) <= 1)
            ):
                new_start = min(last_start, start)
                new_end = max(last_end, end)
                last["line_start"] = new_start
                last["line_end"] = new_end
                last["line"] = new_start

                last_sev = last.get("severity", "ERROR")
                f_sev = f.get("severity", "ERROR")
                if severity_order.get(f_sev, 0) > severity_order.get(last_sev, 0):
                    last["severity"] = f_sev

                last_rules = [r.strip() for r in last.get("rule_id", "").split(",") if r.strip()]
                f_rules = [r.strip() for r in f.get("rule_id", "").split(",") if r.strip()]
                all_rules = list(dict.fromkeys(last_rules + f_rules))
                last["rule_id"] = ", ".join(all_rules)

                if f.get("message") and f.get("message") != last.get("message"):
                    if not last.get("message"):
                        last["message"] = f["message"]

                # Privilégier un extrait propre
                if not last.get("snippet") or "requires login" in str(last.get("snippet")).lower():
                    last["snippet"] = f.get("snippet", "")
                if not last.get("context_snippet"):
                    last["context_snippet"] = f.get("context_snippet", "")
                continue

        copy_f = dict(f)
        copy_f["line_start"] = start
        copy_f["line_end"] = end
        copy_f["line"] = start
        merged.append(copy_f)

    return merged


def run_semgrep(target: Path, rules: Path = RULES_DIR) -> list[dict]:
    """Lance Semgrep sur un fichier ou un dossier et retourne la liste de findings."""
    cmd = semgrep_cmd() + [
        "--config", str(rules), "--json", "--metrics=off", "--quiet",
        "--disable-version-check", "--no-git-ignore", "--timeout", "30", str(target),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if proc.returncode not in (0, 1) or not proc.stdout.strip():
        raise RuntimeError(f"Semgrep a échoué (code {proc.returncode}) :\n{proc.stderr[-2000:]}")
    raw_findings = []
    for r in json.loads(proc.stdout)["results"]:
        fpath = Path(r["path"])
        line_start = r["start"]["line"]
        line_end = r["end"]["line"]

        # Extraction directe depuis le fichier source (ne jamais utiliser extra.lines)
        snippet, context_snippet = extract_snippet_from_source(fpath, line_start, line_end)

        # Garde-fou supplémentaire : si vide ou requires login, fallback
        if not snippet or "requires login" in snippet.lower():
            extra_lines = r.get("extra", {}).get("lines", "")
            if extra_lines and "requires login" not in extra_lines.lower():
                snippet = extra_lines.strip()
            else:
                snippet = ""

        raw_findings.append(
            {
                "file": fpath.stem,
                "rule_id": r["check_id"].split(".")[-1],
                "cwe": r["extra"]["metadata"]["cwe"],
                "line_start": line_start,
                "line_end": line_end,
                "line": line_start,
                "message": repair_mojibake(" ".join(r["extra"]["message"].split())),
                "severity": r["extra"].get("severity", "ERROR"),
                "snippet": snippet,
                "context_snippet": context_snippet,
            }
        )

    # Dédoublonnage défensif
    return deduplicate_findings(raw_findings)


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
