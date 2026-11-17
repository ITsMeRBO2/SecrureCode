"""Préparation des données SecureCode AI (OWASP Benchmark v1.2, Java).

Usage :
    python data/prepare_data.py                      # clone le Benchmark dans data/raw si absent
    python data/prepare_data.py --benchmark-dir CHEMIN_VERS/BenchmarkJava

Sortie : data/processed/dataset.csv + data/processed/dataset_stats.json

Colonnes : test_name, category, cwe, vulnerable, code_raw, code_clean, split
 - code_raw   : code original (pour la baseline SAST, l'affichage, le LLM)
 - code_clean : sans commentaires, sans annotation @WebServlet, noms de tests
                normalisés (pour le ML) -> évite le data leakage.

Le split train/test se fait PAR FICHIER (un fichier = un cas de test), stratifié
par (CWE, vulnérable). Le jeu de test ne sert qu'à l'évaluation finale.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

REPO_URL = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
TESTCODE_DIR = Path("src/main/java/org/owasp/benchmark/testcode")
EXPECTED_CSV = "expectedresults-1.2.csv"

# Catégories du Benchmark -> CWE retenus pour le projet
CATEGORY_TO_CWE = {"sqli": "CWE-89", "xss": "CWE-79", "pathtraver": "CWE-22"}

_TOKEN = re.compile(
    r"""(?P<keep>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(?P<com>//[^\n]*|/\*.*?\*/)""",
    re.S,
)


def strip_comments(code: str) -> str:
    """Supprime les commentaires Java sans toucher aux chaînes ; garde les retours à la ligne."""
    return _TOKEN.sub(lambda m: m.group("keep") or "\n" * m.group("com").count("\n"), code)


def clean_code(code: str) -> str:
    """Version « propre » pour le ML : retire tout indice qui trahit l'étiquette."""
    code = strip_comments(code)
    code = re.sub(r"@WebServlet\([^)]*\)\s*", "", code)  # contient ex. /sqli-00/
    code = re.sub(r"BenchmarkTest\d+", "TestCase", code)  # nom de fichier/classe
    code = re.sub(r"/(sqli|xss|pathtraver|cmdi|crypto|hash|ldapi|securecookie|trustbound|weakrand|xpathi)-\d+/", "/CAT/", code)  # chemins de pages
    code = re.sub(r"\n\s*\n+", "\n", code)  # lignes vides multiples
    return code.strip()


def load_labels(benchmark_dir: Path) -> pd.DataFrame:
    rows = []
    with open(benchmark_dir / EXPECTED_CSV, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader)  # en-tête
        for r in reader:
            if len(r) < 4:
                continue
            name, category, real_vuln = r[0].strip(), r[1].strip(), r[2].strip()
            if category in CATEGORY_TO_CWE:
                rows.append(
                    {
                        "test_name": name,
                        "category": category,
                        "cwe": CATEGORY_TO_CWE[category],
                        "vulnerable": real_vuln.lower() == "true",
                    }
                )
    return pd.DataFrame(rows)


def build_dataset(benchmark_dir: Path) -> pd.DataFrame:
    df = load_labels(benchmark_dir)
    raws = []
    for name in df["test_name"]:
        path = benchmark_dir / TESTCODE_DIR / f"{name}.java"
        raws.append(path.read_text(encoding="utf-8"))
    df["code_raw"] = raws
    df["code_clean"] = df["code_raw"].map(clean_code)
    return df


def add_split(df: pd.DataFrame, test_size: float = 0.2, seed: int = 42) -> pd.DataFrame:
    """Split par fichier (chaque ligne = un fichier unique), stratifié CWE x vulnérable."""
    assert df["test_name"].is_unique, "un test_name apparaît deux fois"
    strata = df["cwe"] + "|" + df["vulnerable"].astype(str)
    train_idx, test_idx = train_test_split(
        df.index, test_size=test_size, random_state=seed, stratify=strata
    )
    df = df.copy()
    df["split"] = "train"
    df.loc[test_idx, "split"] = "test"
    assert set(df.loc[train_idx, "test_name"]).isdisjoint(df.loc[test_idx, "test_name"])
    return df


def stats(df: pd.DataFrame) -> dict:
    out = {}
    for (split, cwe, vuln), g in df.groupby(["split", "cwe", "vulnerable"]):
        out.setdefault(split, {}).setdefault(cwe, {})["vulnerable" if vuln else "safe"] = len(g)
    return out


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--benchmark-dir", default="data/raw/BenchmarkJava")
    p.add_argument("--out-dir", default="data/processed")
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    bench = Path(args.benchmark_dir)
    if not bench.exists():
        bench.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth", "1", REPO_URL, str(bench)], check=True)

    df = add_split(build_dataset(bench), args.test_size, args.seed)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    df.to_csv(out / "dataset.csv", index=False)
    s = stats(df)
    (out / "dataset_stats.json").write_text(json.dumps(s, indent=2), encoding="utf-8")
    print(f"{len(df)} cas écrits dans {out / 'dataset.csv'}")
    print(json.dumps(s, indent=2))


if __name__ == "__main__":
    main()
