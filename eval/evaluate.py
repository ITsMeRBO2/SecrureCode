"""Métriques par CWE, réutilisables pour la baseline, le ML et la GenAI.

Entrée : CSV avec les colonnes test_name, split, cwe, vulnerable, pred_cwes
         (pred_cwes = CWE prédits pour le fichier, séparés par « ; », vide si rien).

Pour chaque CWE X : positif réel = fichier vulnérable de catégorie X ;
positif prédit = X apparaît dans pred_cwes. Tous les autres fichiers sont des négatifs.

Usage :
    python eval/evaluate.py --pred eval/results/baseline_predictions.csv --split train
"""
from __future__ import annotations

import argparse

import pandas as pd

CWES = ["CWE-89", "CWE-79", "CWE-22"]


def _has(pred: str, cwe: str) -> bool:
    return isinstance(pred, str) and cwe in pred.split(";")


def per_cwe_metrics(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for cwe in CWES:
        y_true = (df["cwe"] == cwe) & df["vulnerable"].astype(bool)
        y_pred = df["pred_cwes"].map(lambda p: _has(p, cwe))
        tp = int((y_true & y_pred).sum())
        fp = int((~y_true & y_pred).sum())
        fn = int((y_true & ~y_pred).sum())
        tn = int((~y_true & ~y_pred).sum())
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        rows.append(
            {"CWE": cwe, "TP": tp, "FP": fp, "FN": fn, "TN": tn,
             "precision": round(precision, 3), "recall": round(recall, 3),
             "F1": round(f1, 3), "taux_FP": round(fpr, 3)}
        )
    return pd.DataFrame(rows)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--pred", required=True)
    p.add_argument("--split", choices=["train", "test", "all"], default="train")
    args = p.parse_args()
    df = pd.read_csv(args.pred, keep_default_na=False)
    df["vulnerable"] = df["vulnerable"].astype(str).str.lower() == "true"
    if args.split != "all":
        df = df[df["split"] == args.split]
    print(f"Split : {args.split} ({len(df)} fichiers)")
    print(per_cwe_metrics(df).to_string(index=False))


if __name__ == "__main__":
    main()
