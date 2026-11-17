"""Entraîne et évalue le classificateur ML.

Usage :
    python ml/train.py

Méthode (sans data leakage) :
 1. Sélection du modèle par validation croisée 5 plis STRATIFIÉE sur le jeu d'entraînement
    uniquement (le TF-IDF est réajusté dans chaque pli, via le Pipeline).
 2. Ré-entraînement du meilleur modèle sur tout le train.
 3. Prédictions : train = out-of-fold (honnêtes), test = modèle final (évalué une seule fois).

Modèle principal : contenu des chaînes masqué ("STR"), pour ne pas lire les constantes
absurdes que le Benchmark utilise dans ses cas sûrs.
Ablation : mêmes hyperparamètres sur le code brut -> montre l'ampleur de la fuite.

Sorties :
    ml/models/securecode_ml.joblib
    eval/results/ml_predictions.csv        (modèle principal)
    eval/results/ml_raw_predictions.csv    (ablation, code brut)
    eval/results/ml_cv_results.json, ml_top_features.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, cross_val_predict, cross_val_score

from ml_model import SAFE, make_pipeline, prepare, save_model

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES = [
    (kind, C, ng)
    for kind, Cs in [("logreg", [1, 10, 100]), ("linsvc", [0.1, 1])]
    for C in Cs
    for ng in (2, 3)
]


def top_features(pipe, k: int = 15) -> dict:
    names = pipe.named_steps["tfidf"].get_feature_names_out()
    clf = pipe.named_steps["clf"]
    return {
        str(cls): [str(names[i]) for i in np.argsort(-clf.coef_[j])[:k]]
        for j, cls in enumerate(clf.classes_)
    }


def fit_and_predict(best, train, test, text_col, cv, seed):
    """Entraîne sur train, renvoie (modèle final, DataFrame de prédictions train OOF + test)."""
    mk = lambda: make_pipeline(best["model"], best["C"], best["ngram_max"], seed)  # noqa: E731
    final = mk().fit(train[text_col], train["label"])
    tr, te = train.copy(), test.copy()
    tr["pred"] = cross_val_predict(mk(), train[text_col], train["label"], cv=cv)
    te["pred"] = final.predict(test[text_col])
    out = pd.concat([tr, te])
    out["pred_cwes"] = out["pred"].map(lambda c: "" if c == SAFE else c)
    return final, out[["test_name", "split", "cwe", "vulnerable", "pred_cwes"]]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", default=str(ROOT / "data/processed/dataset.csv"))
    p.add_argument("--out-dir", default=str(ROOT / "eval/results"))
    p.add_argument("--model-dir", default=str(ROOT / "ml/models"))
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    df = pd.read_csv(args.dataset)
    df["label"] = np.where(df["vulnerable"], df["cwe"], SAFE)
    df["text"] = df["code_clean"].map(prepare)  # chaînes masquées
    df["text_raw"] = df["code_clean"]
    train = df[df["split"] == "train"].reset_index(drop=True)
    test = df[df["split"] == "test"].reset_index(drop=True)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=args.seed)

    results = []
    for kind, C, ng in CANDIDATES:
        pipe = make_pipeline(kind, C, ng, args.seed)
        s = cross_val_score(pipe, train["text"], train["label"], cv=cv, scoring="f1_macro")
        results.append({"model": kind, "C": C, "ngram_max": ng,
                        "cv_f1_macro": round(float(s.mean()), 4), "cv_std": round(float(s.std()), 4)})
        print(f"{kind:7s} C={C:<5} ngram<= {ng}  CV F1 macro = {s.mean():.3f} +/- {s.std():.3f}")
    best = max(results, key=lambda r: r["cv_f1_macro"])
    print("Meilleur (CV sur train, chaînes masquées) :", best)

    final, preds = fit_and_predict(best, train, test, "text", cv, args.seed)

    # Ablation : mêmes hyperparamètres sur le code brut (chaînes non masquées)
    s_raw = cross_val_score(make_pipeline(best["model"], best["C"], best["ngram_max"], args.seed),
                            train["text_raw"], train["label"], cv=cv, scoring="f1_macro")
    _, preds_raw = fit_and_predict(best, train, test, "text_raw", cv, args.seed)
    print(f"Ablation code brut : CV F1 macro = {s_raw.mean():.3f} (fuite par constantes du Benchmark)")

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    preds.to_csv(out / "ml_predictions.csv", index=False)
    preds_raw.to_csv(out / "ml_raw_predictions.csv", index=False)
    (out / "ml_cv_results.json").write_text(
        json.dumps({"candidates": results, "best": best,
                    "ablation_raw_cv_f1_macro": round(float(s_raw.mean()), 4)}, indent=2),
        encoding="utf-8")
    (out / "ml_top_features.json").write_text(
        json.dumps(top_features(final), indent=2), encoding="utf-8")

    model_dir = Path(args.model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    save_model(final, model_dir / "securecode_ml.joblib",
               meta={"params": best, "classes": list(final.classes_), "masked_strings": True})
    print(f"Modèle et prédictions écrits ({len(preds)} fichiers).")


if __name__ == "__main__":
    main()
