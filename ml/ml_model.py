"""Modèle ML : TF-IDF sur les tokens du code Java + classificateur linéaire.

Classes : CWE-89, CWE-79, CWE-22 (fichier vulnérable) ou SAFE (aucune faille ciblée).
Le pipeline n'utilise que des composants scikit-learn (pas de fonction maison dans le
pickle), donc le modèle sauvegardé se recharge n'importe où.
"""
from __future__ import annotations

import re

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

SAFE = "SAFE"
# identifiants Java | nombres | tout symbole isolé (+ ( ) ; " . etc.)
TOKEN_PATTERN = r"[A-Za-z_][A-Za-z0-9_]*|\d+|[^\sA-Za-z0-9_]"


_STRING = re.compile(r'"(?:\\.|[^"\\])*"')


def mask_string_literals(code: str) -> str:
    """Remplace le contenu des chaînes par "STR".

    Le Benchmark génère ses cas sûrs avec des constantes absurdes ("alsosafe",
    "barbarians_at_the_gate"...) : un modèle qui les lit « triche » (fuite de signature).
    """
    return _STRING.sub('"STR"', code)


def prepare(code: str, mask: bool = True) -> str:
    """Prétraitement appliqué avant le TF-IDF, à l'entraînement ET à l'inférence."""
    return mask_string_literals(code) if mask else code


def make_pipeline(kind: str = "logreg", C: float = 10.0, ngram_max: int = 2, seed: int = 42) -> Pipeline:
    vec = TfidfVectorizer(
        token_pattern=TOKEN_PATTERN,
        lowercase=False,
        ngram_range=(1, ngram_max),
        sublinear_tf=True,
        min_df=2,
    )
    if kind == "logreg":
        clf = LogisticRegression(C=C, max_iter=2000, random_state=seed)
    elif kind == "linsvc":
        clf = LinearSVC(C=C, random_state=seed)
    else:
        raise ValueError(f"modèle inconnu : {kind}")
    return Pipeline([("tfidf", vec), ("clf", clf)])


def explain(pipe: Pipeline, code: str, top_k: int = 8, mask: bool = True) -> dict:
    """Prédit et explique : tokens/n-grammes qui ont le plus poussé vers la classe prédite."""
    vec, clf = pipe.named_steps["tfidf"], pipe.named_steps["clf"]
    x = vec.transform([prepare(code, mask)])
    scores = clf.decision_function(x)[0]
    k = int(np.argmax(scores))
    label = str(clf.classes_[k])
    contrib = x.multiply(clf.coef_[k]).tocoo()
    names = vec.get_feature_names_out()
    ranked = sorted(zip(contrib.col, contrib.data), key=lambda t: -t[1])[:top_k]
    e = np.exp(scores - scores.max())
    return {
        "label": label,
        "cwe": None if label == SAFE else label,
        "confidence": round(float((e / e.sum())[k]), 3),  # softmax des scores, non calibré
        "top_tokens": [(str(names[i]), round(float(v), 4)) for i, v in ranked if v > 0],
    }


def save_model(pipe: Pipeline, path, meta: dict | None = None) -> None:
    joblib.dump({"pipeline": pipe, "meta": meta or {}}, path)


def load_model(path) -> Pipeline:
    return joblib.load(path)["pipeline"]
