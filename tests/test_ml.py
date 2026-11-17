import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ml"))
from ml_model import SAFE, explain, load_model, make_pipeline, mask_string_literals  # noqa: E402


def test_mask_string_literals():
    out = mask_string_literals('String a = "alsosafe"; String b = "say \\"hi\\"";')
    assert "alsosafe" not in out and "hi" not in out
    assert out.count('"STR"') == 2


def _toy():
    X, y = [], []
    for v in ["id", "uid", "name", "key"]:
        X.append(f'String {v} = r.getParameter("{v}"); st.executeQuery("select " + {v});')
        y.append("CWE-89")
        X.append(f'String {v} = r.getParameter("{v}"); response.getWriter().println({v});')
        y.append("CWE-79")
        X.append(f'String {v} = r.getParameter("{v}"); ps.setString(1, {v}); ps.executeQuery();')
        y.append(SAFE)
    return X, y


def test_pipeline_fit_predict_explain():
    X, y = _toy()
    pipe = make_pipeline("logreg", C=100, ngram_max=2).fit(X, y)
    res = explain(pipe, X[0])
    assert res["label"] == "CWE-89" and res["cwe"] == "CWE-89"
    assert 0 < res["confidence"] <= 1
    assert res["top_tokens"], "l'explication doit citer des tokens"
    assert explain(pipe, X[2])["cwe"] is None  # SAFE -> pas de CWE


def test_saved_model_loads_if_present():
    path = ROOT / "ml/models/securecode_ml.joblib"
    if not path.exists():
        pytest.skip("modèle non entraîné (python ml/train.py)")
    pipe = load_model(path)
    assert set(pipe.named_steps["clf"].classes_) == {"CWE-22", "CWE-79", "CWE-89", SAFE}
