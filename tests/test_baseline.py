import shutil
import sys
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "baseline"))
sys.path.insert(0, str(ROOT / "eval"))
from evaluate import per_cwe_metrics  # noqa: E402
from run_semgrep import repair_mojibake  # noqa: E402

needs_semgrep = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep absent")

SQLI = """import javax.servlet.http.*;
public class T extends HttpServlet {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String id = request.getParameter("id");
    java.sql.Statement st = conn.createStatement();
    st.executeQuery("SELECT * FROM users WHERE id=" + id);
  }
}
"""

SQLI_FIXED = """import javax.servlet.http.*;
public class T extends HttpServlet {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String id = request.getParameter("id");
    java.sql.PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id=?");
    ps.setString(1, id);
    ps.executeQuery();
  }
}
"""

XSS = """import javax.servlet.http.*;
public class T extends HttpServlet {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String name = request.getParameter("name");
    response.getWriter().println("Hello " + name);
  }
}
"""

PATH = """import javax.servlet.http.*;
public class T extends HttpServlet {
  public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String f = request.getParameter("f");
    java.io.File file = new java.io.File("/data", f);
  }
}
"""


def _cwes(tmp_path, name, code):
    from run_semgrep import run_semgrep

    p = tmp_path / f"{name}.java"
    p.write_text(code, encoding="utf-8")
    return {f["cwe"] for f in run_semgrep(p)}


@needs_semgrep
def test_detects_sqli(tmp_path):
    assert "CWE-89" in _cwes(tmp_path, "sqli", SQLI)


@needs_semgrep
def test_prepared_statement_not_flagged(tmp_path):
    assert "CWE-89" not in _cwes(tmp_path, "fixed", SQLI_FIXED)


@needs_semgrep
def test_detects_xss(tmp_path):
    assert "CWE-79" in _cwes(tmp_path, "xss", XSS)


@needs_semgrep
def test_detects_path_traversal(tmp_path):
    assert "CWE-22" in _cwes(tmp_path, "path", PATH)


def test_per_cwe_metrics_counts():
    df = pd.DataFrame(
        {
            "cwe": ["CWE-89", "CWE-89", "CWE-79", "CWE-22"],
            "vulnerable": [True, False, True, True],
            "pred_cwes": ["CWE-89", "CWE-89", "", "CWE-22"],
        }
    )
    m = per_cwe_metrics(df).set_index("CWE")
    assert (m.loc["CWE-89", "TP"], m.loc["CWE-89", "FP"]) == (1, 1)
    assert m.loc["CWE-89", "precision"] == 0.5 and m.loc["CWE-89", "recall"] == 1.0
    assert m.loc["CWE-79", "FN"] == 1
    assert m.loc["CWE-22", "F1"] == 1.0


def test_repair_mojibake_only_when_needed():
    assert repair_mojibake("DonnÃ©e utilisateur") == "Donnée utilisateur"
    assert repair_mojibake("Texte déjà correct") == "Texte déjà correct"
