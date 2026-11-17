import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "data"))
from prepare_data import add_split, clean_code, strip_comments  # noqa: E402

SAMPLE = '''/** licence */
package org.owasp.benchmark.testcode;

@WebServlet(value = "/sqli-00/BenchmarkTest00008")
public class BenchmarkTest00008 extends HttpServlet {
    // commentaire
    String url = "http://exemple.com"; /* bloc */
}
'''


def test_strip_comments_keeps_strings():
    out = strip_comments(SAMPLE)
    assert "http://exemple.com" in out
    assert "commentaire" not in out and "licence" not in out


def test_clean_code_removes_label_leaks():
    out = clean_code(SAMPLE)
    assert "sqli" not in out
    assert "BenchmarkTest00008" not in out
    assert "@WebServlet" not in out
    assert "TestCase" in out


def test_clean_code_removes_category_paths():
    out = clean_code('request.getRequestDispatcher("/pathtraver-00/BenchmarkTest00001.html");')
    assert "pathtraver" not in out and "sqli" not in out


def test_split_is_disjoint_and_stratified():
    rows = []
    for cwe in ["CWE-89", "CWE-79"]:
        for vuln in [True, False]:
            for i in range(50):
                rows.append({"test_name": f"{cwe}-{vuln}-{i}", "cwe": cwe, "vulnerable": vuln})
    df = add_split(pd.DataFrame(rows), test_size=0.2, seed=42)
    train = set(df[df.split == "train"].test_name)
    test = set(df[df.split == "test"].test_name)
    assert train.isdisjoint(test)
    assert len(test) == 40
    assert df[df.split == "test"].groupby(["cwe", "vulnerable"]).size().eq(10).all()
