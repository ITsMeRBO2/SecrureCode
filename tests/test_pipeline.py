import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.analyze import analyze, export_csv, export_json, looks_like_javascript  # noqa: E402
from pipeline.signatures import detect_signatures  # noqa: E402


class FakeGenerator:
    def generate(self, prompt):
        return json.dumps(
            {
                "cwes": ["CWE-89"],
                "findings": [
                    {
                        "cwe": "CWE-89",
                        "vulnerable_line": 1,
                        "explanation": "Entrée non paramétrée.",
                    }
                ],
                "fixed_code": "public class Fixed {}",
            }
        )


def fake_baseline(_source):
    return [
        {
            "cwe": "CWE-89",
            "line_start": 3,
            "message": "SQL injection détectée.",
        }
    ]


def test_pipeline_aggregates_three_approaches(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "pipeline.analyze.validate_fix",
        lambda code, fixed: {"validated": True},
    )
    result = analyze(
        "class T {}",
        generator=FakeGenerator(),
        model_path=ROOT / "ml/models/securecode_ml.joblib",
        baseline_runner=fake_baseline,
    )
    assert result["status"] == "ok"
    assert result["ml"]["status"] == "ok"
    # Les findings de la liste principale sont uniquement issus de la baseline
    assert {finding["approach"] for finding in result["findings"]} == {"baseline"}
    # Le finding baseline a été enrichi par l'explication GenAI
    assert result["findings"][0].get("genai_explanation") == "Entrée non paramétrée."
    assert result["genai"]["validation"]["validated"] is True

    json_path, csv_path = tmp_path / "result.json", tmp_path / "findings.csv"
    export_json(result, json_path)
    export_csv(result, csv_path)
    assert json.loads(json_path.read_text(encoding="utf-8"))["status"] == "ok"
    assert csv_path.read_text(encoding="utf-8").count("\n") == 2


def test_pipeline_reports_genai_error_without_hiding_other_results():
    class BrokenGenerator:
        def generate(self, prompt):
            raise RuntimeError("Ollama indisponible")

    result = analyze(
        "class T {}",
        generator=BrokenGenerator(),
        model_path=ROOT / "ml/models/securecode_ml.joblib",
        baseline_runner=fake_baseline,
    )
    assert result["status"] == "partial_error"
    assert result["genai"]["status"] == "error"
    assert result["errors"][0]["error"] == "Ollama indisponible"


def test_pipeline_does_not_turn_ml_advisory_into_safe_code_finding():
    result = analyze(
        "public class SafeExample { void run() { int value = 1; } }",
        generator=None,
        model_path=ROOT / "ml/models/securecode_ml.joblib",
        baseline_runner=lambda source: [],
    )
    assert result["status"] == "ok"
    assert result["findings"] == []


def test_pipeline_does_not_trust_genai_alone_on_safe_code(monkeypatch):
    class HallucinatingGenerator:
        def generate(self, prompt):
            return json.dumps(
                {
                    "cwes": ["CWE-79"],
                    "findings": [
                        {
                            "cwe": "CWE-79",
                            "vulnerable_line": 1,
                            "explanation": "Faux finding.",
                        }
                    ],
                    "fixed_code": "public class SafeExample {}",
                }
            )

    monkeypatch.setattr(
        "pipeline.analyze.validate_fix",
        lambda code, fixed: {"validated": True},
    )
    result = analyze(
        "public class SafeExample { void run() { int value = 1; } }",
        generator=HallucinatingGenerator(),
        model_path=ROOT / "ml/models/securecode_ml.joblib",
        baseline_runner=lambda source: [],
    )
    # Sur code sûr sans détection baseline, aucun finding n'est ajouté
    # et GenAI n'est pas appelé (status: skipped)
    assert result["findings"] == []
    assert result["genai"]["status"] == "skipped"
    assert result["overall"] == "safe"


def test_pipeline_rejects_javascript_instead_of_reporting_safe():
    code = "const query = `SELECT * FROM users WHERE id=${req.body.id}`;"
    assert looks_like_javascript(code)
    result = analyze(code)
    assert result["status"] == "unsupported_language"
    assert not result["findings"]
    assert result["ml"]["status"] == "skipped"


def test_pipeline_accepts_java_servlet_class_names():
    code = "public class VulnerableCommentServlet extends HttpServlet {}"
    assert not looks_like_javascript(code)


def test_signature_detector_finds_all_three_cwes():
    code = """
    void run(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String id = request.getParameter("id");
        String comment = request.getParameter("comment");
        String filename = request.getParameter("file");
        Statement st = conn.createStatement();
        st.executeQuery("SELECT * FROM users WHERE id=" + id);
        response.getWriter().println("<p>" + comment + "</p>");
        File file = new File(BASE_DIR + filename);
    }
    """
    assert {finding["cwe"] for finding in detect_signatures(code)} == {
        "CWE-89",
        "CWE-79",
        "CWE-22",
    }


def test_signature_detector_finds_sql_built_before_statement_execution():
    code = """
    boolean login(String username, String password) throws SQLException {
        String query = "SELECT * FROM users WHERE username = '" + username
                     + "' AND password = '" + password + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(query).next();
    }
    """
    findings = detect_signatures(code)
    assert [finding["cwe"] for finding in findings] == ["CWE-89"]


def test_signature_detector_does_not_flag_safe_patterns():
    code = """
    void run(HttpServletRequest request, HttpServletResponse response) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id=?");
        ps.setString(1, request.getParameter("id"));
        response.getWriter().println(encodeForHTML(request.getParameter("comment")));
        Path base = Paths.get(BASE_DIR).toRealPath();
        Path file = base.resolve(request.getParameter("file")).normalize();
        if (!file.startsWith(base)) throw new SecurityException();
    }
    """
    assert detect_signatures(code) == []


def test_signature_detector_does_not_flag_constant_sql_assembly():
    code = """
    void run() throws SQLException {
        String query = "SELECT " + "id FROM users";
        Statement stmt = conn.createStatement();
        stmt.executeQuery(query);
    }
    """
    assert detect_signatures(code) == []


def test_pipeline_keeps_all_genai_cwes(monkeypatch):
    class MultiGenerator:
        def generate(self, prompt):
            return json.dumps(
                {
                    "cwes": ["CWE-89", "CWE-79", "CWE-22"],
                    "findings": [
                        {"cwe": "CWE-89", "vulnerable_line": 1, "explanation": "SQL."},
                        {"cwe": "CWE-79", "vulnerable_line": 2, "explanation": "XSS."},
                        {"cwe": "CWE-22", "vulnerable_line": 3, "explanation": "Chemin."},
                    ],
                    "fixed_code": "public class Fixed {}",
                }
            )

    monkeypatch.setattr(
        "pipeline.analyze.validate_fix",
        lambda code, fixed: {"validated": True},
    )
    result = analyze(
        """
        void run(HttpServletRequest request, HttpServletResponse response) throws Exception {
            String id = request.getParameter("id");
            String comment = request.getParameter("comment");
            String filename = request.getParameter("file");
            Statement st = conn.createStatement();
            st.executeQuery("SELECT * FROM users WHERE id=" + id);
            response.getWriter().println("<p>" + comment + "</p>");
            File file = new File(BASE_DIR + filename);
        }
        """,
        generator=MultiGenerator(),
        model_path=ROOT / "ml/models/securecode_ml.joblib",
        baseline_runner=lambda source: [
            {"cwe": "CWE-89", "line": 8, "line_start": 8, "message": "SQL", "severity": "ERROR"},
            {"cwe": "CWE-79", "line": 9, "line_start": 9, "message": "XSS", "severity": "ERROR"},
            {"cwe": "CWE-22", "line": 10, "line_start": 10, "message": "Path", "severity": "ERROR"},
        ],
    )
    # Les findings sont issus de la baseline (aucun finding 'genai' concurrent)
    assert all(f["approach"] == "baseline" for f in result["findings"])
    assert {f["cwe"] for f in result["findings"]} == {"CWE-89", "CWE-79", "CWE-22"}
    # Les explications GenAI ont enrichi chaque finding baseline
    by_cwe = {f["cwe"]: f["genai_explanation"] for f in result["findings"]}
    assert by_cwe["CWE-89"] == "SQL."
    assert by_cwe["CWE-79"] == "XSS."
    assert by_cwe["CWE-22"] == "Chemin."
    assert set(result["genai"]["confirmed_cwes"]) == {"CWE-89", "CWE-79", "CWE-22"}


def test_pipeline_retries_on_javac_failure(monkeypatch):
    attempts = []

    class RetryGenerator:
        def generate(self, prompt):
            attempts.append(prompt)
            return json.dumps(
                {
                    "cwes": ["CWE-89"],
                    "findings": [
                        {"cwe": "CWE-89", "vulnerable_line": 1, "explanation": "SQL."}
                    ],
                    "fixed_code": f"public class Fixed{len(attempts)} {{}}",
                }
            )

    validation_calls = []

    def mock_validate(code, fixed):
        validation_calls.append(fixed)
        if len(validation_calls) == 1:
            return {
                "validated": False,
                "javac": {"ok": False, "message": "syntax error line 1"},
                "baseline": {"ok": True, "message": ""},
                "ml": {"ok": True, "message": ""},
            }
        return {
            "validated": True,
            "javac": {"ok": True, "message": ""},
            "baseline": {"ok": True, "message": ""},
            "ml": {"ok": True, "message": ""},
        }

    monkeypatch.setattr("pipeline.analyze.validate_fix", mock_validate)
    result = analyze(
        "class T {}",
        generator=RetryGenerator(),
        model_path=ROOT / "ml/models/securecode_ml.joblib",
        baseline_runner=fake_baseline,
    )
    assert len(validation_calls) == 2
    assert "syntax error line 1" in attempts[1]
    assert result["genai"]["validation"]["validated"] is True


def test_pipeline_retries_on_invalid_json_response(monkeypatch):
    attempts = []

    class InvalidJsonThenValidGenerator:
        def generate(self, prompt):
            attempts.append(prompt)
            if len(attempts) == 1:
                return "ceci n'est pas un json valide"
            return json.dumps(
                {
                    "cwes": ["CWE-89"],
                    "findings": [
                        {"cwe": "CWE-89", "vulnerable_line": 1, "explanation": "SQL."}
                    ],
                    "fixed_code": "public class Fixed {}",
                }
            )

    monkeypatch.setattr(
        "pipeline.analyze.validate_fix",
        lambda code, fixed: {"validated": True, "javac": {"ok": True}},
    )
    result = analyze(
        "class T {}",
        generator=InvalidJsonThenValidGenerator(),
        model_path=ROOT / "ml/models/securecode_ml.joblib",
        baseline_runner=fake_baseline,
    )
    assert len(attempts) == 2
    assert result["genai"]["status"] == "ok"
    assert result["genai"]["cwes"] == ["CWE-89"]
