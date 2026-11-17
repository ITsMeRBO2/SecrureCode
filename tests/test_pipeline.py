import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.analyze import analyze, export_csv, export_json  # noqa: E402


class FakeGenerator:
    def generate(self, prompt):
        return json.dumps(
            {
                "cwe": "CWE-89",
                "vulnerable_line": 1,
                "explanation": "Entrée non paramétrée.",
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
    assert {finding["approach"] for finding in result["findings"]} == {"baseline", "genai"}
    assert result["genai"]["validation"]["validated"] is True

    json_path, csv_path = tmp_path / "result.json", tmp_path / "findings.csv"
    export_json(result, json_path)
    export_csv(result, csv_path)
    assert json.loads(json_path.read_text(encoding="utf-8"))["status"] == "ok"
    assert csv_path.read_text(encoding="utf-8").count("\n") == 3


def test_pipeline_reports_genai_error_without_hiding_other_results():
    class BrokenGenerator:
        def generate(self, prompt):
            raise RuntimeError("Ollama indisponible")

    result = analyze(
        "class T {}",
        generator=BrokenGenerator(),
        model_path=ROOT / "ml/models/securecode_ml.joblib",
        baseline_runner=lambda source: [],
    )
    assert result["status"] == "partial_error"
    assert result["genai"]["status"] == "error"
    assert result["errors"][0]["error"] == "Ollama indisponible"
