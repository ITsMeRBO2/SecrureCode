import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.streamlit_app import findings_csv, numbered_code  # noqa: E402


def test_numbered_code_preserves_line_numbers():
    assert numbered_code("first\nsecond") == "   1 | first\n   2 | second"


def test_findings_csv_contains_validation_status():
    output = findings_csv(
        {
            "findings": [
                {
                    "approach": "genai",
                    "status": "detected",
                    "cwe": "CWE-89",
                    "line": 4,
                    "confidence": None,
                    "explanation": "SQL non paramétré.",
                    "validation": {"validated": True},
                }
            ]
        }
    )
    assert "CWE-89" in output
    assert "True" in output
