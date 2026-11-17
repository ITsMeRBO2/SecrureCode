import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from genai.analyze import analyze, parse_response  # noqa: E402


class FakeGenerator:
    def __init__(self, response):
        self.response = response
        self.prompt = None

    def generate(self, prompt):
        self.prompt = prompt
        return self.response


def _response(**overrides):
    value = {
        "cwe": "CWE-89",
        "vulnerable_line": 7,
        "explanation": "La ligne 7 concatène une entrée utilisateur dans SQL.",
        "fixed_code": "class T {}",
    }
    value.update(overrides)
    return json.dumps(value)


def test_analyze_uses_prompt_and_parses_mocked_response():
    generator = FakeGenerator(_response())
    result = analyze("class T {}", generator)
    assert result["cwe"] == "CWE-89"
    assert "class T {}" in generator.prompt


@pytest.mark.parametrize("raw", ["not-json", _response(cwe="CWE-1"), _response(vulnerable_line=0)])
def test_parse_response_rejects_invalid_json(raw):
    with pytest.raises(ValueError):
        parse_response(raw)
