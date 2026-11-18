import json
import sys
from urllib.error import HTTPError
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from genai.analyze import analyze, parse_response  # noqa: E402
from genai.client import OllamaClient, OllamaError  # noqa: E402
from genai.validator import java_classpath  # noqa: E402


class FakeGenerator:
    def __init__(self, response):
        self.response = response
        self.prompt = None

    def generate(self, prompt):
        self.prompt = prompt
        return self.response


def _response(**overrides):
    value = {
        "cwes": ["CWE-89"],
        "findings": [
            {
                "cwe": "CWE-89",
                "vulnerable_line": 7,
                "explanation": "La ligne 7 concatène une entrée utilisateur dans SQL.",
            }
        ],
        "fixed_code": "class T {}",
    }
    value.update(overrides)
    return json.dumps(value)


def test_analyze_uses_prompt_and_parses_mocked_response():
    generator = FakeGenerator(_response())
    result = analyze("class T {}", generator)
    assert result["cwes"] == ["CWE-89"]
    assert "class T {}" in generator.prompt


def test_analyze_requires_confirmed_cwes_in_response():
    generator = FakeGenerator(_response())
    with pytest.raises(ValueError, match="CWE manquantes"):
        analyze("class T {}", generator, expected_cwes={"CWE-89", "CWE-79"})


@pytest.mark.parametrize(
    "raw",
    [
        "not-json",
        _response(cwes=["CWE-1"]),
        _response(findings=[{"cwe": "CWE-89", "vulnerable_line": 0, "explanation": "x"}]),
    ],
)
def test_parse_response_rejects_invalid_json(raw):
    with pytest.raises(ValueError):
        parse_response(raw)


def test_parse_response_accepts_multiple_cwes():
    result = parse_response(
        _response(
            cwes=["CWE-89", "CWE-79", "CWE-22"],
            findings=[
                {"cwe": "CWE-89", "vulnerable_line": 1, "explanation": "SQL."},
                {"cwe": "CWE-79", "vulnerable_line": 2, "explanation": "XSS."},
                {"cwe": "CWE-22", "vulnerable_line": 3, "explanation": "Chemin."},
            ],
        )
    )
    assert result["cwes"] == ["CWE-89", "CWE-79", "CWE-22"]


def test_parse_response_accepts_safe_result():
    result = parse_response(
        json.dumps({"cwes": ["SAFE"], "findings": [], "fixed_code": "class Safe {}"})
    )
    assert result["cwes"] == ["SAFE"]


def test_ollama_http_error_includes_server_detail(monkeypatch):
    error = HTTPError(
        "http://localhost:11434/api/generate",
        500,
        "server error",
        {},
        __import__("io").BytesIO(b'{"error":"model crashed"}'),
    )
    monkeypatch.setattr("genai.client.urlopen", lambda request, timeout: (_ for _ in ()).throw(error))
    with pytest.raises(OllamaError, match="model crashed"):
        OllamaClient().generate("test")


def test_ollama_request_limits_repetition(monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"response":"{}"}'

    captured = {}

    def fake_urlopen(request, timeout):
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return Response()

    monkeypatch.setattr("genai.client.urlopen", fake_urlopen)
    OllamaClient().generate("test")
    options = captured["body"]["options"]
    assert options["repeat_penalty"] > 1
    assert options["num_predict"] >= 2048


def test_java_classpath_uses_environment(monkeypatch):
    monkeypatch.setenv("SECURECODE_JAVA_CLASSPATH", r"C:\lib\servlet-api.jar")
    assert java_classpath() == r"C:\lib\servlet-api.jar"


def test_parse_response_cleans_markdown_code_blocks():
    raw = _response(fixed_code="```java\npublic class Fixed {}\n```")
    result = parse_response(raw)
    assert result["fixed_code"] == "public class Fixed {}"


def test_analyze_includes_retry_hint_in_prompt():
    generator = FakeGenerator(_response())
    analyze("class T {}", generator, retry_hint="\n\nATTENTION : javac error")
    assert "ATTENTION : javac error" in generator.prompt


def test_parse_response_handles_markdown_json_wrapper():
    inner = _response()
    wrapped = f"```json\n{inner}\n```"
    result = parse_response(wrapped)
    assert result["cwes"] == ["CWE-89"]


def test_parse_response_handles_literal_newlines_in_strings():
    # Chaîne avec un saut de ligne réel (non échappé en \n) dans fixed_code
    raw = '{\n  "cwes": ["CWE-89"],\n  "findings": [{"cwe": "CWE-89", "vulnerable_line": 1, "explanation": "x"}],\n  "fixed_code": "class T {\n  void foo() {}\n}"\n}'
    result = parse_response(raw)
    assert "class T" in result["fixed_code"]


def test_parse_response_handles_trailing_commas():
    raw = '{\n  "cwes": ["CWE-89",],\n  "findings": [{"cwe": "CWE-89", "vulnerable_line": 1, "explanation": "x",},],\n  "fixed_code": "class T {}",\n}'
    result = parse_response(raw)
    assert result["cwes"] == ["CWE-89"]


def test_ollama_check_connection_success(monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"models": [{"name": "qwen2.5-coder:7b"}]}).encode("utf-8")

    monkeypatch.setattr("genai.client.urlopen", lambda req, timeout: Response())
    client = OllamaClient(base_url="http://127.0.0.1:11434", model="qwen2.5-coder:7b")
    is_ok, msg = client.check_connection()
    assert is_ok is True
    assert "Connecté" in msg


def test_ollama_check_connection_model_missing(monkeypatch):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"models": [{"name": "llama3:8b"}]}).encode("utf-8")

    monkeypatch.setattr("genai.client.urlopen", lambda req, timeout: Response())
    client = OllamaClient(base_url="http://127.0.0.1:11434", model="qwen2.5-coder:7b")
    is_ok, msg = client.check_connection()
    assert is_ok is False
    assert "n'est pas installé" in msg


def test_ollama_check_connection_offline(monkeypatch):
    from urllib.error import URLError

    def raise_err(req, timeout):
        raise URLError("Connection refused")

    monkeypatch.setattr("genai.client.urlopen", raise_err)
    client = OllamaClient(base_url="http://127.0.0.1:11434", model="qwen2.5-coder:7b")
    is_ok, msg = client.check_connection()
    assert is_ok is False
    assert "inaccessible" in msg

