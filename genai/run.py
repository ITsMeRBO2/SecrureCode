"""CLI GenAI : analyse un fichier Java et valide le correctif proposé."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from genai.analyze import analyze
from genai.client import OllamaClient
from genai.validator import validate_fix


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyse GenAI locale d'un fichier Java.")
    parser.add_argument("source", type=Path, help="Fichier Java à analyser")
    parser.add_argument("--model", default="qwen2.5-coder:7b")
    parser.add_argument("--url", default="http://localhost:11434")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--output", type=Path, help="Fichier JSON de sortie (sinon stdout)")
    args = parser.parse_args()

    code = args.source.read_text(encoding="utf-8")
    result = analyze(
        code,
        OllamaClient(base_url=args.url, model=args.model, timeout=args.timeout),
    )
    result["validation"] = validate_fix(code, result["fixed_code"])
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
