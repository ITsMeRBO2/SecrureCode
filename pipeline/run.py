"""CLI du pipeline complet SecureCode AI."""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

from genai.client import OllamaClient
from pipeline.analyze import analyze, export_csv, export_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyse baseline + ML + GenAI d'un fichier Java.")
    parser.add_argument("source", type=Path)
    parser.add_argument("--model", default="qwen2.5-coder:7b")
    parser.add_argument("--url", default="http://localhost:11434")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--json", type=Path, default=Path("eval/results/pipeline_result.json"))
    parser.add_argument("--csv", type=Path, default=Path("eval/results/pipeline_findings.csv"))
    parser.add_argument("--no-genai", action="store_true", help="Désactive l'appel Ollama.")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)

    generator = None if args.no_genai else OllamaClient(
        base_url=args.url, model=args.model, timeout=args.timeout
    )
    result = analyze(args.source.read_text(encoding="utf-8"), generator=generator)
    export_json(result, args.json)
    export_csv(result, args.csv)
    print(f"Résultats écrits dans {args.json} et {args.csv} (statut: {result['status']}).")


if __name__ == "__main__":
    main()
