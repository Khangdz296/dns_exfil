"""
tools/dga_model.py
Stage 2 - dga_classifier_agent tool

Runs DGA inference with the pre-trained RandomForest model produced by
tools/train_dga_model.py.

Public APIs:
- score_dga(queries, model_path): in-memory scoring for agent/tool calls.
- score_dga_file(input_path, output_path, model_path): file-based wrapper for
  the Pi chain, writing data/output/dga_scores.json.
"""

from __future__ import annotations

import copy
import json
import logging
import sys
from pathlib import Path
from typing import Any

import joblib
import numpy as np

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = ROOT_DIR / "models" / "dga_model.pkl"
VOWELS = frozenset("aeiou")

_MODEL_CACHE: dict[str, Any] = {}


def _compute_subdomain_features(subdomain: str) -> dict[str, float]:
    """Compute the same subdomain features used during DGA model training."""
    subdomain = str(subdomain or "")
    length = len(subdomain)
    if length == 0:
        return {
            "subdomain_length": 0.0,
            "vowel_ratio": 0.0,
            "consonant_ratio": 0.0,
            "unique_char_ratio": 0.0,
        }

    alpha_chars = [char for char in subdomain.lower() if char.isalpha()]
    alpha_count = len(alpha_chars)
    vowel_count = sum(1 for char in alpha_chars if char in VOWELS)
    consonant_count = alpha_count - vowel_count

    return {
        "subdomain_length": float(length),
        "vowel_ratio": vowel_count / alpha_count if alpha_count else 0.0,
        "consonant_ratio": consonant_count / alpha_count if alpha_count else 0.0,
        "unique_char_ratio": len(set(subdomain.lower())) / length,
    }


def _extract_features(record: dict[str, Any]) -> list[float]:
    """Extract the 7-feature vector expected by models/dga_model.pkl."""
    subdomain_features = _compute_subdomain_features(record.get("subdomain", ""))
    return [
        float(record.get("domain_length", 0)),
        float(record.get("digit_ratio", 0.0)),
        float(record.get("label_count", 0)),
        subdomain_features["subdomain_length"],
        subdomain_features["vowel_ratio"],
        subdomain_features["consonant_ratio"],
        subdomain_features["unique_char_ratio"],
    ]


def _load_model(model_path: str | Path = MODEL_PATH) -> Any:
    """Load the trained model once and cache it by path."""
    path = Path(model_path)
    cache_key = str(path.resolve())
    if cache_key not in _MODEL_CACHE:
        if not path.exists():
            raise FileNotFoundError(f"DGA model not found: {path}")
        _MODEL_CACHE[cache_key] = joblib.load(path)
    return _MODEL_CACHE[cache_key]


def score_dga(
    queries: list[dict[str, Any]],
    model_path: str | Path = MODEL_PATH,
) -> list[dict[str, Any]]:
    """
    Score normalized DNS query records for DGA likelihood.

    Returns a deep copy of the input records with `dga_score` added.
    """
    if not queries:
        raise ValueError("queries must not be empty")

    model = _load_model(model_path)
    results = copy.deepcopy(queries)

    feature_matrix = np.array(
        [_extract_features(record) for record in results],
        dtype=np.float64,
    )
    probability_matrix = model.predict_proba(feature_matrix)
    malicious_scores = probability_matrix[:, 1]

    for record, score in zip(results, malicious_scores):
        record["dga_score"] = round(float(score), 6)

    return results


def _load_queries(input_path: str) -> list[dict[str, Any]] | dict[str, Any]:
    """Load dns_queries.json as a JSON array or {queries: [...]} object."""
    input_file = Path(input_path)
    if not input_file.exists():
        return {"error": "file_not_found", "path": str(input_file)}

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        return {"error": "invalid_json", "path": str(input_file), "detail": str(exc)}
    except OSError as exc:
        return {"error": "read_failed", "path": str(input_file), "detail": str(exc)}

    if isinstance(data, dict) and "queries" in data:
        queries = data["queries"]
    elif isinstance(data, list):
        queries = data
    else:
        return {"error": "invalid_format", "detail": "Expected array or {queries: [...]}"}

    if not isinstance(queries, list):
        return {"error": "invalid_format", "detail": "queries must be a list"}

    return queries


def score_dga_file(
    input_path: str,
    output_path: str,
    model_path: str | Path = MODEL_PATH,
) -> dict[str, Any]:
    """
    File-based wrapper for the Pi chain.

    Reads `dns_queries.json`, writes `dga_scores.json`, and returns a small
    processing summary. Invalid records are skipped so one malformed query does
    not stop the whole parallel Stage 2 branch.
    """
    loaded = _load_queries(input_path)
    if isinstance(loaded, dict) and "error" in loaded:
        return loaded

    valid_queries: list[dict[str, Any]] = []
    skipped = 0
    for query in loaded:
        if not isinstance(query, dict):
            skipped += 1
            continue
        if "query_id" not in query or "domain" not in query:
            skipped += 1
            continue
        valid_queries.append(query)

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    if not valid_queries:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2)
        return {
            "total_processed": 0,
            "skipped_count": skipped,
            "output_file": str(output_file),
        }

    try:
        scored = score_dga(valid_queries, model_path=model_path)
    except FileNotFoundError as exc:
        return {"error": "model_not_found", "path": str(model_path), "detail": str(exc)}
    except ValueError as exc:
        return {"error": "invalid_input", "detail": str(exc)}
    except Exception as exc:
        return {"error": "scoring_failed", "detail": str(exc)}

    rows = [
        {
            "query_id": record["query_id"],
            "domain": record["domain"],
            "label": record.get("label", "unknown"),
            "dga_score": record["dga_score"],
            "source": record.get("source", "unknown"),
        }
        for record in scored
    ]

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)

    log.info("Processed %s DGA queries; skipped %s", len(rows), skipped)
    log.info("Saved -> %s", output_file)

    return {
        "total_processed": len(rows),
        "skipped_count": skipped,
        "output_file": str(output_file),
    }


def _print_usage() -> None:
    print("Usage:")
    print("  python -m tools.dga_model score <input_json> <output_json> [model_path]")
    print()
    print("Example:")
    print("  python -m tools.dga_model score \\")
    print("    data/output/dns_queries.json \\")
    print("    data/output/dga_scores.json \\")
    print("    models/dga_model.pkl")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] != "score":
        _print_usage()
        sys.exit(1)

    if len(sys.argv) < 4:
        _print_usage()
        sys.exit(1)

    cli_input_path = sys.argv[2]
    cli_output_path = sys.argv[3]
    cli_model_path = sys.argv[4] if len(sys.argv) > 4 else MODEL_PATH

    result = score_dga_file(cli_input_path, cli_output_path, cli_model_path)
    if "error" in result:
        print(f"[ERROR] {result}")
        sys.exit(1)

    print(f"[OK] Processed {result['total_processed']} queries")
    print(f"[OK] Skipped {result['skipped_count']} malformed queries")
    print(f"[OK] Output: {result['output_file']}")
