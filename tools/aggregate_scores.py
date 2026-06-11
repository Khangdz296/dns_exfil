"""
tools/aggregate_scores.py
Stage 3 - orchestrator_agent tool

Aggregates scores from 3 Stage-2 agents (entropy, DGA, embedding)
using weighted average and applies threshold for verdict.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict

from tools.logging_utils import setup_pipeline_logger

log = setup_pipeline_logger(__name__)

# Weights (must sum to 1.0)
ENTROPY_WEIGHT = 0.3
DGA_WEIGHT = 0.4
EMBED_WEIGHT = 0.3

# Entropy is measured over alphanumeric DNS labels; log2(36) ~= 5.17.
MAX_ENTROPY = 5.17

# Threshold for suspected exfiltration
THRESHOLD = 0.6
DGA_HIGH_THRESHOLD = 0.75
ENTROPY_EMBED_ENTROPY_THRESHOLD = 0.65
ENTROPY_EMBED_EMBED_THRESHOLD = 0.85

REQUIRED_SCORE_FIELDS = {
    "entropy": "entropy_score",
    "dga": "dga_score",
    "embed": "embed_score",
}


def _load_json_array(path: Path, name: str) -> list[dict[str, Any]] | dict[str, Any]:
    """Load one Stage-2 score file and validate that it contains a JSON array."""
    if not path.exists():
        log.error(f"{name} file not found: {path}")
        return {"error": f"{name}_not_found", "path": str(path)}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        log.error(f"{name} file is not valid JSON: {e}")
        return {"error": "invalid_json", "stage": name, "path": str(path), "detail": str(e)}
    except OSError as e:
        log.error(f"Failed to read {name} file: {e}")
        return {"error": "read_failed", "stage": name, "path": str(path), "detail": str(e)}

    if not isinstance(data, list):
        log.error(f"{name} file must contain a JSON array")
        return {"error": "invalid_format", "stage": name, "path": str(path)}

    return data


def _as_float(value: Any) -> float | None:
    """Convert score values to float; return None when a value is not numeric."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _index_scores(
    records: list[dict[str, Any]],
    name: str,
) -> dict[int, dict[str, Any]] | dict[str, Any]:
    """Index score records by query_id and skip malformed rows."""
    score_field = REQUIRED_SCORE_FIELDS[name]
    indexed: dict[int, dict[str, Any]] = {}
    skipped = 0

    for record in records:
        if not isinstance(record, dict):
            skipped += 1
            continue

        if "query_id" not in record or score_field not in record:
            skipped += 1
            log.warning(f"Skipping malformed {name} record: {record}")
            continue

        try:
            query_id = int(record["query_id"])
        except (TypeError, ValueError):
            skipped += 1
            log.warning(f"Skipping {name} record with invalid query_id: {record}")
            continue

        score_value = _as_float(record.get(score_field))
        if score_value is None:
            skipped += 1
            log.warning(f"Skipping {name} record with invalid {score_field}: {record}")
            continue

        if query_id in indexed:
            log.warning(f"Duplicate query_id={query_id} in {name}; keeping first record")
            continue

        record = dict(record)
        record[score_field] = score_value
        indexed[query_id] = record

    if skipped:
        log.info(f"Skipped {skipped} malformed {name} records")

    return indexed


def load_scores(entropy_path: str, dga_path: str, embed_path: str) -> Dict[int, Dict[str, Any]]:
    """
    Load and merge scores from 3 files by query_id.

    Only query_ids present in all 3 score files are returned. This keeps the
    orchestrator output faithful to the parallel Stage-2 contract instead of
    silently scoring missing branches as zero.
    """
    files = {
        "entropy": Path(entropy_path),
        "dga": Path(dga_path),
        "embed": Path(embed_path),
    }

    indexed: dict[str, dict[int, dict[str, Any]]] = {}

    for name, path in files.items():
        data = _load_json_array(path, name)
        if isinstance(data, dict) and "error" in data:
            return data

        score_index = _index_scores(data, name)
        if isinstance(score_index, dict) and "error" in score_index:
            return score_index
        indexed[name] = score_index

    common_query_ids = (
        set(indexed["entropy"])
        & set(indexed["dga"])
        & set(indexed["embed"])
    )

    missing_count = (
        len(set(indexed["entropy"]) | set(indexed["dga"]) | set(indexed["embed"]))
        - len(common_query_ids)
    )
    if missing_count:
        log.warning(f"Skipped {missing_count} query_ids missing one or more score types")

    merged: dict[int, dict[str, Any]] = {}

    for query_id in sorted(common_query_ids):
        entropy = indexed["entropy"][query_id]
        dga = indexed["dga"][query_id]
        embed = indexed["embed"][query_id]

        merged[query_id] = {
            "query_id": query_id,
            "domain": entropy.get("domain") or dga.get("domain") or embed.get("domain", ""),
            "label": entropy.get("label") or dga.get("label") or embed.get("label", "unknown"),
            "source": entropy.get("source") or dga.get("source") or embed.get("source", "unknown"),
            "entropy_score": float(entropy.get("entropy_score", 0.0)),
            "dga_score": float(dga.get("dga_score", 0.0)),
            "embed_score": float(embed.get("embed_score", 0.0)),
        }

    return merged


def _build_risk_reasons(
    entropy_norm: float,
    dga_score: float,
    embed_score: float,
    combined_score: float,
) -> list[str]:
    """Explain which detection signals contributed to a suspicious verdict."""
    reasons: list[str] = []

    if combined_score >= THRESHOLD:
        reasons.append("combined_score_above_threshold")
    if dga_score >= DGA_HIGH_THRESHOLD:
        reasons.append("high_dga_probability")
    if entropy_norm >= ENTROPY_EMBED_ENTROPY_THRESHOLD:
        reasons.append("high_entropy")
    if embed_score >= ENTROPY_EMBED_EMBED_THRESHOLD:
        reasons.append("far_from_benign_embedding")
    if (
        entropy_norm >= ENTROPY_EMBED_ENTROPY_THRESHOLD
        and embed_score >= ENTROPY_EMBED_EMBED_THRESHOLD
    ):
        reasons.append("entropy_embedding_agreement")

    return reasons


def _is_suspected(
    entropy_norm: float,
    dga_score: float,
    embed_score: float,
    combined_score: float,
) -> bool:
    """Hybrid verdict rule: weighted score plus high-confidence fallback rules."""
    return (
        combined_score >= THRESHOLD
        or dga_score >= DGA_HIGH_THRESHOLD
        or (
            entropy_norm >= ENTROPY_EMBED_ENTROPY_THRESHOLD
            and embed_score >= ENTROPY_EMBED_EMBED_THRESHOLD
        )
    )


def aggregate_scores(
    entropy_path: str,
    dga_path: str,
    embed_path: str,
    output_path: str,
) -> Dict[str, Any]:
    """
    Aggregate scores from 3 Stage-2 agents using weighted average.

    Combined score = 0.3*entropy_norm + 0.4*dga + 0.3*embed.
    Verdict uses the weighted score plus high-confidence fallback rules.
    """
    log.info("Loading scores from Stage 2 agents...")
    merged = load_scores(entropy_path, dga_path, embed_path)

    if isinstance(merged, dict) and "error" in merged:
        return merged

    results = []
    suspected_count = 0

    for query_id, data in merged.items():
        entropy_norm = min(max(data["entropy_score"] / MAX_ENTROPY, 0.0), 1.0)
        dga = min(max(data["dga_score"], 0.0), 1.0)
        embed = min(max(data["embed_score"], 0.0), 1.0)

        combined = (
            ENTROPY_WEIGHT * entropy_norm
            + DGA_WEIGHT * dga
            + EMBED_WEIGHT * embed
        )

        verdict = "suspected" if _is_suspected(entropy_norm, dga, embed, combined) else "benign"
        risk_reasons = _build_risk_reasons(entropy_norm, dga, embed, combined)
        if verdict == "suspected":
            suspected_count += 1

        results.append({
            "query_id": query_id,
            "domain": data["domain"],
            "label": data["label"],
            "source": data["source"],
            "entropy_score": round(data["entropy_score"], 4),
            "entropy_norm": round(entropy_norm, 4),
            "dga_score": round(dga, 6),
            "embed_score": round(embed, 4),
            "combined_score": round(combined, 4),
            "verdict": verdict,
            "risk_reasons": risk_reasons,
        })

    results.sort(key=lambda x: x["combined_score"], reverse=True)

    total = len(results)
    suspected_percent = (suspected_count / total * 100) if total else 0.0
    log.info(f"Processed {total} queries")
    log.info(f"Suspected exfiltration: {suspected_count} ({suspected_percent:.1f}%)")

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    log.info(f"Saved -> {output_file}")

    return {
        "total_processed": total,
        "suspected_count": suspected_count,
        "output_file": str(output_file),
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 5:
        print("Usage:")
        print("  python aggregate_scores.py <entropy_json> <dga_json> <embed_json> <output_json>")
        print()
        print("Example:")
        print("  python aggregate_scores.py \\")
        print("    data/output/entropy_scores.json \\")
        print("    data/output/dga_scores.json \\")
        print("    data/output/embed_scores.json \\")
        print("    data/output/scores.json")
        sys.exit(1)

    result = aggregate_scores(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])

    if "error" not in result:
        print(f"[OK] Processed {result['total_processed']} queries")
        print(f"[OK] Suspected: {result['suspected_count']}")
        print(f"[OK] Output: {result['output_file']}")
    else:
        print(f"[ERROR] {result}")
        sys.exit(1)
