"""
tools/aggregate_scores.py
Stage 3 — orchestrator_agent tool

Aggregates scores from 3 Stage-2 agents (entropy, DGA, embedding)
using weighted average and applies threshold for verdict.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

# Weights (must sum to 1.0)
ENTROPY_WEIGHT = 0.3
DGA_WEIGHT = 0.4
EMBED_WEIGHT = 0.3

# Threshold for suspected exfiltration
THRESHOLD = 0.6


def load_scores(entropy_path: str, dga_path: str, embed_path: str) -> Dict[int, Dict]:
    """Load and merge scores from 3 files by query_id."""
    files = {
        "entropy": Path(entropy_path),
        "dga": Path(dga_path),
        "embed": Path(embed_path)
    }

    for name, path in files.items():
        if not path.exists():
            log.error(f"{name} file not found: {path}")
            return {"error": f"{name}_not_found", "path": str(path)}

    merged = {}

    for name, path in files.items():
        with open(path, "r") as f:
            data = json.load(f)

        for record in data:
            qid = record["query_id"]
            if qid not in merged:
                merged[qid] = {
                    "query_id": qid,
                    "domain": record["domain"],
                    "label": record.get("label", "unknown")
                }

            if name == "entropy":
                merged[qid]["entropy_score"] = record["entropy_score"]
            elif name == "dga":
                merged[qid]["dga_score"] = record["dga_score"]
            elif name == "embed":
                merged[qid]["embed_score"] = record["embed_score"]

    return merged


def aggregate_scores(
    entropy_path: str,
    dga_path: str,
    embed_path: str,
    output_path: str
) -> Dict:
    """
    Aggregate scores from 3 Stage-2 agents using weighted average.

    Combined score = 0.3*entropy + 0.4*dga + 0.3*embed
    Verdict: combined_score > 0.6 → suspected exfiltration
    """
    log.info("Loading scores from Stage 2 agents...")
    merged = load_scores(entropy_path, dga_path, embed_path)

    if isinstance(merged, dict) and "error" in merged:
        return merged

    results = []
    suspected_count = 0

    for qid, data in merged.items():
        # Normalize entropy (0-5.17 → 0-1.0)
        entropy_norm = min(data.get("entropy_score", 0) / 5.17, 1.0)
        dga = data.get("dga_score", 0)
        embed = data.get("embed_score", 0)

        # Weighted average
        combined = (
            ENTROPY_WEIGHT * entropy_norm +
            DGA_WEIGHT * dga +
            EMBED_WEIGHT * embed
        )

        verdict = "suspected" if combined > THRESHOLD else "benign"
        if verdict == "suspected":
            suspected_count += 1

        results.append({
            "query_id": qid,
            "domain": data["domain"],
            "label": data["label"],
            "entropy_score": data.get("entropy_score", 0),
            "dga_score": dga,
            "embed_score": embed,
            "combined_score": round(combined, 4),
            "verdict": verdict
        })

    # Sort by combined_score descending
    results.sort(key=lambda x: x["combined_score"], reverse=True)

    log.info(f"Processed {len(results)} queries")
    log.info(f"Suspected exfiltration: {suspected_count} ({suspected_count/len(results)*100:.1f}%)")

    # Write output
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    log.info(f"Saved → {output_file}")

    return {
        "total_processed": len(results),
        "suspected_count": suspected_count,
        "output_file": str(output_file)
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
