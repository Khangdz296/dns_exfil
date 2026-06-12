"""
tools/shannon_entropy.py
Stage 2 — entropy_agent tool

Calculates Shannon entropy for DNS subdomains to detect high-randomness
strings typical of DGA domains and DNS exfiltration.
"""

import json
import logging
import math
from collections import Counter
from datetime import datetime
from pathlib import Path

from tools.logging_utils import setup_pipeline_logger

log = setup_pipeline_logger(__name__)


def calculate_subdomain_entropy(subdomain: str) -> float:
    """
    Calculate Shannon entropy of a subdomain string.

    H = -Σ [p(c) × log₂(p(c))] for each unique character c

    Args:
        subdomain: Subdomain string (e.g., "a3f9bc12").

    Returns:
        Shannon entropy (0.0 to ~5.17 for alphanumeric).
        Returns 0.0 for empty or single-character strings.
    """
    if not subdomain or len(subdomain) < 2:
        return 0.0

    # Count character frequencies
    char_counts = Counter(subdomain)
    total_chars = len(subdomain)

    # Calculate entropy
    entropy = 0.0
    for count in char_counts.values():
        probability = count / total_chars
        entropy -= probability * math.log2(probability)

    return entropy


def calculate_entropy(input_path: str, output_path: str) -> dict:
    """
    Calculate entropy scores for all DNS queries.

    Args:
        input_path:  Path to dns_queries.json (Stage 1 output).
        output_path: Path to write entropy_scores.json.

    Returns:
        Dict with processing summary:
        {
            "total_processed": int,
            "high_entropy_count": int,
            "output_file": str
        }
    """
    input_file = Path(input_path)
    if not input_file.exists():
        log.error(f"File not found: {input_path}")
        return {"error": "file_not_found", "path": str(input_path)}

    log.info(f"Reading DNS queries: {input_path}")
    try:
        with open(input_file, "r") as f:
            data = json.load(f)
    except Exception as e:
        log.error(f"Failed to parse JSON: {e}")
        return {"error": "invalid_json", "detail": str(e)}

    # Handle both array and object with "queries" field
    if isinstance(data, dict) and "queries" in data:
        queries = data["queries"]
    elif isinstance(data, list):
        queries = data
    else:
        log.error("Unexpected JSON format (expected array or {queries: [...]})")
        return {"error": "invalid_format", "detail": "No queries found"}

    results = []
    high_entropy_count = 0
    threshold = 3.5

    for query in queries:
        # Validate required fields
        if "query_id" not in query or "domain" not in query:
            log.warning(f"Skipping query missing required fields: {query}")
            continue

        # Extract subdomain (may be empty string)
        subdomain = query.get("subdomain", "")

        # Calculate entropy
        entropy_score = calculate_subdomain_entropy(subdomain)

        # Track high-entropy domains
        if entropy_score > threshold:
            high_entropy_count += 1

        # Build result entry
        results.append({
            "query_id": query["query_id"],
            "domain": query["domain"],
            "subdomain": subdomain,
            "label": query.get("label", "unknown"),
            "entropy_score": round(entropy_score, 4),
            "source": query.get("source", "unknown")
        })

    total_processed = len(results)
    log.info(f"Processed {total_processed} queries")
    log.info(f"High-entropy domains (> {threshold}): {high_entropy_count}")

    # Write output
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    log.info(f"Saved → {output_file}")

    return {
        "total_processed": total_processed,
        "high_entropy_count": high_entropy_count,
        "output_file": str(output_file)
    }


if __name__ == "__main__":
    import sys

    input_path = sys.argv[1] if len(sys.argv) > 1 else "data/output/dns_queries.json"
    output_path = (
        sys.argv[2]
        if len(sys.argv) > 2
        else f"outputs/{datetime.now():%Y%m%d_%H%M%S_%f}/entropy_scores.json"
    )

    result = calculate_entropy(input_path, output_path)

    if "error" not in result:
        print(f"[OK] Processed {result['total_processed']} queries")
        print(f"[OK] Found {result['high_entropy_count']} high-entropy domains")
        print(f"[OK] Output: {result['output_file']}")
    else:
        print(f"[ERROR] {result}")
