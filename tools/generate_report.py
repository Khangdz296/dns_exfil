"""
tools/generate_report.py
Stage 3 - report_agent tool

Generates a markdown security report from aggregated scores.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

THRESHOLD = 0.6
DGA_HIGH_THRESHOLD = 0.75
ENTROPY_EMBED_ENTROPY_THRESHOLD = 0.65
ENTROPY_EMBED_EMBED_THRESHOLD = 0.85


def _load_scores(input_path: str) -> list[dict[str, Any]] | dict[str, Any]:
    """Load aggregated scores and validate that the input is a JSON array."""
    input_file = Path(input_path)
    if not input_file.exists():
        log.error(f"File not found: {input_path}")
        return {"error": "file_not_found", "path": str(input_path)}

    log.info(f"Reading scores: {input_path}")
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            scores = json.load(f)
    except json.JSONDecodeError as e:
        log.error(f"Invalid JSON in scores file: {e}")
        return {"error": "invalid_json", "path": str(input_path), "detail": str(e)}
    except OSError as e:
        log.error(f"Failed to read scores file: {e}")
        return {"error": "read_failed", "path": str(input_path), "detail": str(e)}

    if not isinstance(scores, list):
        log.error("Scores file must contain a JSON array")
        return {"error": "invalid_format", "path": str(input_path)}

    return scores


def _score_value(record: dict[str, Any], field: str) -> float:
    """Return a numeric score value with safe fallback for report formatting."""
    try:
        return float(record.get(field, 0.0))
    except (TypeError, ValueError):
        return 0.0


def _percent(part: int, total: int) -> float:
    """Avoid ZeroDivisionError when generating empty reports."""
    return (part / total * 100) if total else 0.0


def _format_reasons(record: dict[str, Any]) -> str:
    """Format risk reason codes for a compact Markdown table cell."""
    reasons = record.get("risk_reasons", [])
    if not isinstance(reasons, list) or not reasons:
        return "-"
    return ", ".join(str(reason) for reason in reasons)


def generate_report(input_path: str, output_path: str, top_n: int = 10) -> Dict[str, Any]:
    """Generate DNS exfiltration detection report in markdown format."""
    loaded = _load_scores(input_path)
    if isinstance(loaded, dict) and "error" in loaded:
        return loaded

    scores = loaded
    total = len(scores)
    sorted_scores = sorted(
        scores,
        key=lambda item: _score_value(item, "combined_score"),
        reverse=True,
    )
    suspected = [
        score for score in sorted_scores
        if score.get("verdict") == "suspected"
    ]
    suspected_count = len(suspected)
    top_domains = sorted_scores[:max(top_n, 0)]

    sources: dict[str, int] = {}
    for score in scores:
        src = str(score.get("source", "unknown") or "unknown")
        sources[src] = sources.get(src, 0) + 1

    report_lines = [
        "# DNS Exfiltration Detection Report",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"- **Total DNS queries analyzed:** {total:,}",
        (
            f"- **Suspected exfiltration attempts:** {suspected_count:,} "
            f"({_percent(suspected_count, total):.1f}%)"
        ),
        f"- **Weighted-score threshold:** {THRESHOLD}",
        (
            "- **Hybrid rule:** suspected when weighted score is high, "
            "DGA probability is high, or entropy and embedding agree"
        ),
    ]

    if total == 0:
        report_lines.append("- **Warning:** No score records were available for analysis.")

    report_lines.extend([
        "",
        "---",
        "",
        f"## Top {top_n} Suspicious Domains",
        "",
        "| Rank | Domain | Entropy | DGA | Embed | Combined | Verdict | Reasons |",
        "|------|--------|---------|-----|-------|----------|---------|---------|",
    ])

    if top_domains:
        for rank, domain in enumerate(top_domains, 1):
            report_lines.append(
                f"| {rank} | `{domain.get('domain', '')}` | "
                f"{_score_value(domain, 'entropy_score'):.2f} | "
                f"{_score_value(domain, 'dga_score'):.2f} | "
                f"{_score_value(domain, 'embed_score'):.2f} | "
                f"**{_score_value(domain, 'combined_score'):.2f}** | "
                f"{domain.get('verdict', 'unknown')} | "
                f"{_format_reasons(domain)} |"
            )
    else:
        report_lines.append("| - | No records available | - | - | - | - | - | - |")

    report_lines.extend([
        "",
        "---",
        "",
        "## Score Breakdown",
        "",
        "### Detection Methods",
        "",
        "1. **Entropy Analysis (30% weight)**",
        "   - Measures randomness in subdomain characters",
        "   - High entropy indicates random hex/base64-like encoding",
        "",
        "2. **DGA Classification (40% weight)**",
        "   - RandomForest ML classifier with engineered DNS features",
        "   - Detects Domain Generation Algorithm patterns",
        "",
        "3. **Embedding Similarity (30% weight)**",
        "   - TF-IDF character n-grams with nearest benign reference scoring",
        "   - Measures lexical distance from known benign DNS strings",
        "",
        "### Hybrid Verdict Rule",
        "",
        f"- Weighted score >= {THRESHOLD}",
        f"- Or DGA score >= {DGA_HIGH_THRESHOLD}",
        (
            f"- Or entropy_norm >= {ENTROPY_EMBED_ENTROPY_THRESHOLD} "
            f"and embed_score >= {ENTROPY_EMBED_EMBED_THRESHOLD}"
        ),
        "",
        "### Source Distribution",
        "",
    ])

    if sources:
        for src, count in sorted(sources.items()):
            report_lines.append(f"- **{src}:** {count:,} queries ({_percent(count, total):.1f}%)")
    else:
        report_lines.append("- No source data available.")

    report_lines.extend([
        "",
        "---",
        "",
        "## Recommendations",
        "",
        "1. **Immediate Actions:**",
        f"   - Block or investigate {suspected_count} suspected domains",
        "   - Review source IPs of high-score queries",
        "   - Check DNS logs for long, random, or encoded subdomain patterns",
        "",
        "2. **Long-term Measures:**",
        "   - Implement DNS query rate limiting",
        "   - Deploy DNS firewall rules",
        "   - Monitor subdomain entropy and DGA likelihood in real time",
        "",
        "---",
        "",
        "*Report generated by DNS Exfiltration Detector*",
        "*Multi-agent ML pipeline with parallel scoring*",
        "",
    ])

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    log.info(f"Report generated -> {output_file}")

    return {
        "total_queries": total,
        "suspected_count": suspected_count,
        "report_file": str(output_file),
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage:")
        print("  python generate_report.py <scores_json> <output_md> [top_n]")
        print()
        print("Example:")
        print("  python generate_report.py data/output/scores.json data/output/exfil_report.md 10")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]
    top_n = int(sys.argv[3]) if len(sys.argv) > 3 else 10

    result = generate_report(input_path, output_path, top_n)

    if "error" not in result:
        print(f"[OK] Analyzed {result['total_queries']} queries")
        print(f"[OK] Found {result['suspected_count']} suspected domains")
        print(f"[OK] Report: {result['report_file']}")
    else:
        print(f"[ERROR] {result}")
        sys.exit(1)
