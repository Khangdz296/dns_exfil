"""
Local end-to-end runner for the DNS exfiltration pipeline.

This runner mirrors the Pi chain while producing clear lifecycle logs for
demo/review:
  - Stage 1 runs sequentially.
  - Stage 2 fans out three independent scoring agents in parallel.
  - Stage 3 aggregates scores and generates the report.
"""

from __future__ import annotations

import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

from tools.aggregate_scores import aggregate_scores
from tools.dga_model import score_dga_file
from tools.dns_extractor import extract_dns_queries
from tools.embed_score import calculate_embed_scores
from tools.generate_report import generate_report
from tools.logging_utils import setup_pipeline_logger
from tools.pcap_reader import capture_live_dns, read_pcap_file
from tools.shannon_entropy import calculate_entropy

log = setup_pipeline_logger("pipeline")

OUTPUT_DIR = Path("data/output")
RAW_PACKETS_PATH = OUTPUT_DIR / "raw_packets.json"
DNS_QUERIES_PATH = OUTPUT_DIR / "dns_queries.json"
ENTROPY_SCORES_PATH = OUTPUT_DIR / "entropy_scores.json"
DGA_SCORES_PATH = OUTPUT_DIR / "dga_scores.json"
EMBED_SCORES_PATH = OUTPUT_DIR / "embed_scores.json"
SCORES_PATH = OUTPUT_DIR / "scores.json"
REPORT_PATH = OUTPUT_DIR / "exfil_report.md"


def _is_error(result: Any) -> bool:
    return isinstance(result, dict) and "error" in result


def _abort_if_error(stage_name: str, result: Any) -> None:
    if _is_error(result):
        raise RuntimeError(f"{stage_name} failed: {result}")


def _summarize_result(result: Any) -> Any:
    """Keep lifecycle logs compact; avoid dumping packet/query arrays."""
    if isinstance(result, list):
        return {"type": "list", "count": len(result)}
    if isinstance(result, dict):
        compact_keys = (
            "total_processed",
            "high_entropy_count",
            "high_distance_count",
            "subdomain_path_count",
            "domain_fallback_count",
            "skipped_count",
            "suspected_count",
            "total_queries",
            "output_file",
            "report_file",
        )
        return {key: result[key] for key in compact_keys if key in result}
    return result


def _timed_agent(
    agent_name: str,
    func: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Run one agent/tool function with standard start/end logging."""
    started = time.perf_counter()
    log.info("SUBAGENT START | %s", agent_name)
    try:
        result = func(*args, **kwargs)
        _abort_if_error(agent_name, result)
    except Exception:
        elapsed = time.perf_counter() - started
        log.exception("SUBAGENT FAILED | %s | elapsed=%.2fs", agent_name, elapsed)
        raise

    elapsed = time.perf_counter() - started
    log.info(
        "SUBAGENT END | %s | elapsed=%.2fs | result=%s",
        agent_name,
        elapsed,
        _summarize_result(result),
    )
    return result


def run_stage1(args: argparse.Namespace) -> list[dict[str, Any]]:
    """Run Stage 1 ingestion and normalization."""
    log.info("STAGE 1 START | Data ingestion | mode=%s", args.mode)

    if args.mode == "pcap":
        packets = _timed_agent(
            "pcap_reader_agent",
            read_pcap_file,
            args.input,
            args.max_packets,
        )
        queries = _timed_agent(
            "dns_extractor_agent",
            extract_dns_queries,
            packets=packets,
        )
    elif args.mode == "csv":
        queries = _timed_agent(
            "dns_extractor_agent",
            extract_dns_queries,
            csv_path=args.input,
        )
    elif args.mode == "live":
        packets = _timed_agent(
            "pcap_reader_agent",
            capture_live_dns,
            interface=args.interface,
            timeout=args.timeout,
            max_packets=args.max_packets,
        )
        queries = _timed_agent(
            "dns_extractor_agent",
            extract_dns_queries,
            packets=packets,
        )
    else:
        raise ValueError(f"Unsupported mode: {args.mode}")

    log.info(
        "STAGE 1 END | queries=%s | output=%s",
        len(queries),
        DNS_QUERIES_PATH,
    )
    return queries


def run_stage2(args: argparse.Namespace) -> dict[str, Any]:
    """Run the three independent Stage 2 scorers in parallel."""
    log.info("STAGE 2 PARALLEL START | Fan-out entropy + DGA + embedding agents")

    tasks: dict[str, tuple[Callable[..., Any], tuple[Any, ...]]] = {
        "entropy_agent": (
            calculate_entropy,
            (str(DNS_QUERIES_PATH), str(ENTROPY_SCORES_PATH)),
        ),
        "dga_classifier_agent": (
            score_dga_file,
            (str(DNS_QUERIES_PATH), str(DGA_SCORES_PATH), args.dga_model),
        ),
        "embedding_agent": (
            calculate_embed_scores,
            (str(DNS_QUERIES_PATH), str(EMBED_SCORES_PATH), args.embed_model),
        ),
    }

    results: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(_timed_agent, agent_name, func, *task_args): agent_name
            for agent_name, (func, task_args) in tasks.items()
        }

        for future in as_completed(futures):
            agent_name = futures[future]
            results[agent_name] = future.result()

    log.info("STAGE 2 PARALLEL END | completed_agents=%s", sorted(results))
    return results


def run_stage3(args: argparse.Namespace) -> dict[str, Any]:
    """Run aggregation and report generation."""
    log.info("STAGE 3 START | Aggregation and reporting")

    aggregate_result = _timed_agent(
        "orchestrator_agent",
        aggregate_scores,
        str(ENTROPY_SCORES_PATH),
        str(DGA_SCORES_PATH),
        str(EMBED_SCORES_PATH),
        str(SCORES_PATH),
    )
    report_result = _timed_agent(
        "report_agent",
        generate_report,
        str(SCORES_PATH),
        str(REPORT_PATH),
        args.top_n,
    )

    log.info(
        "STAGE 3 END | scores=%s | report=%s",
        SCORES_PATH,
        REPORT_PATH,
    )
    return {
        "aggregate": aggregate_result,
        "report": report_result,
    }


def run_pipeline(args: argparse.Namespace) -> dict[str, Any]:
    """Run the complete pipeline and return a compact processing summary."""
    started = time.perf_counter()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    log.info("=" * 72)
    log.info(
        "PIPELINE START | mode=%s | input=%s | parallel_stage=2",
        args.mode,
        args.input if args.mode != "live" else args.interface or "default",
    )

    queries = run_stage1(args)
    stage2 = run_stage2(args)
    stage3 = run_stage3(args)

    elapsed = time.perf_counter() - started
    summary = {
        "mode": args.mode,
        "query_count": len(queries),
        "stage2_agents": sorted(stage2),
        "scores_file": str(SCORES_PATH),
        "report_file": str(REPORT_PATH),
        "elapsed_seconds": round(elapsed, 2),
    }

    log.info("PIPELINE COMPLETE | elapsed=%.2fs | summary=%s", elapsed, summary)
    log.info("=" * 72)
    return {
        "queries": len(queries),
        "stage2": stage2,
        "stage3": stage3,
        "summary": summary,
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the DNS exfiltration pipeline locally.")
    parser.add_argument(
        "--mode",
        choices=("pcap", "csv", "live"),
        default="pcap",
        help="Input mode. Default: pcap",
    )
    parser.add_argument(
        "--input",
        default="data/input/demo.pcap",
        help="PCAP path for pcap mode or CSV path for csv mode.",
    )
    parser.add_argument("--interface", default=None, help="Interface name for live mode.")
    parser.add_argument("--timeout", type=int, default=30, help="Live capture timeout.")
    parser.add_argument("--max-packets", type=int, default=10_000, help="Maximum DNS packets.")
    parser.add_argument("--dga-model", default="models/dga_model.pkl", help="DGA model path.")
    parser.add_argument("--embed-model", default="models/embed_model.pkl", help="Embedding model path.")
    parser.add_argument("--top-n", type=int, default=10, help="Top suspicious domains in report.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        result = run_pipeline(args)
    except Exception as exc:
        log.error("PIPELINE FAILED | %s", exc)
        return 1

    summary = result["summary"]
    print("[OK] Pipeline completed")
    print(f"[OK] Queries: {summary['query_count']}")
    print(f"[OK] Scores: {summary['scores_file']}")
    print(f"[OK] Report: {summary['report_file']}")
    print("[OK] Log: data/output/pipeline.log")
    return 0


if __name__ == "__main__":
    sys.exit(main())
