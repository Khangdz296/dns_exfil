"""
tools/dns_extractor.py
Stage 1 — dns_extractor_agent tool

Normalizes DNS input from two sources:
  Source A: raw_packets.json from pcap_reader_agent (PCAP mode)
  Source B: dns_tunneling.csv from Kaggle (CSV mode)

Outputs data/output/dns_queries.json consumed by all Stage-2 agents.
"""

import json
import logging
import os
from collections import Counter
from pathlib import Path

os.environ.setdefault("WINDIR", r"C:\Windows")

import pandas as pd
import tldextract
from scapy.layers.dns import DNS, DNSQR

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

OUTPUT_PATH = Path("data/output/dns_queries.json")
TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)


# ── helpers ──────────────────────────────────────────────────────────────────

def _parse_domain(domain: str) -> dict:
    """Extract subdomain, tld, label_count, domain_length, digit_ratio."""
    domain = domain.lower().rstrip(".")
    ext = TLD_EXTRACTOR(domain)
    subdomain = ext.subdomain or ""
    tld = ext.suffix or ""
    label_count = len([p for p in domain.split(".") if p])
    digit_ratio = (
        sum(c.isdigit() for c in subdomain) / len(subdomain)
        if subdomain else 0.0
    )
    return {
        "domain":        domain,
        "subdomain":     subdomain,
        "tld":           tld,
        "label_count":   label_count,
        "domain_length": len(domain),
        "digit_ratio":   round(digit_ratio, 4),
    }


def _add_counts(records: list[dict]) -> list[dict]:
    """Add repeat frequency count for each (domain, src_ip) pair."""
    freq = Counter((r["domain"], r["src_ip"]) for r in records)
    for r in records:
        r["count"] = freq[(r["domain"], r["src_ip"])]
    return records


# ── Source A: PCAP ────────────────────────────────────────────────────────────

def _from_packets(packets: list[dict]) -> list[dict]:
    records = []
    skipped = 0

    for pkt in packets:
        try:
            payload = bytes.fromhex(pkt["raw_payload"])
            dns = DNS(payload)

            # Keep only query packets (QR=0)
            if dns.qr != 0:
                continue
            if not dns.qd:
                continue

            qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
            qtype_map = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT"}
            qtype = qtype_map.get(dns.qd.qtype, str(dns.qd.qtype))

            parsed = _parse_domain(qname)
            if not parsed["domain"]:
                skipped += 1
                continue

            records.append({
                "timestamp":  pkt.get("timestamp", 0.0),
                "src_ip":     pkt.get("src_ip", "0.0.0.0"),
                "query_type": qtype,
                "label":      "unknown",
                "source":     "pcap",
                **parsed,
            })

        except Exception as e:
            log.warning(f"Skipping packet_id={pkt.get('packet_id')}: {e}")
            skipped += 1
            continue

    log.info(f"PCAP mode: {len(records)} kept, {skipped} skipped.")
    return records


# ── Source B: CSV ─────────────────────────────────────────────────────────────

def _from_csv(csv_path: str) -> list[dict]:
    df = pd.read_csv(csv_path)

    required = {"domain_name", "label"}
    missing = required - set(df.columns)
    if missing:
        return {"error": "missing_columns", "columns": list(missing)}

    df = df.dropna(subset=["domain_name"])
    records = []
    skipped = 0

    for _, row in df.iterrows():
        parsed = _parse_domain(str(row["domain_name"]))
        if not parsed["domain"]:
            skipped += 1
            continue

        records.append({
            "timestamp":  0.0,
            "src_ip":     "0.0.0.0",
            "query_type": "A",
            "label":      str(row.get("label", "unknown")).lower(),
            "source":     "csv",
            **parsed,
        })

    log.info(f"CSV mode: {len(records)} kept, {skipped} skipped.")
    return records


# ── Main entry point ──────────────────────────────────────────────────────────

def extract_dns_queries(
    packets: list[dict] | None = None,
    csv_path: str | None = None,
) -> list[dict]:
    """
    Normalize DNS input from PCAP packets and/or CSV into dns_queries.json.

    Args:
        packets:  Output from read_pcap_file() — list of raw packet dicts.
        csv_path: Path to Kaggle dns_tunneling.csv.

    Returns:
        Unified list of query records. Also writes dns_queries.json.
    """
    if packets is None and csv_path is None:
        log.error("No input provided.")
        return {"error": "no_input_found"}

    all_records = []

    if packets is not None:
        result = _from_packets(packets)
        if isinstance(result, dict):  # error
            return result
        all_records.extend(result)

    if csv_path is not None:
        result = _from_csv(csv_path)
        if isinstance(result, dict):  # error
            return result
        all_records.extend(result)

    # Add repeat counts then sequential IDs
    all_records = _add_counts(all_records)
    for i, r in enumerate(all_records, start=1):
        r["query_id"] = i

    # Reorder fields to match output contract
    ordered = []
    field_order = [
        "query_id", "timestamp", "src_ip", "domain", "query_type",
        "subdomain", "tld", "label_count", "domain_length",
        "digit_ratio", "label", "count", "source",
    ]
    for r in all_records:
        ordered.append({k: r[k] for k in field_order})

    # Write output
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(ordered, f, indent=2)

    log.info(f"Total: {len(ordered)} records → {OUTPUT_PATH}")
    return ordered


if __name__ == "__main__":
    import sys

    # Default: try both sources
    packets = None
    raw_path = Path("data/output/raw_packets.json")
    if raw_path.exists():
        packets = json.loads(raw_path.read_text())

    # Allow disabling CSV with "none" argument
    csv = None
    if len(sys.argv) >= 2:
        csv = None if sys.argv[1].lower() == "none" else sys.argv[1]
    elif not packets:
        # Only use CSV as fallback if no packets
        csv = "data/input/dns_tunneling.csv"

    result = extract_dns_queries(packets=packets, csv_path=csv)
    if isinstance(result, list):
        print(f"Done: {len(result)} records written to {OUTPUT_PATH}")
