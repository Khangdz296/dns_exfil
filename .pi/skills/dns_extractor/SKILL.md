---
name: dns-extractor
description: Normalize DNS input from PCAP or CSV into one unified JSON dataset.
---

# SKILL: dns_extractor

## Purpose

Normalize DNS input from two sources into one unified JSON dataset.
Source A: decode raw DNS payloads from `pcap_reader_agent` output.
Source B: read CSV directly from the Kaggle dns-tunneling dataset.
Output is consumed by all three Stage-2 analysis agents.

## Tool function

`extract_dns_queries(packets: list[dict] = None, csv_path: str = None) -> list[dict]`

## When to use

- **PCAP mode**: after `pcap_reader_agent` produces `raw_packets.json`.
- **CSV mode**: when `data/input/dns_tunneling.csv` is the input source.
- **Both**: pass both arguments to merge into one output list.

## Inputs

| Parameter  | Type       | Required | Description                       |
| ---------- | ---------- | -------- | --------------------------------- |
| `packets`  | list[dict] | no\*     | Output list from `read_pcap_file` |
| `csv_path` | str        | no\*     | Path to Kaggle CSV file           |

\*At least one of `packets` or `csv_path` must be provided.

## Outputs

Returns a list of dicts written to `data/output/dns_queries.json`.
Every item contains exactly these fields:

| Field           | Type    | Description                                             |
| --------------- | ------- | ------------------------------------------------------- |
| `query_id`      | integer | Sequential ID starting at 1                             |
| `timestamp`     | float   | Unix epoch (0.0 for CSV rows)                           |
| `src_ip`        | string  | Source IP ("0.0.0.0" for CSV rows)                      |
| `domain`        | string  | Full domain, lowercase, no trailing dot                 |
| `query_type`    | string  | `"A"`, `"AAAA"`, `"TXT"`, `"CNAME"`, `"MX"`, etc.       |
| `subdomain`     | string  | Everything left of the registered domain (may be `""`)  |
| `tld`           | string  | Top-level domain, e.g. `"com"`, `"net"`                 |
| `label_count`   | integer | Number of DNS labels in the full domain                 |
| `domain_length` | integer | Total character length of the full domain               |
| `digit_ratio`   | float   | Ratio of digit characters in `subdomain` (0.0 if empty) |
| `label`         | string  | `"benign"`, `"malicious"`, or `"unknown"`               |
| `count`         | integer | Repeat frequency of this `(domain, src_ip)` pair        |
| `source`        | string  | `"pcap"` or `"csv"`                                     |

## Dependencies

```
scapy>=2.5.0
tldextract>=3.4.0
pandas>=2.0.0
```

## Example call

```python
from tools.pcap_reader import read_pcap_file
from tools.dns_extractor import extract_dns_queries

# PCAP mode
packets = read_pcap_file("data/input/demo.pcap")
queries = extract_dns_queries(packets=packets)

# CSV mode
queries = extract_dns_queries(csv_path="data/input/dns_tunneling.csv")

# Both merged
queries = extract_dns_queries(packets=packets,
                              csv_path="data/input/dns_tunneling.csv")

print(f"Extracted {len(queries)} DNS queries")
```

## Notes

- PCAP mode: only QR=0 (query) packets are kept; responses are discarded.
- Domain parsing uses `TLDExtract(suffix_list_urls=None)` for deterministic,
  offline Public Suffix List behavior.
- CSV mode: `timestamp`, `src_ip`, `query_type` are set to defaults
  (`0.0`, `"0.0.0.0"`, `"A"`) since the dataset does not include them.
- Malformed payloads are skipped with a warning log entry.
- Output is always saved to `data/output/dns_queries.json`.
