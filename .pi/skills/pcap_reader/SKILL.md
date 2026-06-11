---
name: pcap-reader
description: Reads DNS packets from existing PCAP/PCAPng files.
---

# SKILL: pcap_reader

## Purpose

Collect raw IPv4/IPv6 DNS packet metadata from an existing PCAP/PCAPng file
using Scapy's streaming `PcapReader`. It filters to UDP/TCP port 53 and
returns raw DNS payload metadata for downstream decoding.

## Tool functions

```python
read_pcap_file(filepath: str, max_packets: int = 10_000) -> list[dict] | dict
```

## When to use

- Use `read_pcap_file` when the input is a `.pcap` or `.pcapng` file path.
- Use the separate `capture_live_dns` skill for live capture.
- Do not use this skill for CSV datasets; pass CSV directly to
  `dns_extractor_agent`.

## Inputs

### `read_pcap_file`

| Parameter     | Type | Required | Description                           |
| ------------- | ---- | -------- | ------------------------------------- |
| `filepath`    | str  | yes      | Absolute or relative PCAP/PCAPng path |
| `max_packets` | int  | no       | Max DNS packets to keep               |

## Outputs

Returns a list of dicts. Each dict contains:

| Field                | Type    | Description                    |
| -------------------- | ------- | ------------------------------ |
| `packet_id`          | integer | Sequential index starting at 1 |
| `timestamp`          | float   | Unix epoch seconds             |
| `src_ip`             | string  | Source IP address              |
| `dst_ip`             | string  | Destination IP address         |
| `src_port`           | integer | Source port                    |
| `dst_port`           | integer | Destination port               |
| `protocol`           | string  | `"UDP"` or `"TCP"`             |
| `dns_payload_length` | integer | Byte length of DNS payload     |
| `raw_payload`        | string  | Hex-encoded DNS payload bytes  |

Result is also written to `data/output/raw_packets.json`.

On failure, returns an error dict:

```json
{"error": "capture_failed", "detail": "permission or interface error"}
```

## Dependencies

```text
scapy>=2.5.0
```

## Example calls

```python
from tools.pcap_reader import read_pcap_file

packets = read_pcap_file("data/input/demo.pcap", max_packets=5000)
```

## Notes

- Only UDP/TCP port 53 packets are returned; all others are discarded.
- TCP DNS segments are reassembled per direction. Complete messages have
  their two-byte length prefix removed before output.
- PCAP files are streamed and stop reading once `max_packets` DNS messages
  have been retained.
- Corrupt packets are skipped with a warning log entry.
- Live captures saved by the `capture_live_dns` skill are read through this
  same function.
