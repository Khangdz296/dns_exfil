---
name: pcap-reader
description: Reads a PCAP or PCAPng file and extracts raw DNS packets (UDP/TCP port 53).
---

# SKILL: pcap_reader

## Purpose

Read DNS packets from a PCAP or PCAPng file using `scapy`.
Filter to UDP/TCP port 53 only and return raw packet metadata
for downstream decoding by `dns_extractor_agent`.

## Tool function

`read_pcap_file(filepath: str, max_packets: int = 10_000) -> list[dict]`

## When to use

Input is a `.pcap` or `.pcapng` file path.

## Inputs

| Parameter     | Type | Required | Description                           |
| ------------- | ---- | -------- | ------------------------------------- |
| `filepath`    | str  | yes      | Absolute path to PCAP or PCAPng file  |
| `max_packets` | int  | no       | Max packets to read (default: 10,000) |

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

## Dependencies

```
scapy>=2.5.0
```

## Example call

```python
from tools.pcap_reader import read_pcap_file

packets = read_pcap_file("data/input/demo.pcap", max_packets=5000)
print(f"Loaded {len(packets)} DNS packets")
```

## Notes

- Only UDP/TCP port 53 packets are returned; all others are discarded.
- Corrupt packets are skipped with a warning log entry.
- This tool reads files only. There is no live capture mode.
