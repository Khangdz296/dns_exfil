---
name: pcap-reader
description: Reads DNS packets from PCAP/PCAPng files or live network capture.
---

# SKILL: pcap_reader

## Purpose

Collect raw DNS packet metadata using `scapy`.
The skill supports both offline PCAP/PCAPng input and optional live DNS capture.
It filters to UDP/TCP port 53 only and returns raw packet metadata for
downstream decoding by `dns_extractor_agent`.

## Tool functions

```python
read_pcap_file(filepath: str, max_packets: int = 10_000) -> list[dict] | dict
capture_live_dns(
    interface: str | None = None,
    timeout: int = 30,
    max_packets: int = 1_000,
) -> list[dict] | dict
```

## When to use

- Use `read_pcap_file` when the input is a `.pcap` or `.pcapng` file path.
- Use `capture_live_dns` when the project needs a short local live DNS capture.
- Do not use this skill for CSV datasets; pass CSV directly to
  `dns_extractor_agent`.

## Inputs

### `read_pcap_file`

| Parameter     | Type | Required | Description                           |
| ------------- | ---- | -------- | ------------------------------------- |
| `filepath`    | str  | yes      | Absolute or relative PCAP/PCAPng path |
| `max_packets` | int  | no       | Max DNS packets to keep               |

### `capture_live_dns`

| Parameter     | Type     | Required | Description                                     |
| ------------- | -------- | -------- | ----------------------------------------------- |
| `interface`   | str/null | no       | Network interface; null uses Scapy default      |
| `timeout`     | int      | no       | Capture duration in seconds                     |
| `max_packets` | int      | no       | Max DNS packets to keep                         |

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
Npcap/libpcap for live capture
```

## Example calls

```python
from tools.pcap_reader import capture_live_dns, read_pcap_file

packets = read_pcap_file("data/input/demo.pcap", max_packets=5000)
live_packets = capture_live_dns(interface=None, timeout=30, max_packets=1000)
```

## Notes

- Only UDP/TCP port 53 packets are returned; all others are discarded.
- Corrupt packets are skipped with a warning log entry.
- Live capture can require administrator/root privileges and a packet capture
  driver such as Npcap on Windows.
