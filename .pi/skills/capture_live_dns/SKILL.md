---
name: capture-live-dns
description: >
  Capture live DNS queries with tcpdump for a configurable duration, save
  the traffic to a PCAP file, and process it through the existing PCAP reader.
  Use when a user explicitly requests timed live DNS capture from a network
  interface.
---

# SKILL: capture_live_dns

## Purpose

Capture live DNS query traffic sent to UDP or TCP destination port 53.
The capture is saved as a PCAP file and then passed to `read_pcap_file`, so
live and offline inputs use the same packet normalization pipeline.

## Tool function

```python
capture_live_dns(
    interface: str | None = None,
    timeout: int = 30,
    max_packets: int = 1_000,
    output_pcap: str = "data/input/live_capture.pcap",
) -> list[dict] | dict
```

## When to use

- Use this skill only when the user explicitly requests live DNS capture.
- Use `pcap_reader` directly when a PCAP/PCAPng file already exists.
- Do not use this skill for CSV input.

## Inputs

| Parameter     | Type     | Required | Description                                  |
| ------------- | -------- | -------- | -------------------------------------------- |
| `interface`   | str/null | no       | tcpdump interface; null uses its default     |
| `timeout`     | int      | no       | Capture duration in seconds, from 1 to 3,600 |
| `max_packets` | int      | no       | Stop after this many packets, from 1 to 10,000 |
| `output_pcap` | str      | no       | Destination `.pcap` or `.pcapng` file        |

## Capture behavior

Run `tcpdump` without a shell using arguments equivalent to:

```text
tcpdump -i <interface> -n -U -s 0 -c <max_packets>
        -w <output_pcap>
        "udp dst port 53 or tcp dst port 53"
```

The tool must:

1. Create the output directory when necessary.
2. Stop when `timeout` expires or `max_packets` is reached.
3. Terminate tcpdump and wait for the PCAP file to flush when time expires.
4. Preserve the generated PCAP file.
5. Call `read_pcap_file(output_pcap, max_packets)` after capture.
6. Return the normalized records and write `data/output/raw_packets.json`.

The BPF filter captures only packets sent to destination port 53. It excludes
normal DNS responses whose source port is 53. The downstream
`dns_extractor_agent` still validates the DNS payload and retains QR=0 queries.

## Outputs

On success, return the same packet list produced by `read_pcap_file`.

On failure, return one of:

```json
{"error": "tcpdump_not_found"}
```

```json
{"error": "interface_not_found", "interface": "<interface>"}
```

```json
{"error": "permission_denied", "detail": "<reason>"}
```

```json
{"error": "invalid_capture_argument", "detail": "<reason>"}
```

```json
{"error": "capture_failed", "detail": "<reason>"}
```

## Dependencies

```text
tcpdump
libpcap/Npcap
scapy>=2.5.0
```

Live capture may require administrator/root privileges. On Windows, the
runtime must provide a tcpdump-compatible executable and Npcap.

## Example

```python
from tools.pcap_reader import capture_live_dns

packets = capture_live_dns(
    interface="eth0",
    timeout=45,
    max_packets=1000,
    output_pcap="data/input/live_dns_45s.pcap",
)
```

## Constraints

- Do not use `shell=True`.
- Do not parse tcpdump console output into packet records.
- Do not delete the generated PCAP.
- Do not broaden the capture filter to source port 53.
- Do not decode DNS records in this skill.
