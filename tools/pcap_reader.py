"""
tools/pcap_reader.py
Stage 1 - pcap_reader_agent tool

Reads a PCAP/PCAPng file or captures live traffic, filters DNS packets
(UDP/TCP port 53), and writes raw_packets.json for dns_extractor_agent.
"""

import json
import logging
import os
from pathlib import Path

os.environ.setdefault("WINDIR", r"C:\Windows")

from scapy.all import IP, TCP, UDP, rdpcap, sniff

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

OUTPUT_PATH = Path("data/output/raw_packets.json")


def _packet_to_record(pkt, packet_id: int) -> dict | None:
    """Convert a Scapy packet into the raw DNS packet output contract."""
    if not pkt.haslayer(IP):
        return None
    if pkt.haslayer(UDP):
        proto = "UDP"
        layer = pkt[UDP]
    elif pkt.haslayer(TCP):
        proto = "TCP"
        layer = pkt[TCP]
    else:
        return None

    if layer.dport != 53 and layer.sport != 53:
        return None

    payload_bytes = bytes(layer.payload)
    if not payload_bytes:
        return None

    return {
        "packet_id": packet_id,
        "timestamp": float(pkt.time),
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "src_port": int(layer.sport),
        "dst_port": int(layer.dport),
        "protocol": proto,
        "dns_payload_length": len(payload_bytes),
        "raw_payload": payload_bytes.hex(),
    }


def _write_output(records: list[dict]) -> None:
    """Write raw DNS packet records to the shared Stage-1 output file."""
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
    log.info(f"Saved -> {OUTPUT_PATH}")


def read_pcap_file(filepath: str, max_packets: int = 10_000) -> list[dict] | dict:
    """
    Read DNS packets from a PCAP or PCAPng file.

    Args:
        filepath: Path to `.pcap` or `.pcapng` file.
        max_packets: Maximum number of DNS packets to return.

    Returns:
        List of packet dicts. Also writes to data/output/raw_packets.json.
    """
    path = Path(filepath)
    if not path.exists():
        log.error(f"File not found: {filepath}")
        return {"error": "file_not_found", "path": str(filepath)}

    log.info(f"Reading PCAP: {filepath}")
    try:
        packets = rdpcap(str(path))
    except Exception as e:
        log.error(f"Failed to read PCAP: {e}")
        return {"error": "read_failed", "detail": str(e)}

    results = []
    packet_id = 1

    for i, pkt in enumerate(packets):
        if len(results) >= max_packets:
            log.warning(f"Reached max_packets={max_packets}, stopping early.")
            break

        try:
            record = _packet_to_record(pkt, packet_id)
            if record is None:
                continue
            results.append(record)
            packet_id += 1
        except Exception as e:
            log.warning(f"Skipping corrupt packet #{i}: {e}")
            continue

    if not results:
        log.warning("No DNS packets found in file.")

    log.info(f"Scanned {len(packets)} packets - kept {len(results)} DNS packets.")
    _write_output(results)
    return results


def capture_live_dns(
    interface: str | None = None,
    timeout: int = 30,
    max_packets: int = 1_000,
) -> list[dict] | dict:
    """
    Capture live DNS packets from a network interface.

    Args:
        interface: Interface name. If None, Scapy chooses the default.
        timeout: Capture duration in seconds.
        max_packets: Maximum DNS packets to keep.

    Returns:
        List of packet dicts. Also writes to data/output/raw_packets.json.
    """
    log.info(
        "Starting live DNS capture "
        f"(interface={interface or 'default'}, timeout={timeout}s, max_packets={max_packets})"
    )
    try:
        packets = sniff(
            iface=interface,
            filter="udp port 53 or tcp port 53",
            timeout=timeout,
            count=max_packets,
            store=True,
        )
    except Exception as e:
        log.error(f"Live capture failed: {e}")
        return {"error": "capture_failed", "detail": str(e)}

    results = []
    packet_id = 1
    for i, pkt in enumerate(packets):
        try:
            record = _packet_to_record(pkt, packet_id)
            if record is None:
                continue
            results.append(record)
            packet_id += 1
        except Exception as e:
            log.warning(f"Skipping captured packet #{i}: {e}")
            continue

    if not results:
        log.warning("No DNS packets captured.")

    log.info(f"Captured {len(results)} DNS packets.")
    _write_output(results)
    return results


if __name__ == "__main__":
    import sys

    if len(sys.argv) >= 2 and sys.argv[1] == "live":
        iface = sys.argv[2] if len(sys.argv) > 2 else None
        timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 30
        max_packets = int(sys.argv[4]) if len(sys.argv) > 4 else 1_000
        pkts = capture_live_dns(interface=iface, timeout=timeout, max_packets=max_packets)
    else:
        fp = sys.argv[1] if len(sys.argv) > 1 else "data/input/demo.pcap"
        pkts = read_pcap_file(fp)

    if isinstance(pkts, list):
        print(f"Done: {len(pkts)} DNS packets extracted.")
    else:
        print(f"Error: {pkts}")
