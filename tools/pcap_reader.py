"""
tools/pcap_reader.py
Stage 1 - pcap_reader_agent tool

Reads a PCAP/PCAPng file or captures live DNS queries with tcpdump, then
writes raw_packets.json for dns_extractor_agent.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

os.environ.setdefault("WINDIR", r"C:\Windows")

from scapy.all import IP, IPv6, TCP, UDP, PcapReader
from tools.logging_utils import setup_pipeline_logger

log = setup_pipeline_logger(__name__)

OUTPUT_PATH = Path("data/output/raw_packets.json")
DEFAULT_LIVE_PCAP = Path("data/output/live_capture.pcap")
LIVE_DNS_FILTER = "udp dst port 53 or tcp dst port 53"


def _network_addresses(pkt) -> tuple[str, str] | None:
    """Return source and destination addresses for IPv4 or IPv6 packets."""
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    return None


def _build_record(
    pkt,
    layer,
    protocol: str,
    payload_bytes: bytes,
    packet_id: int,
    timestamp: float | None = None,
) -> dict | None:
    """Build one normalized raw DNS payload record."""
    addresses = _network_addresses(pkt)
    if addresses is None or not payload_bytes:
        return None

    src_ip, dst_ip = addresses
    return {
        "packet_id": packet_id,
        "timestamp": float(pkt.time if timestamp is None else timestamp),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": int(layer.sport),
        "dst_port": int(layer.dport),
        "protocol": protocol,
        "dns_payload_length": len(payload_bytes),
        "raw_payload": payload_bytes.hex(),
    }


def _udp_record(pkt, packet_id: int) -> dict | None:
    """Convert one UDP DNS packet into the output contract."""
    if not pkt.haslayer(UDP):
        return None

    layer = pkt[UDP]
    if layer.dport != 53 and layer.sport != 53:
        return None
    payload_bytes = bytes(layer.payload)
    return _build_record(pkt, layer, "UDP", payload_bytes, packet_id)


def _tcp_records(
    pkt,
    packet_id: int,
    streams: dict[tuple[str, str, int, int], dict],
) -> list[dict]:
    """
    Reassemble TCP payloads and extract complete length-prefixed DNS messages.

    DNS over TCP prefixes each message with a two-byte network-order length.
    The stream state handles normal contiguous segments and retransmission
    overlap. A gap resets that direction because incomplete bytes cannot be
    decoded safely.
    """
    if not pkt.haslayer(TCP):
        return []

    addresses = _network_addresses(pkt)
    if addresses is None:
        return []

    layer = pkt[TCP]
    if layer.dport != 53 and layer.sport != 53:
        return []

    payload = bytes(layer.payload)
    if not payload:
        return []

    src_ip, dst_ip = addresses
    key = (src_ip, dst_ip, int(layer.sport), int(layer.dport))
    sequence = int(layer.seq)
    state = streams.get(key)

    if state is None:
        state = {
            "buffer": bytearray(),
            "next_seq": sequence,
            "timestamp": float(pkt.time),
            "packet": pkt,
            "layer": layer,
        }
        streams[key] = state

    if sequence > state["next_seq"]:
        log.warning("TCP DNS stream gap detected for %s; resetting buffer.", key)
        state["buffer"].clear()
        state["next_seq"] = sequence
        state["timestamp"] = float(pkt.time)
        state["packet"] = pkt
        state["layer"] = layer

    overlap = max(state["next_seq"] - sequence, 0)
    if overlap < len(payload):
        state["buffer"].extend(payload[overlap:])
        state["next_seq"] = sequence + len(payload)

    records = []
    while len(state["buffer"]) >= 2:
        message_length = int.from_bytes(state["buffer"][:2], "big")
        if message_length < 12:
            log.warning("Invalid TCP DNS message length %s for %s.", message_length, key)
            state["buffer"].clear()
            break
        if len(state["buffer"]) < message_length + 2:
            break

        dns_payload = bytes(state["buffer"][2:message_length + 2])
        del state["buffer"][:message_length + 2]
        record = _build_record(
            state["packet"],
            state["layer"],
            "TCP",
            dns_payload,
            packet_id + len(records),
            timestamp=state["timestamp"],
        )
        if record is not None:
            records.append(record)

        if state["buffer"]:
            state["timestamp"] = float(pkt.time)
            state["packet"] = pkt
            state["layer"] = layer

    if int(layer.flags) & 0x05:
        if state["buffer"]:
            log.warning("Discarding incomplete TCP DNS message for %s.", key)
        streams.pop(key, None)

    return records


def _packet_to_records(
    pkt,
    packet_id: int,
    tcp_streams: dict[tuple[str, str, int, int], dict],
) -> list[dict]:
    """Convert one captured packet into zero or more DNS payload records."""
    udp_record = _udp_record(pkt, packet_id)
    if udp_record is not None:
        return [udp_record]
    if pkt.haslayer(TCP):
        return _tcp_records(pkt, packet_id, tcp_streams)
    return []


def _validate_max_packets(max_packets: int) -> dict | None:
    if not isinstance(max_packets, int) or not 1 <= max_packets <= 10_000:
        return {
            "error": "invalid_capture_argument",
            "detail": "max_packets must be an integer from 1 to 10000",
        }
    return None


def _close_reader(reader) -> None:
    close = getattr(reader, "close", None)
    if callable(close):
        close()


def _open_pcap_reader(path: Path):
    try:
        return PcapReader(str(path))
    except Exception as e:
        log.error(f"Failed to read PCAP: {e}")
        return {"error": "read_failed", "detail": str(e)}


def _next_packet(reader):
    try:
        return next(reader)
    except StopIteration:
        return None


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

    validation_error = _validate_max_packets(max_packets)
    if validation_error is not None:
        return validation_error

    log.info(f"Reading PCAP: {filepath}")
    reader = _open_pcap_reader(path)
    if isinstance(reader, dict):
        return reader

    results = []
    packet_id = 1
    scanned_count = 0
    tcp_streams: dict[tuple[str, str, int, int], dict] = {}

    try:
        while len(results) < max_packets:
            pkt = _next_packet(reader)
            if pkt is None:
                break
            scanned_count += 1

            try:
                records = _packet_to_records(pkt, packet_id, tcp_streams)
                remaining = max_packets - len(results)
                results.extend(records[:remaining])
                packet_id += min(len(records), remaining)
            except Exception as e:
                log.warning(f"Skipping corrupt packet #{scanned_count}: {e}")
    except Exception as e:
        log.error(f"Failed while reading PCAP: {e}")
        return {"error": "read_failed", "detail": str(e)}
    finally:
        _close_reader(reader)

    if not results:
        log.warning("No DNS packets found in file.")

    if len(results) >= max_packets:
        log.warning(f"Reached max_packets={max_packets}, stopping early.")

    log.info(f"Scanned {scanned_count} packets - kept {len(results)} DNS messages.")
    _write_output(results)
    return results


def capture_live_dns(
    interface: str | None = None,
    timeout: int = 30,
    max_packets: int = 1_000,
    output_pcap: str = str(DEFAULT_LIVE_PCAP),
) -> list[dict] | dict:
    """
    Capture live DNS queries with tcpdump, then process the generated PCAP.

    Args:
        interface: tcpdump interface name. If None, tcpdump uses its default.
        timeout: Capture duration in seconds.
        max_packets: Maximum DNS query packets to capture.
        output_pcap: Path for the generated PCAP/PCAPng file.

    Returns:
        Output from read_pcap_file, which also writes raw_packets.json.
    """
    if not isinstance(timeout, int) or not 1 <= timeout <= 3_600:
        return {
            "error": "invalid_capture_argument",
            "detail": "timeout must be an integer from 1 to 3600",
        }
    validation_error = _validate_max_packets(max_packets)
    if validation_error is not None:
        return validation_error

    capture_path = Path(output_pcap)
    if capture_path.suffix.lower() not in {".pcap", ".pcapng"}:
        return {
            "error": "invalid_capture_argument",
            "detail": "output_pcap must end with .pcap or .pcapng",
        }

    tcpdump = shutil.which("tcpdump")
    if tcpdump is None:
        log.error("tcpdump executable was not found.")
        return {"error": "tcpdump_not_found"}

    capture_path.parent.mkdir(parents=True, exist_ok=True)
    command = [tcpdump]
    if interface:
        command.extend(["-i", interface])
    command.extend(
        [
            "-n",
            "-U",
            "-s",
            "0",
            "-c",
            str(max_packets),
            "-w",
            str(capture_path),
            LIVE_DNS_FILTER,
        ]
    )

    log.info(
        "Starting live DNS capture "
        f"(interface={interface or 'default'}, timeout={timeout}s, "
        f"max_packets={max_packets}, output={capture_path})"
    )

    timed_out = False
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            _, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.terminate()
            try:
                _, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                _, stderr = process.communicate()
    except OSError as e:
        log.error(f"Live capture failed: {e}")
        return {"error": "capture_failed", "detail": str(e)}

    stderr = (stderr or "").strip()
    if process.returncode != 0 and not timed_out:
        detail = stderr or f"tcpdump exited with status {process.returncode}"
        lowered = detail.lower()
        if "permission denied" in lowered or "operation not permitted" in lowered:
            error = {"error": "permission_denied", "detail": detail}
        elif (
            "no such device" in lowered
            or "does not exist" in lowered
            or "can't find" in lowered
        ):
            error = {
                "error": "interface_not_found",
                "interface": interface,
                "detail": detail,
            }
        else:
            error = {"error": "capture_failed", "detail": detail}
        log.error(f"Live capture failed: {detail}")
        return error

    if not capture_path.exists():
        detail = stderr or "tcpdump did not create the requested PCAP file"
        log.error(f"Live capture failed: {detail}")
        return {"error": "capture_failed", "detail": detail}

    log.info(f"Live capture saved -> {capture_path}")
    return read_pcap_file(str(capture_path), max_packets=max_packets)


if __name__ == "__main__":
    import sys

    if len(sys.argv) >= 2 and sys.argv[1] == "live":
        iface = sys.argv[2] if len(sys.argv) > 2 else None
        timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 30
        max_packets = int(sys.argv[4]) if len(sys.argv) > 4 else 1_000
        output_pcap = (
            sys.argv[5] if len(sys.argv) > 5 else str(DEFAULT_LIVE_PCAP)
        )
        pkts = capture_live_dns(
            interface=iface,
            timeout=timeout,
            max_packets=max_packets,
            output_pcap=output_pcap,
        )
    else:
        fp = sys.argv[1] if len(sys.argv) > 1 else "data/input/demo.pcap"
        pkts = read_pcap_file(fp)

    if isinstance(pkts, list):
        print(f"Done: {len(pkts)} DNS packets extracted.")
    else:
        print(f"Error: {pkts}")
