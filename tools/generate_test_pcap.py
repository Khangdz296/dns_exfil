"""
tools/generate_test_pcap.py
Stage 1 — helper script

Generates data/input/demo.pcap containing a mix of benign and
simulated DNS exfiltration queries for pipeline testing and demo.

Run:
    python tools/generate_test_pcap.py
    python tools/generate_test_pcap.py data/input/demo_mixed.pcap
"""

import os
from pathlib import Path

os.environ.setdefault("WINDIR", r"C:\Windows")

from scapy.all import IP, UDP, DNS, DNSQR, wrpcap

OUTPUT_PATH = Path("data/input/demo.pcap")
DNS_SERVER = "8.8.8.8"
START_TIME = 1718000000.0


# ── Traffic profile ────────────────────────────────────────────────────────────
# (domain, src_ip, query_type, expected_label)
TRAFFIC = [
    # Benign browsing / system traffic
    ("google.com", "192.168.1.10", "A", "benign"),
    ("www.google.com", "192.168.1.10", "A", "benign"),
    ("github.com", "192.168.1.11", "A", "benign"),
    ("api.github.com", "192.168.1.11", "A", "benign"),
    ("stackoverflow.com", "192.168.1.12", "A", "benign"),
    ("cdn.jsdelivr.net", "192.168.1.12", "A", "benign"),
    ("cloudflare.com", "192.168.1.13", "A", "benign"),
    ("one.one.one.one", "192.168.1.13", "A", "benign"),
    ("windowsupdate.microsoft.com", "192.168.1.20", "A", "benign"),
    ("time.windows.com", "192.168.1.20", "A", "benign"),
    ("connectivity-check.ubuntu.com", "192.168.1.30", "A", "benign"),
    ("archive.ubuntu.com", "192.168.1.30", "A", "benign"),
    ("youtube.com", "192.168.1.14", "A", "benign"),
    ("i.ytimg.com", "192.168.1.14", "A", "benign"),
    ("wikipedia.org", "192.168.1.15", "A", "benign"),
    ("en.wikipedia.org", "192.168.1.15", "A", "benign"),
    ("reddit.com", "192.168.1.16", "A", "benign"),
    ("gateway.discord.gg", "192.168.1.17", "A", "benign"),
    ("ntp.org", "192.168.1.18", "A", "benign"),
    ("pool.ntp.org", "192.168.1.18", "A", "benign"),

    # Simulated DNS exfiltration traffic embedded among benign requests
    ("a3f9bc12xk29.evil.com", "10.0.0.5", "TXT", "malicious"),
    ("d4e8f2a1b7c3.tunnel.net", "10.0.0.5", "TXT", "malicious"),
    ("xk29ab88zq11.exfil.io", "10.0.0.6", "TXT", "malicious"),
    ("9f3d2c1e8b7a.bad-domain.org", "10.0.0.7", "MX", "malicious"),
    ("q7w2e5r8t1y4.covert.net", "10.0.0.5", "CNAME", "malicious"),
    ("b64chunk001.userdata-sync.com", "10.0.0.9", "TXT", "malicious"),
    ("b64chunk002.userdata-sync.com", "10.0.0.9", "TXT", "malicious"),
    ("b64chunk003.userdata-sync.com", "10.0.0.9", "TXT", "malicious"),
    ("6f2a9bc1d4e8f0aa.internal-cache.net", "10.0.0.10", "TXT", "malicious"),
    ("7c10ffab2291de45.internal-cache.net", "10.0.0.10", "TXT", "malicious"),
    ("8aa2cd9011ef4470.internal-cache.net", "10.0.0.10", "TXT", "malicious"),
    ("xkq9zbf3mw.com", "10.0.0.8", "A", "malicious"),
    ("p4j7rvn2ks.net", "10.0.0.8", "A", "malicious"),
    ("b8tz1qmx5w.org", "10.0.0.9", "A", "malicious"),

    # Repeated beacon / exfil bursts from same host
    ("a3f9bc12xk29.evil.com", "10.0.0.5", "TXT", "malicious"),
    ("a3f9bc12xk29.evil.com", "10.0.0.5", "TXT", "malicious"),
    ("d4e8f2a1b7c3.tunnel.net", "10.0.0.5", "TXT", "malicious"),
    ("google.com", "192.168.1.10", "A", "benign"),
    ("github.com", "192.168.1.11", "A", "benign"),
]


def build_packet(domain: str, src_ip: str, query_type: str, packet_index: int):
    """Build a single DNS query packet with a deterministic timestamp."""
    packet = (
        IP(src=src_ip, dst=DNS_SERVER)
        / UDP(sport=40000 + packet_index, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=domain, qtype=query_type))
    )
    packet.time = START_TIME + (packet_index * 0.37)
    return packet


def generate(output_path: Path = OUTPUT_PATH) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    packets = [
        build_packet(domain, src_ip, query_type, index)
        for index, (domain, src_ip, query_type, _) in enumerate(TRAFFIC, start=1)
    ]

    wrpcap(str(output_path), packets)

    benign = sum(1 for _, _, _, label in TRAFFIC if label == "benign")
    malicious = sum(1 for _, _, _, label in TRAFFIC if label == "malicious")
    unique_domains = len({domain for domain, _, _, _ in TRAFFIC})
    unique_sources = len({src_ip for _, src_ip, _, _ in TRAFFIC})

    print(f"Generated {len(packets)} packets -> {output_path}")
    print("Breakdown:")
    print(f"  Benign:         {benign}")
    print(f"  Malicious:      {malicious}")
    print(f"  Unique domains: {unique_domains}")
    print(f"  Unique sources: {unique_sources}")


if __name__ == "__main__":
    import sys

    output = Path(sys.argv[1]) if len(sys.argv) > 1 else OUTPUT_PATH
    generate(output)
