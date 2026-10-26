"""PCAP ingestion and bidirectional network flow extraction for NetSentry AI.

What it does:
    Parses raw PCAP/PCAPNG network packet captures, aggregates individual packets
    into bidirectional flows using the canonical 5-tuple, and computes standard
    DCN flow statistics matching NetSentry AI feature schemas.

Why it is needed:
    Network sensors, taps, and firewalls capture raw packet bytes (PCAP). Machine learning
    models operate on statistical connection summaries (flows). This module bridges
    the gap between raw packet capture and tabular ML inference.

DCN / ML connection:
    - 5-Tuple: (Source IP, Destination IP, Source Port, Destination Port, Transport Protocol).
    - Aggregates forward (client->server) and backward (server->client) packet sizes,
      inter-arrival times, TCP control flags (SYN, RST, FIN, ACK), and transmission rates.

ETHICAL NOTICE:
    Only analyze packet captures from networks you own or have explicit written
    authorization to monitor.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import pandas as pd


@dataclass
class PcapFlowExtractionResult:
    """Summary of PCAP packet ingestion and flow aggregation."""
    pcap_path: str
    total_packets_read: int
    total_flows_extracted: int
    flow_dataframe: pd.DataFrame
    capture_duration_sec: float
    protocols_encountered: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pcap_path": self.pcap_path,
            "total_packets_read": self.total_packets_read,
            "total_flows_extracted": self.total_flows_extracted,
            "capture_duration_sec": round(self.capture_duration_sec, 2),
            "protocols_encountered": self.protocols_encountered,
            "warnings": self.warnings,
        }


def extract_flows_from_pcap(
    pcap_path: str | Path,
    max_packets: int = 10000,
) -> PcapFlowExtractionResult:
    """Read PCAP and reconstruct bidirectional network flows with feature metrics.

    Args:
        pcap_path: Path to .pcap or .pcapng file.
        max_packets: Maximum packets to process to protect laptop memory.

    Returns:
        PcapFlowExtractionResult containing extracted flow DataFrame.
    """
    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    try:
        from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP
    except ImportError:
        raise ImportError("Scapy is required for PCAP parsing. Run: pip install scapy")

    # Flow tracker: key -> list of packets [(timestamp, length, is_fwd, flags)]
    flows: dict[tuple, dict[str, Any]] = {}
    proto_counts: dict[str, int] = {}
    first_ts = None
    last_ts = None
    pkt_count = 0

    with PcapReader(str(path)) as pcap_reader:
        for pkt in pcap_reader:
            pkt_count += 1
            if pkt_count > max_packets:
                break

            ts = float(pkt.time)
            if first_ts is None or ts < first_ts:
                first_ts = ts
            if last_ts is None or ts > last_ts:
                last_ts = ts

            # Inspect network layer
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                proto = pkt[IP].proto
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
                proto = pkt[IPv6].nh
            else:
                continue

            length = len(pkt)
            proto_name = "TCP" if proto == 6 else "UDP" if proto == 17 else "ICMP" if proto == 1 else str(proto)
            proto_counts[proto_name] = proto_counts.get(proto_name, 0) + 1

            sport = 0
            dport = 0
            tcp_flags = ""

            if pkt.haslayer(TCP):
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
                tcp_flags = str(pkt[TCP].flags)
            elif pkt.haslayer(UDP):
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)

            # Bidirectional canonical key: order endpoints to group forward and backward packets
            if (src_ip, sport) <= (dst_ip, dport):
                flow_key = (src_ip, sport, dst_ip, dport, proto)
                is_fwd = True
            else:
                flow_key = (dst_ip, dport, src_ip, sport, proto)
                is_fwd = False

            if flow_key not in flows:
                flows[flow_key] = {
                    "start_time": ts,
                    "end_time": ts,
                    "fwd_packets": 0,
                    "bwd_packets": 0,
                    "fwd_bytes": 0,
                    "bwd_bytes": 0,
                    "syn_flags": 0,
                    "rst_flags": 0,
                    "ack_flags": 0,
                }

            entry = flows[flow_key]
            entry["end_time"] = ts
            if is_fwd:
                entry["fwd_packets"] += 1
                entry["fwd_bytes"] += length
            else:
                entry["bwd_packets"] += 1
                entry["bwd_bytes"] += length

            if "S" in tcp_flags:
                entry["syn_flags"] += 1
            if "R" in tcp_flags:
                entry["rst_flags"] += 1
            if "A" in tcp_flags:
                entry["ack_flags"] += 1

    records = []
    for (src_ip, sport, dst_ip, dport, proto), f in flows.items():
        dur_sec = max(f["end_time"] - f["start_time"], 0.0001)
        dur_ms = dur_sec * 1000.0
        total_pkts = f["fwd_packets"] + f["bwd_packets"]
        total_bytes = f["fwd_bytes"] + f["bwd_bytes"]

        records.append({
            "flow_duration_ms": round(dur_ms, 3),
            "total_fwd_packets": f["fwd_packets"],
            "total_backward_packets": f["bwd_packets"],
            "flow_bytes_per_second": round(total_bytes / dur_sec, 2),
            "flow_packets_per_second": round(total_pkts / dur_sec, 2),
            "syn_flag_count": f["syn_flags"],
            "rst_flag_count": f["rst_flags"],
            "average_packet_size": round(total_bytes / max(total_pkts, 1), 2),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto,
        })

    flow_df = pd.DataFrame(records)
    total_dur = (last_ts - first_ts) if (first_ts and last_ts) else 0.0

    return PcapFlowExtractionResult(
        pcap_path=str(path.resolve()),
        total_packets_read=pkt_count,
        total_flows_extracted=len(flow_df),
        flow_dataframe=flow_df,
        capture_duration_sec=total_dur,
        protocols_encountered=proto_counts,
        warnings=[
            "ETHICAL WARNING: Ensure you have authorization to inspect traffic from this network tap.",
            "Features extracted match the NetSentry flow schema for direct inference.",
        ],
    )


def get_tshark_extraction_command(pcap_path: str, output_csv: str) -> str:
    """Return standard Wireshark/TShark CLI command for high-speed offline extraction."""
    return (
        f'tshark -r "{pcap_path}" -T fields -E header=y -E separator=, '
        '-e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport '
        f'-e frame.len -e tcp.flags > "{output_csv}"'
    )
