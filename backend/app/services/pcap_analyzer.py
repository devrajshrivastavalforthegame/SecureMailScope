from pathlib import Path
from collections import defaultdict
from scapy.all import rdpcap, IP, IPv6, TCP, Raw


SMTP_PORTS = {25, 465, 587}
IMAP_PORTS = {143, 993}
POP3_PORTS = {110, 995}

TLS_CONTENT_TYPES = {
    20,  # ChangeCipherSpec
    21,  # Alert
    22,  # Handshake
    23,  # Application Data
    24,  # Heartbeat
}


def get_ip_addresses(packet):
    if IP in packet:
        return packet[IP].src, packet[IP].dst

    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst

    return None, None


def canonical_session_key(src_ip, src_port, dst_ip, dst_port):
    endpoint_a = (str(src_ip), int(src_port))
    endpoint_b = (str(dst_ip), int(dst_port))

    return tuple(sorted((endpoint_a, endpoint_b)))


def detect_protocol(src_port, dst_port, payload):
    ports = {src_port, dst_port}

    if ports & SMTP_PORTS:
        return "SMTP"

    if ports & IMAP_PORTS:
        return "IMAP"

    if ports & POP3_PORTS:
        return "POP3"

    text = payload.decode("utf-8", errors="ignore").upper()

    smtp_markers = (
        "EHLO",
        "HELO",
        "STARTTLS",
        "MAIL FROM:",
        "RCPT TO:",
        "220 ",
        "250 ",
        "250-",
    )

    if any(marker in text for marker in smtp_markers):
        return "SMTP"

    return "UNKNOWN"


def is_tls_record(payload):
    if len(payload) < 5:
        return False

    content_type = payload[0]
    major_version = payload[1]

    return (
        content_type in TLS_CONTENT_TYPES
        and major_version == 0x03
    )


def analyze_starttls(messages):
    state = {
        "advertised": False,
        "requested": False,
        "accepted": False,
        "upgraded": False,
        "failed": False,
        "final_state": "NOT_OBSERVED",
        "evidence": {
            "advertised_packets": [],
            "requested_packets": [],
            "accepted_packets": [],
            "tls_packets": [],
        },
    }

    starttls_request_seen = False

    for message in messages:
        payload = message["payload"]
        text = payload.decode("utf-8", errors="ignore")
        upper_text = text.upper()

        packet_number = message["packet_number"]

        # Server advertises STARTTLS inside SMTP capabilities.
        if (
            "STARTTLS" in upper_text
            and (
                "250-" in upper_text
                or "250 " in upper_text
            )
        ):
            state["advertised"] = True
            state["evidence"]["advertised_packets"].append(
                packet_number
            )

        # Client explicitly requests STARTTLS.
        lines = [
            line.strip().upper()
            for line in text.replace("\r", "").split("\n")
            if line.strip()
        ]

        if any(line == "STARTTLS" for line in lines):
            state["requested"] = True
            starttls_request_seen = True
            state["evidence"]["requested_packets"].append(
                packet_number
            )

        # Server accepts STARTTLS.
        if starttls_request_seen:
            if any(
                line.startswith("220")
                for line in lines
            ):
                state["accepted"] = True
                state["evidence"]["accepted_packets"].append(
                    packet_number
                )

        # A TLS record after STARTTLS acceptance indicates
        # that the connection actually transitioned toward TLS.
        if state["accepted"] and is_tls_record(payload):
            state["upgraded"] = True
            state["evidence"]["tls_packets"].append(
                packet_number
            )

    if state["upgraded"]:
        state["final_state"] = "UPGRADED"

    elif state["accepted"]:
        state["final_state"] = "ACCEPTED"

    elif state["requested"]:
        state["failed"] = True
        state["final_state"] = "FAILED"

    elif state["advertised"]:
        state["final_state"] = "ADVERTISED"

    return state


def analyze_pcap(pcap_path: str | Path):
    pcap_path = Path(pcap_path)

    if not pcap_path.exists():
        raise FileNotFoundError(
            f"PCAP not found: {pcap_path}"
        )

    packets = rdpcap(str(pcap_path))

    sessions = defaultdict(list)
    protocol_counts = defaultdict(int)

    for packet_number, packet in enumerate(
        packets,
        start=1,
    ):
        if TCP not in packet:
            continue

        src_ip, dst_ip = get_ip_addresses(packet)

        if not src_ip or not dst_ip:
            continue

        tcp = packet[TCP]

        payload = (
            bytes(packet[Raw].load)
            if Raw in packet
            else b""
        )

        if not payload:
            continue

        protocol = detect_protocol(
            tcp.sport,
            tcp.dport,
            payload,
        )

        if protocol == "UNKNOWN":
            continue

        session_key = canonical_session_key(
            src_ip,
            tcp.sport,
            dst_ip,
            tcp.dport,
        )

        sessions[session_key].append(
            {
                "packet_number": packet_number,
                "source_ip": str(src_ip),
                "source_port": int(tcp.sport),
                "destination_ip": str(dst_ip),
                "destination_port": int(tcp.dport),
                "payload": payload,
            }
        )

        protocol_counts[protocol] += 1

    session_results = []

    for index, (session_key, messages) in enumerate(
        sessions.items(),
        start=1,
    ):
        # PCAP order is preserved.
        messages.sort(
            key=lambda item: item["packet_number"]
        )

        protocol_candidates = []

        for message in messages:
            protocol_candidates.append(
                detect_protocol(
                    message["source_port"],
                    message["destination_port"],
                    message["payload"],
                )
            )

        if "SMTP" in protocol_candidates:
            protocol = "SMTP"
        elif "IMAP" in protocol_candidates:
            protocol = "IMAP"
        elif "POP3" in protocol_candidates:
            protocol = "POP3"
        else:
            protocol = "UNKNOWN"

        endpoint_a, endpoint_b = session_key

        session_result = {
            "session_id": f"SESSION-{index:03d}",
            "protocol": protocol,
            "endpoints": [
                f"{endpoint_a[0]}:{endpoint_a[1]}",
                f"{endpoint_b[0]}:{endpoint_b[1]}",
            ],
            "packet_count": len(messages),
            "packet_numbers": [
                message["packet_number"]
                for message in messages
            ],
            "starttls": (
                analyze_starttls(messages)
                if protocol == "SMTP"
                else None
            ),
        }

        session_results.append(session_result)

    return {
        "pcap": {
            "filename": pcap_path.name,
            "packet_count": len(packets),
        },
        "protocols": dict(protocol_counts),
        "session_count": len(session_results),
        "sessions": session_results,
    }
