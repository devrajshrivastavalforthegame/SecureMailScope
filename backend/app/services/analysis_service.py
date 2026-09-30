from __future__ import annotations
from backend.app.ml.anomaly_detector import analyze_anomaly
import json
import re
from pathlib import Path

from scapy.all import rdpcap, IP, IPv6, TCP, Raw

from backend.app.services.evidence_service import (
    load_cases,
    save_cases,
)
from backend.app.services.pcap_analyzer import (
    canonical_session_key,
    detect_protocol,
)
from backend.app.services.tls_analyzer import (
    analyze_tls,
)
from backend.app.rules.rule_engine import (
    evaluate_analysis,
)


BASE_DIR = Path(__file__).resolve().parents[3]

MAX_ANALYSIS_BYTES = 25 * 1024 * 1024

UPLOAD_DIR = BASE_DIR / "uploads"
DATA_DIR = BASE_DIR / "data"


def get_ip_addresses(packet):
    if IP in packet:
        return packet[IP].src, packet[IP].dst

    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst

    return None, None


def find_case(case_id: str):
    for case in load_cases():
        if case["case_id"] == case_id:
            return case

    raise FileNotFoundError(
        f"Case not found: {case_id}"
    )


def reconstruct_sessions(pcap_path: Path):
    packets = rdpcap(str(pcap_path))

    sessions = {}

    for packet_number, packet in enumerate(
        packets,
        start=1,
    ):
        if TCP not in packet or Raw not in packet:
            continue

        src_ip, dst_ip = get_ip_addresses(
            packet
        )

        if not src_ip or not dst_ip:
            continue

        tcp = packet[TCP]
        payload = bytes(
            packet[Raw].load
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

        key = canonical_session_key(
            src_ip,
            tcp.sport,
            dst_ip,
            tcp.dport,
        )

        if key not in sessions:
            sessions[key] = []

        sessions[key].append(
            {
                "packet_number": packet_number,
                "source_ip": str(src_ip),
                "source_port": int(tcp.sport),
                "destination_ip": str(dst_ip),
                "destination_port": int(tcp.dport),
                "payload": payload,
            }
        )

    results = []

    for index, (key, messages) in enumerate(
        sessions.items(),
        start=1,
    ):
        messages.sort(
            key=lambda message:
            message["packet_number"]
        )

        protocol = detect_protocol(
            messages[0]["source_port"],
            messages[0]["destination_port"],
            messages[0]["payload"],
        )

        if any(
            detect_protocol(
                message["source_port"],
                message["destination_port"],
                message["payload"],
            ) == "SMTP"
            for message in messages
        ):
            protocol = "SMTP"

        session = {
            "session_id": (
                f"SESSION-{index:03d}"
            ),
            "protocol": protocol,
            "endpoints": [
                f"{key[0][0]}:{key[0][1]}",
                f"{key[1][0]}:{key[1][1]}",
            ],
            "packet_count": len(messages),
            "packet_numbers": [
                message["packet_number"]
                for message in messages
            ],
            "messages": messages,
        }

        if protocol == "SMTP":
            from backend.app.services.pcap_analyzer import (
                analyze_starttls,
            )

            session["starttls"] = (
                analyze_starttls(messages)
            )

        else:
            session["starttls"] = None

        tls_messages = [
            message
            for message in messages
            if len(message["payload"]) >= 5
            and (
                message["payload"][0]
                in {20, 21, 22, 23, 24}
            )
            and 0x03 <= message["payload"][1] <= 0x03
        ]

        session["tls"] = (
            analyze_tls(messages)
            if tls_messages
            else {
                "tls_detected": False
            }
        )
        session["ml"] = analyze_anomaly(session)

        session.pop("messages", None)

        results.append(session)

    return {
        "packet_count": len(packets),
        "session_count": len(results),
        "sessions": results,
    }


def analyze_case(case_id: str):
    if not re.fullmatch(
        r"CASE-\d{8}-[A-F0-9]{8}",
        case_id,
    ):
        raise ValueError("Invalid case ID.")

    case = find_case(case_id)

    stored_filename = case.get("stored_filename")

    if (
        not isinstance(stored_filename, str)
        or not re.fullmatch(
            r"CASE-\d{8}-[A-F0-9]{8}\.(?:pcap|pcapng)",
            stored_filename,
        )
    ):
        raise ValueError(
            "Invalid stored evidence reference."
        )

    upload_root = UPLOAD_DIR.resolve()
    pcap_path = (
        UPLOAD_DIR / stored_filename
    ).resolve()

    if pcap_path.parent != upload_root:
        raise ValueError(
            "Invalid evidence storage path."
        )

    if not pcap_path.exists():
        raise FileNotFoundError(
            "Stored evidence not found."
        )

    if not pcap_path.is_file():
        raise ValueError(
            "Stored evidence is not a regular file."
        )

    try:
        evidence_size = pcap_path.stat().st_size
    except OSError as exc:
        raise ValueError(
            "Unable to inspect stored evidence."
        ) from exc

    if evidence_size > MAX_ANALYSIS_BYTES:
        raise ValueError(
            "Evidence exceeds the 25 MB analysis limit."
        )

    reconstruction = reconstruct_sessions(
        pcap_path
    )

    evaluation = evaluate_analysis(
        reconstruction["sessions"]
    )

    # Preserve ML results when persisting evaluated sessions.
    evaluated_sessions = evaluation["sessions"]

    for source_session, evaluated_session in zip(
        reconstruction["sessions"],
        evaluated_sessions,
    ):
        if "ml" in source_session:
            evaluated_session["ml"] = source_session["ml"]


    result = {
        "case": {
            "case_id": case["case_id"],
            "filename": case[
                "original_filename"
            ],
            "sha256": case["sha256"],
        },
        "analysis": {
            "packet_count": reconstruction[
                "packet_count"
            ],
            "session_count": reconstruction[
                "session_count"
            ],
            "posture": evaluation[
                "posture"
            ],
            "findings": evaluation[
                "findings"
            ],
            "sessions": evaluated_sessions,
        },
    }

    output_path = (
        DATA_DIR
        / f"{case_id}_analysis.json"
    )

    output_path.write_text(
        json.dumps(
            result,
            indent=2,
        ),
        encoding="utf-8",
    )

    cases = load_cases()

    for stored_case in cases:
        if stored_case["case_id"] == case_id:
            stored_case["status"] = "ANALYZED"

    save_cases(cases)

    return result




