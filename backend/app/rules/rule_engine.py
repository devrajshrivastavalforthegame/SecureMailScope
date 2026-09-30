from __future__ import annotations

from typing import Any


SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
}   


def make_finding(
    finding_id: str,
    severity: str,
    title: str,
    description: str,
    remediation: str,
    evidence: list[int] | None = None,
    confidence: str = "OBSERVED",
):
    return {
        "id": finding_id,
        "severity": severity,
        "title": title,
        "description": description,
        "remediation": remediation,
        "evidence_packets": evidence or [],
        "confidence": confidence,
    }


def evaluate_starttls(session: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []

    state = session.get("starttls") or {}
    evidence = state.get("evidence") or {}

    if not state.get("advertised"):
        findings.append(
            make_finding(
                "SEC-STARTTLS-001",
                "HIGH",
                "STARTTLS is not advertised",
                "The SMTP session did not advertise STARTTLS capability.",
                "Configure the mail service to advertise STARTTLS and enforce TLS for appropriate email flows.",
                confidence="OBSERVED",
            )
        )

    elif state.get("requested") and not state.get("accepted"):
        findings.append(
            make_finding(
                "SEC-STARTTLS-002",
                "CRITICAL",
                "STARTTLS negotiation failed",
                "STARTTLS was requested but the server did not provide the expected acceptance response.",
                "Investigate the SMTP TLS configuration and reject or quarantine sessions that cannot establish the required secure channel.",
                evidence=(
                    evidence.get("requested_packets", [])
                ),
                confidence="OBSERVED",
            )
        )

    elif state.get("accepted") and not state.get("upgraded"):
        findings.append(
            make_finding(
                "SEC-STARTTLS-003",
                "HIGH",
                "STARTTLS accepted but TLS traffic was not observed",
                "The server accepted the STARTTLS request, but no TLS record was observed afterward.",
                "Verify the TLS transition and investigate incomplete or interrupted sessions.",
                evidence=(
                    evidence.get("accepted_packets", [])
                ),
                confidence="OBSERVED",
            )
        )

    return findings


def evaluate_tls(tls: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []

    evidence = tls.get("tls_packet_numbers", [])

    negotiated_version = tls.get(
        "negotiated_version"
    )

    cipher = (
        tls.get("selected_cipher_suite")
        or tls.get("cipher_suite")
    )

    forward_secrecy = tls.get(
        "forward_secrecy"
    )

    if negotiated_version in {"TLS 1.0", "TLS 1.1"}:
        findings.append(
            make_finding(
                "SEC-TLS-001",
                "CRITICAL",
                "Deprecated TLS version detected",
                f"The observed negotiated TLS version is {negotiated_version}.",
                "Disable deprecated TLS versions and configure the mail service to use modern TLS versions.",
                evidence=evidence,
                confidence="OBSERVED",
            )
        )

        if cipher:
            cipher_upper = cipher.upper()

            weak_cipher = any(
                marker in cipher_upper
                for marker in (
                    "_RC4_",
                    "_3DES_",
                    "_DES_",
                    "_NULL_",
                    "_EXPORT_",
                    "_MD5",
                    "_CBC_",
                )
            )

            rsa_key_exchange = (
                "_RSA_WITH_" in cipher_upper
                and "ECDHE" not in cipher_upper
                and "DHE" not in cipher_upper
            )

            if weak_cipher:
                findings.append(
                    make_finding(
                        "SEC-TLS-002",
                        "HIGH",
                        "Weak or legacy TLS cipher detected",
                        f"The selected cipher is {cipher}.",
                        "Replace legacy cipher suites with modern authenticated encryption suites.",
                        evidence=evidence,
                        confidence="OBSERVED",
                    )
                )

            # A static RSA key exchange is reported as one
            # forward-secrecy finding, not two overlapping findings.
            if rsa_key_exchange:
                findings.append(
                    make_finding(
                        "SEC-TLS-003",
                        "MEDIUM",
                        "Forward secrecy unavailable",
                        f"The selected cipher is {cipher}, which does not indicate ephemeral DHE/ECDHE key exchange.",
                        "Prefer ECDHE or DHE-based key exchange where supported.",
                        evidence=evidence,
                        confidence="INFERRED",
                    )
                )

   

    if negotiated_version is None:
        # A ClientHello alone must not be treated as a negotiated
        # protocol-version finding.
        pass

    return findings


def evaluate_certificate(
    certificate: dict[str, Any] | None,
    expected_hostname: str | None = None,
    evidence: list[int] | None = None,
) -> list[dict[str, Any]]:
    findings = []

    evidence = evidence or []

    if not certificate:
        return findings

    if certificate.get("parse_error"):
        findings.append(
            make_finding(
                "SEC-CERT-001",
                "HIGH",
                "Certificate could not be parsed",
                certificate["parse_error"],
                "Verify that the captured certificate data is complete and correctly encoded.",
                evidence=evidence,
                confidence="OBSERVED",
            )
        )
        return findings

    if certificate.get("expired"):
        findings.append(
            make_finding(
                "SEC-CERT-002",
                "HIGH",
                "Certificate is expired or not yet valid",
                "The certificate validity period does not contain the analysis time.",
                "Renew the certificate and verify validity periods across mail infrastructure.",
                evidence=evidence,
                confidence="OBSERVED",
            )
        )

    if expected_hostname:
        names = set(
            certificate.get("san_dns_names", [])
        )

        common_name = certificate.get(
            "common_name"
        )

        if (
            expected_hostname not in names
            and expected_hostname != common_name
        ):
            findings.append(
                make_finding(
                    "SEC-CERT-003",
                    "HIGH",
                    "Certificate hostname mismatch",
                    f"The expected hostname {expected_hostname} was not found in the observed certificate identity.",
                    "Install a certificate whose SAN contains the mail server hostname.",
                    evidence=evidence,
                    confidence="OBSERVED",
                )
            )

    return findings


def calculate_posture_score(
    findings: list[dict[str, Any]]
) -> dict[str, Any]:
    score = 100

    deductions = []

    for finding in findings:
        penalty = SEVERITY_WEIGHTS.get(
            finding["severity"],
            0,
        )

        score -= penalty

        deductions.append(
            {
                "finding_id": finding["id"],
                "severity": finding["severity"],
                "penalty": penalty,
            }
        )

    score = max(0, min(100, score))

    critical = sum(
        1
        for finding in findings
        if finding["severity"] == "CRITICAL"
    )

    high = sum(
        1
        for finding in findings
        if finding["severity"] == "HIGH"
    )

    medium = sum(
        1
        for finding in findings
        if finding["severity"] == "MEDIUM"
    )

    low = sum(
        1
        for finding in findings
        if finding["severity"] == "LOW"
    )

    if score >= 80:
        posture = "SECURE"
    elif score >= 60:
        posture = "MODERATE"
    elif score >= 40:
        posture = "HIGH RISK"
    else:
        posture = "CRITICAL RISK"

    return {
        "score": score,
        "posture": posture,
        "deductions": deductions,
        "summary": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "total": len(findings),
        },
    }


def evaluate_session(
    session: dict[str, Any],
    tls: dict[str, Any] | None = None,
) -> dict[str, Any]:
    findings = []

    findings.extend(
        evaluate_starttls(session)
    )

    if tls and tls.get("tls_detected"):
        findings.extend(
            evaluate_tls(tls)
        )

        certificate = tls.get(
            "certificate"
        )

        expected_hostname = None

        client_hello = tls.get(
            "client_hello"
        ) or {}

        expected_hostname = client_hello.get(
            "server_name"
        )

        findings.extend(
            evaluate_certificate(
                certificate,
                expected_hostname,
                tls.get(
                    "tls_packet_numbers",
                    []
                ),
            )
        )

    score = calculate_posture_score(
        findings
    )

    tls_summary = None

    if tls:
        client_hello = tls.get("client_hello") or {}
        server_hello = tls.get("server_hello") or {}

        tls_summary = {
            "tls_detected": tls.get("tls_detected", False),
            "record_count": tls.get("record_count", 0),
            "negotiated_version": tls.get("negotiated_version"),
            "highest_offered_version": tls.get(
                "highest_offered_version"
            ),
            "selected_cipher_suite": (
                tls.get("selected_cipher_suite")
                or tls.get("cipher_suite")
            ),
            "key_exchange": tls.get(
                "key_exchange",
                "Unknown"
            ),
            "forward_secrecy": tls.get(
                "forward_secrecy"
            ),
            "server_name": client_hello.get(
                "server_name"
            ),
            "supported_versions": client_hello.get(
                "supported_versions",
                []
            ),
            "key_share": client_hello.get(
                "key_share",
                False
            ),
            "server_hello": server_hello,
            "certificate": tls.get(
                "certificate"
            ),
            "handshake_messages": tls.get(
                "handshake_messages",
                []
            ),
            "tls_packet_numbers": tls.get(
                "tls_packet_numbers",
                []
            ),
        }

    return {
        "session_id": session["session_id"],
        "protocol": session["protocol"],
        "endpoints": session.get(
            "endpoints",
            []
        ),
        "packet_count": session.get(
            "packet_count",
            0
        ),
        "packet_numbers": session.get(
            "packet_numbers",
            []
        ),
        "starttls": session.get(
            "starttls"
        ),
        "tls": tls_summary,
        "findings": findings,
        "posture": score,
    }


def evaluate_analysis(
    sessions: list[dict[str, Any]]
) -> dict[str, Any]:
    session_results = []

    all_findings = []

    for session in sessions:
        result = evaluate_session(
            session,
            session.get("tls"),
        )

        session_results.append(result)
        all_findings.extend(
            result["findings"]
        )

    overall = calculate_posture_score(
        all_findings
    )

    return {
        "posture": overall,
        "findings": all_findings,
        "sessions": session_results,
    }
