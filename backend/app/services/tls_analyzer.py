from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes


TLS_VERSIONS = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

TLS_CONTENT_TYPES = {
    20: "CHANGE_CIPHER_SPEC",
    21: "ALERT",
    22: "HANDSHAKE",
    23: "APPLICATION_DATA",
}

HANDSHAKE_TYPES = {
    1: "CLIENT_HELLO",
    2: "SERVER_HELLO",
    11: "CERTIFICATE",
    12: "SERVER_KEY_EXCHANGE",
    13: "CERTIFICATE_REQUEST",
    14: "SERVER_HELLO_DONE",
    16: "CLIENT_KEY_EXCHANGE",
}

CIPHER_SUITES = {
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}


def version_name(value: int | None) -> str:
    if value is None:
        return "Unknown"

    return TLS_VERSIONS.get(value, f"Unknown (0x{value:04x})")


def is_tls_record(data: bytes) -> bool:
    if len(data) < 5:
        return False

    content_type = data[0]
    version = int.from_bytes(data[1:3], "big")

    return (
        content_type in TLS_CONTENT_TYPES
        and 0x0300 <= version <= 0x0304
    )


def parse_tls_records(data: bytes) -> list[dict[str, Any]]:
    records = []
    offset = 0

    while offset + 5 <= len(data):
        content_type = data[offset]
        version = int.from_bytes(data[offset + 1:offset + 3], "big")
        length = int.from_bytes(data[offset + 3:offset + 5], "big")

        if content_type not in TLS_CONTENT_TYPES:
            offset += 1
            continue

        end = offset + 5 + length

        if end > len(data):
            break

        body = data[offset + 5:end]

        records.append(
            {
                "content_type": content_type,
                "content_type_name": TLS_CONTENT_TYPES[content_type],
                "record_version": version,
                "record_version_name": version_name(version),
                "length": length,
                "body": body,
            }
        )

        offset = end

    return records


def parse_extensions(data: bytes) -> dict[int, bytes]:
    extensions: dict[int, bytes] = {}

    offset = 0

    while offset + 4 <= len(data):
        extension_type = int.from_bytes(
            data[offset:offset + 2],
            "big",
        )

        extension_length = int.from_bytes(
            data[offset + 2:offset + 4],
            "big",
        )

        start = offset + 4
        end = start + extension_length

        if end > len(data):
            break

        extensions[extension_type] = data[start:end]
        offset = end

    return extensions


def parse_client_hello(body: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "version": None,
        "cipher_suites": [],
        "supported_versions": [],
        "server_name": None,
        "key_share": False,
        "extensions": [],
    }

    if len(body) < 38:
        return result

    offset = 0

    legacy_version = int.from_bytes(
        body[offset:offset + 2],
        "big",
    )
    offset += 2

    result["version"] = version_name(legacy_version)

    offset += 32

    if offset >= len(body):
        return result

    session_id_length = body[offset]
    offset += 1

    offset += session_id_length

    if offset + 2 > len(body):
        return result

    cipher_length = int.from_bytes(
        body[offset:offset + 2],
        "big",
    )
    offset += 2

    cipher_end = min(offset + cipher_length, len(body))

    while offset + 2 <= cipher_end:
        cipher = int.from_bytes(
            body[offset:offset + 2],
            "big",
        )

        result["cipher_suites"].append(
            {
                "code": f"0x{cipher:04x}",
                "name": CIPHER_SUITES.get(
                    cipher,
                    f"Unknown TLS cipher 0x{cipher:04x}",
                ),
            }
        )

        offset += 2

    if offset >= len(body):
        return result

    compression_methods_length = body[offset]
    offset += 1 + compression_methods_length

    if offset + 2 > len(body):
        return result

    extensions_length = int.from_bytes(
        body[offset:offset + 2],
        "big",
    )
    offset += 2

    extensions_end = min(
        offset + extensions_length,
        len(body),
    )

    extensions = parse_extensions(
        body[offset:extensions_end]
    )

    result["extensions"] = [
        {
            "type": extension_type,
            "length": len(extension_data),
        }
        for extension_type, extension_data
        in extensions.items()
    ]

    # Extension 43 = supported_versions.
    if 43 in extensions:
        supported = extensions[43]

        if supported:
            versions_length = supported[0]

            raw_versions = supported[
                1:1 + versions_length
            ]

            for i in range(0, len(raw_versions) - 1, 2):
                value = int.from_bytes(
                    raw_versions[i:i + 2],
                    "big",
                )

                result["supported_versions"].append(
                    version_name(value)
                )

    # Extension 0 = server_name.
    if 0 in extensions:
        server_name_data = extensions[0]

        try:
            list_length = int.from_bytes(
                server_name_data[0:2],
                "big",
            )

            end = min(
                2 + list_length,
                len(server_name_data),
            )

            cursor = 2

            while cursor + 3 <= end:
                name_type = server_name_data[cursor]
                name_length = int.from_bytes(
                    server_name_data[cursor + 1:cursor + 3],
                    "big",
                )
                cursor += 3

                name_end = min(
                    cursor + name_length,
                    end,
                )

                if name_type == 0:
                    result["server_name"] = (
                        server_name_data[
                            cursor:name_end
                        ].decode(
                            "utf-8",
                            errors="ignore",
                        )
                    )
                    break

                cursor = name_end

        except Exception:
            pass

    # Extension 51 = key_share.
    result["key_share"] = 51 in extensions

    return result


def parse_server_hello(body: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "version": None,
        "cipher_suite": None,
        "supported_version": None,
        "key_share": False,
    }

    if len(body) < 38:
        return result

    offset = 0

    legacy_version = int.from_bytes(
        body[offset:offset + 2],
        "big",
    )
    offset += 2

    result["version"] = version_name(legacy_version)

    offset += 32

    if offset >= len(body):
        return result

    session_id_length = body[offset]
    offset += 1

    offset += session_id_length

    if offset + 3 > len(body):
        return result

    cipher = int.from_bytes(
        body[offset:offset + 2],
        "big",
    )
    offset += 2

    result["cipher_suite"] = {
        "code": f"0x{cipher:04x}",
        "name": CIPHER_SUITES.get(
            cipher,
            f"Unknown TLS cipher 0x{cipher:04x}",
        ),
    }

    offset += 1

    if offset + 2 > len(body):
        return result

    extensions_length = int.from_bytes(
        body[offset:offset + 2],
        "big",
    )
    offset += 2

    extensions_end = min(
        offset + extensions_length,
        len(body),
    )

    extensions = parse_extensions(
        body[offset:extensions_end]
    )

    if 43 in extensions and len(extensions[43]) >= 2:
        selected_version = int.from_bytes(
            extensions[43][:2],
            "big",
        )

        result["supported_version"] = version_name(
            selected_version
        )

    result["key_share"] = 51 in extensions

    return result


def parse_certificate(body: bytes) -> dict[str, Any] | None:
    if len(body) < 3:
        return None

    total_length = int.from_bytes(
        body[0:3],
        "big",
    )

    end = min(
        3 + total_length,
        len(body),
    )

    cursor = 3

    if cursor + 3 > end:
        return None

    certificate_length = int.from_bytes(
        body[cursor:cursor + 3],
        "big",
    )
    cursor += 3

    certificate_end = min(
        cursor + certificate_length,
        end,
    )

    certificate_der = body[
        cursor:certificate_end
    ]

    if not certificate_der:
        return None

    try:
        cert = x509.load_der_x509_certificate(
            certificate_der
        )

        now = datetime.now(timezone.utc)

        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc

        try:
            common_name = cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )[0].value
        except (IndexError, AttributeError):
            common_name = None

        san_names = []

        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value

            san_names = san.get_values_for_type(
                x509.DNSName
            )

        except x509.ExtensionNotFound:
            pass

        fingerprint = cert.fingerprint(
            hashes.SHA256()
        ).hex()

        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "common_name": common_name,
            "san_dns_names": san_names,
            "serial_number": str(cert.serial_number),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "expired": now < not_before or now > not_after,
            "sha256_fingerprint": fingerprint,
        }

    except Exception as exc:
        return {
            "parse_error": str(exc),
        }


def analyze_tls(messages: list[dict[str, Any]]) -> dict[str, Any]:
    combined = bytearray()
    tls_packet_numbers = []

    for message in messages:
        payload = message.get("payload", b"")

        if not payload:
            continue

        if is_tls_record(payload):
            tls_packet_numbers.append(
                message["packet_number"]
            )

            combined.extend(payload)

        elif tls_packet_numbers:
            combined.extend(payload)

    data = bytes(combined)

    records = parse_tls_records(data)

    handshake_messages = []

    client_hello = None
    server_hello = None
    certificate = None

    for record in records:
        if record["content_type"] != 22:
            continue

        body = record["body"]
        offset = 0

        while offset + 4 <= len(body):
            handshake_type = body[offset]
            handshake_length = int.from_bytes(
                body[offset + 1:offset + 4],
                "big",
            )

            start = offset + 4
            end = start + handshake_length

            if end > len(body):
                break

            handshake_body = body[start:end]

            handshake_messages.append(
                HANDSHAKE_TYPES.get(
                    handshake_type,
                    f"UNKNOWN_{handshake_type}",
                )
            )

            if handshake_type == 1:
                client_hello = parse_client_hello(
                    handshake_body
                )

            elif handshake_type == 2:
                server_hello = parse_server_hello(
                    handshake_body
                )

            elif handshake_type == 11:
                certificate = parse_certificate(
                    handshake_body
                )

            offset = end

        negotiated_version = None
    highest_offered_version = None

    if server_hello:
        negotiated_version = (
            server_hello.get("supported_version")
            or server_hello.get("version")
        )

    if client_hello:
        supported = client_hello.get(
            "supported_versions",
            [],
        )

        version_priority = {
            "TLS 1.0": 1,
            "TLS 1.1": 2,
            "TLS 1.2": 3,
            "TLS 1.3": 4,
        }

        if supported:
            highest_offered_version = max(
                supported,
                key=lambda version: version_priority.get(
                    version,
                    0,
                ),
            )

    selected_cipher = None
    offered_cipher_suites = []

    if server_hello and server_hello.get("cipher_suite"):
        selected_cipher = server_hello["cipher_suite"]["name"]

    if client_hello:
        offered_cipher_suites = client_hello.get(
            "cipher_suites",
            [],
        )

    key_exchange = "Unknown"
    forward_secrecy = None

    if server_hello and selected_cipher:
        cipher_upper = selected_cipher.upper()

        if "ECDHE" in cipher_upper:
            key_exchange = "ECDHE"
            forward_secrecy = True

        elif "DHE" in cipher_upper:
            key_exchange = "DHE"
            forward_secrecy = True

        elif "RSA" in cipher_upper:
            key_exchange = "RSA"
            forward_secrecy = False

    elif client_hello and client_hello.get("key_share"):
        key_exchange = "Key Share (ClientHello)"
        forward_secrecy = True

    if (
        negotiated_version == "TLS 1.3"
        and server_hello
        and server_hello.get("key_share")
    ):
        key_exchange = "Key Share"
        forward_secrecy = True

    if selected_cipher:
        cipher_upper = selected_cipher.upper()

        if "ECDHE" in cipher_upper:
            key_exchange = "ECDHE"
            forward_secrecy = True

        elif "DHE" in cipher_upper:
            key_exchange = "DHE"
            forward_secrecy = True

        elif "RSA" in cipher_upper:
            key_exchange = "RSA"
            forward_secrecy = False

    if (
        negotiated_version == "TLS 1.3"
        and (
            (
                server_hello
                and server_hello.get("key_share")
            )
            or (
                client_hello
                and client_hello.get("key_share")
            )
        )
    ):
        key_exchange = "Key Share"
        forward_secrecy = True

    return {
        "tls_detected": bool(records),
        "record_count": len(records),
        "tls_record_versions": sorted(
            {
                record["record_version_name"]
                for record in records
            }
        ),
        "negotiated_version": negotiated_version,
        "cipher_suite": selected_cipher,
        "key_exchange": key_exchange,
        "forward_secrecy": forward_secrecy,
        "client_hello": client_hello,
        "server_hello": server_hello,
        "certificate": certificate,
        "handshake_messages": handshake_messages,
        "tls_packet_numbers": tls_packet_numbers,
    }
