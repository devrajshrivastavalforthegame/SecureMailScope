from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest


# ---------------------------------------------------------
# Controlled baseline
#
# These represent normal/acceptable email TLS observations
# with small variations between TLS versions, ciphers and
# ephemeral key-exchange mechanisms.
# ---------------------------------------------------------

BASELINE = np.array([
    [1.00, 1.00, 1.00, 1.00, 1.00, 1.00],
    [0.95, 1.00, 1.00, 1.00, 1.00, 1.00],
    [1.00, 0.95, 1.00, 1.00, 1.00, 1.00],
    [0.95, 0.95, 1.00, 1.00, 1.00, 1.00],
    [1.00, 1.00, 0.95, 1.00, 1.00, 1.00],
    [0.95, 1.00, 0.95, 1.00, 1.00, 1.00],
    [1.00, 0.95, 0.95, 1.00, 1.00, 1.00],
    [0.95, 0.95, 0.95, 1.00, 1.00, 1.00],
    [1.00, 1.00, 0.90, 0.95, 1.00, 1.00],
    [0.95, 1.00, 0.90, 0.95, 1.00, 1.00],
    [1.00, 0.90, 1.00, 1.00, 0.95, 1.00],
    [0.95, 0.90, 1.00, 1.00, 0.95, 1.00],
    [1.00, 1.00, 1.00, 1.00, 0.95, 1.00],
    [0.95, 1.00, 1.00, 0.95, 1.00, 1.00],
    [1.00, 0.95, 1.00, 0.95, 1.00, 1.00],
    [0.95, 0.95, 1.00, 0.95, 1.00, 1.00],
    [1.00, 1.00, 0.95, 1.00, 0.95, 1.00],
    [0.95, 1.00, 0.95, 1.00, 0.95, 1.00],
    [1.00, 0.95, 0.95, 1.00, 0.95, 1.00],
    [0.95, 0.95, 0.95, 1.00, 0.95, 1.00],
], dtype=float)


MODEL = IsolationForest(
    n_estimators=200,
    contamination=0.10,
    random_state=42,
)

MODEL.fit(BASELINE)


def build_features(
    session: dict[str, Any],
) -> list[float]:

    tls = session.get("tls") or {}
    starttls = session.get("starttls") or {}

    version = tls.get(
        "negotiated_version"
    )

    cipher = (
        tls.get("selected_cipher_suite")
        or ""
    ).upper()

    key_exchange = (
        tls.get("key_exchange")
        or ""
    )

    certificate = (
        tls.get("certificate")
        or {}
    )

    # TLS security level
    if version == "TLS 1.3":
        modern_tls = 1.0
    elif version == "TLS 1.2":
        modern_tls = 0.95
    elif version == "TLS 1.1":
        modern_tls = 0.35
    elif version == "TLS 1.0":
        modern_tls = 0.15
    else:
        modern_tls = 0.50

    # Cipher quality
    if "CHACHA20" in cipher or "GCM" in cipher:
        cipher_quality = 1.0
    elif "CBC" in cipher and (
        "ECDHE" in cipher
        or "DHE" in cipher
    ):
        cipher_quality = 0.65
    elif "CBC" in cipher:
        cipher_quality = 0.20
    elif cipher:
        cipher_quality = 0.50
    else:
        cipher_quality = 0.40

    # Key-exchange quality
    if key_exchange in {
        "ECDHE",
        "DHE",
        "Key Share",
        "Key Share (ClientHello)",
    }:
        key_exchange_quality = 1.0
    elif key_exchange == "RSA":
        key_exchange_quality = 0.20
    else:
        key_exchange_quality = 0.50

    forward_secrecy = (
        1.0
        if tls.get("forward_secrecy") is True
        else 0.0
    )

    certificate_validity = (
        1.0
        if (
            certificate
            and not certificate.get(
                "expired",
                False,
            )
        )
        else 0.0
    )

    starttls_quality = (
        1.0
        if starttls.get("upgraded")
        else 0.0
    )

    return [
        modern_tls,
        cipher_quality,
        key_exchange_quality,
        forward_secrecy,
        certificate_validity,
        starttls_quality,
    ]


def analyze_anomaly(
    session: dict[str, Any],
) -> dict[str, Any]:

    features = build_features(session)

    vector = np.array(
        [features],
        dtype=float,
    )

    prediction = int(
        MODEL.predict(vector)[0]
    )

    raw_score = float(
        MODEL.decision_function(vector)[0]
    )

    is_anomaly = bool(
        prediction == -1
    )

    # Normalized presentation score.
    anomaly_strength = max(
        0.0,
        min(
            1.0,
            0.5 - raw_score,
        ),
    )

    classification = (
        "ANOMALOUS"
        if is_anomaly
        else "NORMAL"
    )

    return {
        "model": "Isolation Forest",
        "classification": classification,
        "is_anomaly": is_anomaly,
        "anomaly_strength": float(
            round(anomaly_strength, 3)
        ),
        "raw_model_score": float(
            round(raw_score, 5)
        ),
        "features": {
            "modern_tls": round(
                float(features[0]),
                3,
            ),
            "cipher_quality": round(
                float(features[1]),
                3,
            ),
            "key_exchange_quality": round(
                float(features[2]),
                3,
            ),
            "forward_secrecy": bool(
                features[3] == 1.0
            ),
            "valid_certificate": bool(
                features[4] == 1.0
            ),
            "starttls_upgraded": bool(
                features[5] == 1.0
            ),
        },
        "note": (
            "Prototype anomaly model trained on "
            "a controlled synthetic baseline. "
            "Model output is advisory and complements "
            "deterministic security rules."
        ),
    }