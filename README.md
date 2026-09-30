# SecureMailScope

## AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications

SecureMailScope is a passive PCAP analysis prototype for assessing the cryptographic security posture of secure email communications.

It analyzes captured SMTP traffic, reconstructs TCP sessions, evaluates STARTTLS state transitions, parses TLS and X.509 information, applies deterministic security rules, and supplements them with an advisory Isolation Forest anomaly detector.

## Core Pipeline

PCAP
→ SHA-256 Case Creation
→ TCP Session Reconstruction
→ SMTP Detection
→ STARTTLS State Machine
→ TLS Analysis
→ X.509 Analysis
→ Security Rules
→ Advisory ML
→ Explainable Posture Score
→ Packet Evidence
→ JSON / PDF Reports
→ React Dashboard

## Implemented Capabilities

- PCAP / PCAPNG evidence upload
- SHA-256 case identification
- TCP session reconstruction
- SMTP protocol detection
- STARTTLS state tracking
- TLS version analysis
- Cipher suite analysis
- Key-exchange analysis
- Forward-secrecy assessment
- SNI extraction
- X.509 certificate parsing
- Certificate validity checking
- Certificate hostname/SAN checking
- Deterministic severity-based findings
- Explainable 0–100 posture score
- Packet-level evidence references
- Isolation Forest anomaly detection
- React security dashboard
- JSON export
- PDF security assessment report

## Demo Scenarios

### Secure Scenario

File:

samples/full_secure_starttls.pcap

Expected result:

100 / 100
SECURE
0 findings
AI: NORMAL

### Risk Scenario

File:

samples/weak_tls_starttls.pcap

Expected result:

5 / 100
CRITICAL RISK
5 findings
AI: ANOMALOUS

## Backend Setup

Create and activate the virtual environment:

Windows PowerShell:

    python -m venv .venv
    .\.venv\Scripts\Activate.ps1

Install dependencies:

    pip install -r requirements.txt

Run FastAPI:

    python -m uvicorn backend.app.main:app

Backend:

    http://127.0.0.1:8000

Health check:

    http://127.0.0.1:8000/health

## Frontend Setup

Open a second PowerShell:

    cd frontend
    npm install
    npm run dev

Frontend:

    http://localhost:5173

## Demo Workflow

1. Start FastAPI.
2. Start the React frontend.
3. Open http://localhost:5173.
4. Upload a PCAP or select a demo scenario.
5. Review the posture score.
6. Inspect STARTTLS, TLS, certificate and AI results.
7. Open the Evidence Inspector.
8. Export JSON or PDF.

## AI Model Note

The Isolation Forest model is a prototype anomaly detector trained against a controlled synthetic baseline.

Its output is advisory and complements the deterministic security rules.

No production accuracy or real-world detection-rate claim is made by this prototype.

## Privacy

The prototype performs passive analysis on captured evidence and is designed for local processing.

Captured network data should be treated as sensitive forensic material.

## Current Scope

The current prototype provides deep analysis for SMTP / STARTTLS.

The broader architecture can be extended to IMAP, POP3 and larger multi-session evidence sets.

## Technologies

Backend:
- Python
- FastAPI
- Scapy
- cryptography
- scikit-learn
- ReportLab

Frontend:
- React
- TypeScript
- Vite
- lucide-react

## Project Status

SIH 2026 prototype
SecureMailScope
