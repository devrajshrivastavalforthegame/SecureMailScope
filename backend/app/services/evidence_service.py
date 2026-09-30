from pathlib import Path
from hashlib import sha256
from uuid import uuid4
from datetime import datetime, timezone
import json


BASE_DIR = Path(__file__).resolve().parents[3]

UPLOAD_DIR = BASE_DIR / "uploads"
DATA_DIR = BASE_DIR / "data"
CASES_FILE = DATA_DIR / "cases.json"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)


def load_cases():
    if not CASES_FILE.exists():
        return []

    try:
        return json.loads(CASES_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []


def save_cases(cases):
    CASES_FILE.write_text(
        json.dumps(cases, indent=2),
        encoding="utf-8"
    )


async def save_evidence(upload_file):
    original_name = Path(upload_file.filename or "evidence.pcap").name
    extension = Path(original_name).suffix.lower()

    if extension not in {".pcap", ".pcapng"}:
        raise ValueError("Only .pcap and .pcapng files are supported.")

    case_id = (
        f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        f"-{uuid4().hex[:8].upper()}"
    )

    stored_name = f"{case_id}{extension}"
    stored_path = UPLOAD_DIR / stored_name

    file_hash = sha256()
    total_bytes = 0

    try:
        with stored_path.open("wb") as output:
            while True:
                chunk = await upload_file.read(1024 * 1024)

                if not chunk:
                    break

                output.write(chunk)
                file_hash.update(chunk)
                total_bytes += len(chunk)

    except Exception:
        if stored_path.exists():
            stored_path.unlink()
        raise

    case = {
        "case_id": case_id,
        "original_filename": original_name,
        "stored_filename": stored_name,
        "file_type": extension.lstrip("."),
        "size_bytes": total_bytes,
        "sha256": file_hash.hexdigest(),
        "status": "UPLOADED",
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    cases = load_cases()
    cases.append(case)
    save_cases(cases)

    return case
