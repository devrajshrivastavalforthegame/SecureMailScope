from __future__ import annotations

import json
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4


BASE_DIR = Path(__file__).resolve().parents[3]

UPLOAD_DIR = BASE_DIR / "uploads"
DATA_DIR = BASE_DIR / "data"
CASES_FILE = DATA_DIR / "cases.json"

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_FILENAME_LENGTH = 255

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)


def load_cases():
    if not CASES_FILE.exists():
        return []

    try:
        data = json.loads(
            CASES_FILE.read_text(encoding="utf-8")
        )

        if not isinstance(data, list):
            return []

        return data

    except (json.JSONDecodeError, OSError):
        return []


def save_cases(cases):
    CASES_FILE.write_text(
        json.dumps(cases, indent=2),
        encoding="utf-8",
    )


def _validate_filename(filename: str) -> str:
    if not filename:
        raise ValueError("No file supplied.")

    if "\x00" in filename:
        raise ValueError("Invalid filename.")

    if any(ord(char) < 32 for char in filename):
        raise ValueError("Invalid filename.")

    original_name = Path(filename).name

    if not original_name:
        raise ValueError("Invalid filename.")

    if len(original_name) > MAX_FILENAME_LENGTH:
        raise ValueError(
            "Filename is too long."
        )

    return original_name


def _validate_extension(filename: str) -> str:
    extension = Path(filename).suffix.lower()

    if extension not in {".pcap", ".pcapng"}:
        raise ValueError(
            "Only .pcap and .pcapng files are supported."
        )

    return extension


def _validate_magic(header: bytes):
    if len(header) < 4:
        raise ValueError(
            "Uploaded file is too small to be a valid PCAP."
        )

    magic = header[:4]

    if magic in PCAP_MAGICS:
        return ".pcap"

    if magic == PCAPNG_MAGIC:
        return ".pcapng"

    raise ValueError(
        "File content does not match a supported PCAP/PCAPNG format."
    )


async def save_evidence(upload_file):
    original_name = _validate_filename(
        upload_file.filename or ""
    )

    extension = _validate_extension(
        original_name
    )

    case_id = (
        f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        f"-{uuid4().hex[:8].upper()}"
    )

    stored_name = f"{case_id}{extension}"

    upload_root = UPLOAD_DIR.resolve()
    stored_path = (UPLOAD_DIR / stored_name).resolve()

    if stored_path.parent != upload_root:
        raise ValueError(
            "Invalid evidence storage path."
        )

    file_hash = sha256()
    total_bytes = 0

    try:
        # Read enough bytes to verify the actual file signature.
        first_chunk = await upload_file.read(4096)

        if not first_chunk:
            raise ValueError(
                "Uploaded file is empty."
            )

        detected_extension = _validate_magic(
            first_chunk
        )

        if detected_extension != extension:
            raise ValueError(
                "File extension does not match its PCAP content."
            )

        if len(first_chunk) > MAX_UPLOAD_BYTES:
            raise ValueError(
                "File exceeds the 25 MB upload limit."
            )

        with stored_path.open("xb") as output:
            output.write(first_chunk)
            file_hash.update(first_chunk)
            total_bytes = len(first_chunk)

            while True:
                chunk = await upload_file.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                total_bytes += len(chunk)

                if total_bytes > MAX_UPLOAD_BYTES:
                    raise ValueError(
                        "File exceeds the 25 MB upload limit."
                    )

                output.write(chunk)
                file_hash.update(chunk)

    except ValueError:
        if stored_path.exists():
            stored_path.unlink()
        raise

    except OSError:
        if stored_path.exists():
            stored_path.unlink()

        raise ValueError(
            "Evidence could not be stored."
        )

    except Exception:
        if stored_path.exists():
            stored_path.unlink()
        raise

    finally:
        await upload_file.close()

    case = {
        "case_id": case_id,
        "original_filename": original_name,
        "stored_filename": stored_name,
        "file_type": extension.lstrip("."),
        "size_bytes": total_bytes,
        "sha256": file_hash.hexdigest(),
        "status": "UPLOADED",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    cases = load_cases()
    cases.append(case)
    save_cases(cases)

    return case
