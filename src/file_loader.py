from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class InputDocument:
    source: str
    title: str
    text: str


def load_input_file(path: str | Path) -> InputDocument:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Subor neexistuje: {file_path}")
    if not file_path.is_file():
        raise ValueError(f"Cesta nie je subor: {file_path}")

    suffix = file_path.suffix.lower()
    if suffix == ".csv":
        text = read_csv_text(file_path)
    elif suffix == ".txt":
        text = read_text_file(file_path)
    elif suffix == ".pdf":
        text = read_pdf_text(file_path)
    else:
        raise ValueError("Podporovane su iba CSV, TXT a PDF subory.")

    if not text.strip():
        raise ValueError(f"Nepodarilo sa extrahovat text zo suboru: {file_path}")

    return InputDocument(
        source=str(file_path.resolve()),
        title=file_path.name,
        text=text,
    )


def read_csv_text(path: Path) -> str:
    rows: list[str] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        sample = handle.read(4096)
        handle.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample)
        except csv.Error:
            dialect = csv.excel

        reader = csv.reader(handle, dialect)
        for row in reader:
            cleaned = [cell.strip() for cell in row if cell.strip()]
            if cleaned:
                rows.append(" ".join(cleaned))

    return "\n".join(rows)


def read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def read_pdf_text(path: Path) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise RuntimeError(
            "PDF extrakcia vyzaduje balik pypdf. Spust: pip install -r requirements.txt"
        ) from exc

    reader = PdfReader(str(path))
    pages = []
    for page in reader.pages:
        text = page.extract_text() or ""
        if text.strip():
            pages.append(text.strip())

    return repair_pdf_text_artifacts("\n".join(pages))


HEX_HASH_LENGTHS = {32, 40, 64}
HEX_ONLY_RE = re.compile(r"^[a-fA-F0-9]+$")
NPM_VERSION_HASH_RE = re.compile(
    r"(?P<prefix>[A-Za-z0-9@._/-]+@\d+\.\d+\.\d+)"
    r"(?P<digest>[a-fA-F0-9]{40})(?![a-fA-F0-9])"
)


def repair_pdf_text_artifacts(text: str) -> str:
    text = join_split_hex_hash_lines(text)
    text = NPM_VERSION_HASH_RE.sub(r"\g<prefix> \g<digest>", text)
    return text


_repair_pdf_text_artifacts = repair_pdf_text_artifacts


def join_split_hex_hash_lines(text: str) -> str:
    lines = text.splitlines()
    repaired: list[str] = []
    i = 0

    while i < len(lines):
        current = lines[i].strip()

        if HEX_ONLY_RE.fullmatch(current) and len(current) not in HEX_HASH_LENGTHS:
            digest = current
            consumed = 0
            joined = False

            for next_line in lines[i + 1 :]:
                candidate = next_line.strip()
                if not HEX_ONLY_RE.fullmatch(candidate):
                    break
                if len(digest) + len(candidate) > max(HEX_HASH_LENGTHS):
                    break

                digest += candidate
                consumed += 1
                if len(digest) in HEX_HASH_LENGTHS:
                    repaired.append(digest)
                    i += consumed + 1
                    joined = True
                    break
            else:
                consumed = 0

            if joined:
                continue

        repaired.append(lines[i])
        i += 1

    return "\n".join(repaired)
