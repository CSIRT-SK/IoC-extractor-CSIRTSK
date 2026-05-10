from __future__ import annotations

import re
from typing import Optional


IOC_SECTION_PATTERNS = [
    r"indicators of compromise",
    r"indicator of compromise",
    r"\biocs\b",
    r"\bioc\b",
]

IOC_SECTION_STOP_PATTERNS = [
    r"^tags$",
    r"^latest news$",
    r"^articles, news, reports$",
    r"^related articles$",
    r"^with contributions from\b",
]


def normalize(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip().lower())


def is_ioc_heading(line: str) -> bool:
    normalized = normalize(line)
    return any(re.search(pattern, normalized, re.IGNORECASE) for pattern in IOC_SECTION_PATTERNS)


def heading_score(line: str) -> int:
    normalized = normalize(line)
    if re.search(r"indicators? of compromise", normalized, re.IGNORECASE):
        return 3
    if re.search(r"\biocs\b", normalized, re.IGNORECASE):
        return 2
    if re.search(r"\bioc\b", normalized, re.IGNORECASE):
        return 1
    return 0


def is_section_stop(line: str) -> bool:
    normalized = normalize(line)
    return any(re.search(pattern, normalized, re.IGNORECASE) for pattern in IOC_SECTION_STOP_PATTERNS)


def extract_ioc_section_from_text(text: str) -> Optional[str]:
    lines = [line.rstrip() for line in text.splitlines()]

    start = None
    best_score = 0
    for i, line in enumerate(lines):
        if is_ioc_heading(line):
            score = heading_score(line)
            if score >= best_score:
                best_score = score
                start = i + 1

    if start is None:
        return None

    collected: list[str] = []
    for line in lines[start:]:
        if is_section_stop(line):
            break
        if line.strip():
            collected.append(line.strip())

    result = "\n".join(collected).strip()
    return result if result else None
