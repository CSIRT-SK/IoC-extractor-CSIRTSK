from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set, Tuple


@dataclass
class ExtractedIOCs:
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    md5s: List[str] = field(default_factory=list)
    sha1s: List[str] = field(default_factory=list)
    sha256s: List[str] = field(default_factory=list)
    custom: Dict[str, List[str]] = field(default_factory=dict)
    normalized: List[Tuple[str, str, str]] = field(default_factory=list)

    def as_dict(self) -> Dict[str, List[str]]:
        base = {
            "url": self.urls,
            "ip-dst": self.ips,
            "domain": self.domains,
            "email-src": self.emails,
            "md5": self.md5s,
            "sha1": self.sha1s,
            "sha256": self.sha256s,
        }
        for name, values in self.custom.items():
            base[f"custom:{name}"] = values
        return base


URL_REGEX = re.compile(
    r"\b(?:(?:https?|hxxps?)://)[^\s<>()\"']+",
    re.IGNORECASE,
)

EMAIL_REGEX = re.compile(
    r"\b[a-zA-Z0-9._%+-]+(?:@|\[@\])[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

IP_REGEX = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
)

MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
HEX_ONLY_RE = re.compile(r"^[a-fA-F0-9]+$")
HASH_LENGTHS = {32, 40, 64}
SHA256_CONTEXT_RE = re.compile(r"\bsha\s*-?\s*256\b", re.IGNORECASE)

URL_CANDIDATE_REGEX = re.compile(
    r"\b(?:(?:https?|hxxps?)(?:://|\[://\]))[^\s<>()\"']+",
    re.IGNORECASE,
)
EMAIL_CANDIDATE_REGEX = re.compile(
    r"\b[a-zA-Z0-9._%+-]+(?:@|\[@\])[a-zA-Z0-9.\[\]{}()-]+"
    r"(?:\.|\[\.\]|\(\.\)|\{\.\})[a-zA-Z]{2,}\b"
)
IP_CANDIDATE_REGEX = re.compile(
    r"\b(?:\d{1,3}(?:\.|\[\.\]|\(\.\)|\{\.\})){3}\d{1,3}\b"
)
DOMAIN_CANDIDATE_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9-]+(?:\.|\[\.\]|\(\.\)|\{\.\}))+[a-zA-Z]{2,}\b"
)

DEFAULT_CUSTOM_REGEX_PATH = Path(__file__).resolve().parent.parent / "config" / "ioc_custom_regex.txt"


IGNORED_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "localhost",
}


def refang(text: str) -> str:
    replacements = {
        "hxxps[://]": "https://",
        "hxxp[://]": "http://",
        "https[://]": "https://",
        "http[://]": "http://",
        "hxxps://": "https://",
        "hxxp://": "http://",
        "HXXPS[://]": "https://",
        "HXXP[://]": "http://",
        "HTTPS[://]": "https://",
        "HTTP[://]": "http://",
        "[.]": ".",
        "(.)": ".",
        "{.}": ".",
        "[@]": "@",
        "(at)": "@",
        "[:]": ":",
    }

    result = text
    for old, new in replacements.items():
        result = result.replace(old, new)
    return result


def strip_trailing(value: str) -> str:
    return value.strip().strip(".,);]}>\"'")


def dedup(values: List[str], lowercase: bool = False) -> List[str]:
    seen: Set[str] = set()
    output: List[str] = []

    for value in values:
        cleaned = strip_trailing(value)
        if lowercase:
            cleaned = cleaned.lower()

        if not cleaned:
            continue

        if cleaned not in seen:
            seen.add(cleaned)
            output.append(cleaned)

    return output


def repair_split_hash_lines(text: str) -> str:
    lines = text.splitlines()
    repaired: list[str] = []
    sha256_context_until = -1
    i = 0

    while i < len(lines):
        current = lines[i].strip()
        if SHA256_CONTEXT_RE.search(current):
            sha256_context_until = i + 80

        if HEX_ONLY_RE.fullmatch(current) and i <= sha256_context_until:
            joined = join_hex_fragments(lines, i, target_length=64)
            if joined is not None:
                digest, consumed = joined
                repaired.append(digest)
                i += consumed
                continue

        if HEX_ONLY_RE.fullmatch(current) and len(current) not in HASH_LENGTHS:
            for target_length in (64, 40, 32):
                joined = join_hex_fragments(lines, i, target_length=target_length)
                if joined is not None:
                    digest, consumed = joined
                    repaired.append(digest)
                    i += consumed
                    break
            else:
                repaired.append(lines[i])
                i += 1
            continue

        repaired.append(lines[i])
        i += 1

    return "\n".join(repaired)


def join_hex_fragments(
    lines: List[str],
    start: int,
    target_length: int,
) -> Tuple[str, int] | None:
    digest = lines[start].strip()
    if len(digest) >= target_length:
        return None

    consumed = 1
    for next_line in lines[start + 1 :]:
        candidate = next_line.strip()
        if not HEX_ONLY_RE.fullmatch(candidate):
            return None
        if len(digest) + len(candidate) > target_length:
            return None

        digest += candidate
        consumed += 1
        if len(digest) == target_length:
            return digest, consumed

    return None


def collect_extraction_normalizations(text: str) -> List[Tuple[str, str, str]]:
    candidates = [
        ("url", URL_CANDIDATE_REGEX.findall(text), False),
        ("email-src", EMAIL_CANDIDATE_REGEX.findall(text), True),
        ("ip-dst", IP_CANDIDATE_REGEX.findall(text), False),
        ("domain", DOMAIN_CANDIDATE_REGEX.findall(text), True),
        ("md5", MD5_REGEX.findall(text), True),
        ("sha1", SHA1_REGEX.findall(text), True),
        ("sha256", SHA256_REGEX.findall(text), True),
    ]
    normalized: List[Tuple[str, str, str]] = []
    seen: Set[Tuple[str, str, str]] = set()

    for ioc_type, values, lowercase in candidates:
        for raw_value in values:
            cleaned = strip_trailing(refang(raw_value))
            if lowercase:
                cleaned = cleaned.lower()

            if not cleaned or cleaned == raw_value:
                continue

            key = (ioc_type, raw_value, cleaned)
            if key in seen:
                continue

            seen.add(key)
            normalized.append(key)

    return normalized


def load_custom_regex_patterns(
    path: str | Path = DEFAULT_CUSTOM_REGEX_PATH,
) -> Dict[str, re.Pattern[str]]:
    regex_path = Path(path)
    if not regex_path.exists():
        return {}

    patterns: Dict[str, re.Pattern[str]] = {}
    for line_number, line in enumerate(regex_path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped_line = line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            continue
        value = line.rstrip()

        name, separator, pattern = value.partition(":")
        if not separator:
            raise ValueError(
                f"Invalid custom regex format at {regex_path}:{line_number}. "
                "Expected <name>:<regex>."
            )

        normalized_name = name.strip().lower()
        if not normalized_name:
            raise ValueError(
                f"Missing custom regex name at {regex_path}:{line_number}."
            )
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", normalized_name):
            raise ValueError(
                f"Invalid custom regex name '{name.strip()}' at {regex_path}:{line_number}."
            )

        raw_pattern = pattern.strip()
        if not raw_pattern:
            raise ValueError(
                f"Missing custom regex pattern for '{normalized_name}' "
                f"at {regex_path}:{line_number}."
            )

        try:
            patterns[normalized_name] = re.compile(raw_pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(
                f"Invalid custom regex pattern for '{normalized_name}' "
                f"at {regex_path}:{line_number}: {exc}"
            ) from exc

    return patterns


def extract_custom_iocs(
    text: str,
    patterns: Dict[str, re.Pattern[str]],
) -> Dict[str, List[str]]:
    custom_matches: Dict[str, List[str]] = {}

    for name, pattern in patterns.items():
        matches: List[str] = []
        for match in pattern.finditer(text):
            if match.groups():
                value = next((group for group in match.groups() if group), match.group(0))
            else:
                value = match.group(0)
            matches.append(value)

        custom_matches[name] = dedup(matches)

    return custom_matches


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_probably_domain(value: str) -> bool:
    lower = value.lower()

    if lower.startswith(("http://", "https://")):
        return False
    if "@" in lower:
        return False
    if lower in IGNORED_DOMAINS:
        return False
    if is_valid_ip(lower):
        return False

    return "." in lower


def extract_iocs(
    text: str,
    custom_patterns: Dict[str, re.Pattern[str]] | None = None,
) -> ExtractedIOCs:
    text = repair_split_hash_lines(text)
    extraction_normalized = collect_extraction_normalizations(text)
    text = refang(text)

    urls = dedup(URL_REGEX.findall(text))
    emails = dedup(EMAIL_REGEX.findall(text), lowercase=True)

    raw_ips = dedup(IP_REGEX.findall(text))
    ips = [ip for ip in raw_ips if is_valid_ip(ip)]

    raw_domains = dedup(DOMAIN_REGEX.findall(text), lowercase=True)
    domains = [d for d in raw_domains if is_probably_domain(d)]

    md5s = dedup(MD5_REGEX.findall(text), lowercase=True)
    sha1s = dedup(SHA1_REGEX.findall(text), lowercase=True)
    sha256s = dedup(SHA256_REGEX.findall(text), lowercase=True)
    custom = extract_custom_iocs(text, custom_patterns or {})

    return ExtractedIOCs(
        urls=urls,
        ips=ips,
        domains=domains,
        emails=emails,
        md5s=md5s,
        sha1s=sha1s,
        sha256s=sha256s,
        custom=custom,
        normalized=extraction_normalized,
    )
