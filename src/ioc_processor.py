from __future__ import annotations

import ipaddress
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote, unquote, urlsplit, urlunsplit


IOCMap = Dict[str, List[str]]
ConfidenceMap = Dict[str, Dict[str, Dict[str, str]]]


SUPPORTED_TYPES = (
    "url",
    "ip-dst",
    "domain",
    "email-src",
    "md5",
    "sha1",
    "sha256",
)

DEFAULT_IOC_EXCEPTIONS_PATH = Path(__file__).resolve().parent.parent / "config" / "ioc_exceptions.txt"
DEFAULT_IOC_ALLOWLIST_PATH = Path(__file__).resolve().parent.parent / "config" / "ioc_allowlist.txt"

HASH_LENGTHS = {
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
}

IGNORED_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "localhost",
}

BENIGN_DOMAIN_SUFFIXES = {
    "github.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "microsoft.com",
    "npmjs.org",
    "paloaltonetworks.com",
    "registrar-servers.com",
    "trendmicro.com",
}

BENIGN_EXACT_DOMAINS = {
    "packages.npm.org",
    "proton.me",
    "registry.npmjs.org",
}

COMMON_FILE_EXTENSIONS = {
    "bat",
    "cmd",
    "dll",
    "doc",
    "docm",
    "docx",
    "elf",
    "exe",
    "hta",
    "html",
    "jar",
    "js",
    "lnk",
    "pdf",
    "ps1",
    "py",
    "rtf",
    "sh",
    "vbs",
    "xls",
    "xlsm",
    "xlsx",
    "zip",
}

COMMON_TLDS = {
    "academy",
    "app",
    "arpa",
    "asia",
    "at",
    "au",
    "biz",
    "br",
    "ca",
    "cc",
    "ch",
    "cloud",
    "cn",
    "co",
    "com",
    "cz",
    "de",
    "dev",
    "edu",
    "es",
    "eu",
    "fi",
    "fr",
    "gov",
    "host",
    "info",
    "int",
    "io",
    "it",
    "jp",
    "kr",
    "me",
    "mil",
    "net",
    "nl",
    "no",
    "online",
    "onion",
    "org",
    "pl",
    "pro",
    "ru",
    "se",
    "shop",
    "site",
    "sk",
    "space",
    "store",
    "tech",
    "top",
    "tv",
    "ua",
    "uk",
    "us",
    "xyz",
}

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$"
)

EMAIL_RE = re.compile(
    r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)

HEX_RE = re.compile(r"^[a-f0-9]+$")


@dataclass
class ProcessingIssue:
    ioc_type: str
    value: str
    reason: str


@dataclass
class ProcessingReport:
    input_counts: Dict[str, int] = field(default_factory=dict)
    output_counts: Dict[str, int] = field(default_factory=dict)
    normalized: List[Tuple[str, str, str]] = field(default_factory=list)
    duplicates: List[Tuple[str, str]] = field(default_factory=list)
    rejected: List[ProcessingIssue] = field(default_factory=list)

    @property
    def total_input(self) -> int:
        return sum(self.input_counts.values())

    @property
    def total_output(self) -> int:
        return sum(self.output_counts.values())


def score_ioc_confidence(
    iocs: IOCMap,
    extraction_scope: str = "full_article",
) -> ConfidenceMap:
    confidence: ConfidenceMap = {}

    for ioc_type, values in iocs.items():
        confidence[ioc_type] = {}
        for value in values:
            level, reason = score_single_ioc(
                ioc_type,
                value,
                extraction_scope=extraction_scope,
            )
            confidence[ioc_type][value] = {
                "level": level,
                "reason": reason,
            }

    return confidence


def process_iocs_for_misp(
    iocs: IOCMap,
    allowlist: set[Tuple[str, str]] | None = None,
    extraction_normalized: List[Tuple[str, str, str]] | None = None,
) -> Tuple[IOCMap, ProcessingReport]:
    allowlist = allowlist if allowlist is not None else load_ioc_allowlist()
    report = ProcessingReport(
        input_counts={ioc_type: len(values) for ioc_type, values in iocs.items()}
    )
    processed: IOCMap = {ioc_type: [] for ioc_type in SUPPORTED_TYPES}
    seen: set[Tuple[str, str]] = set()

    for ioc_type, values in iocs.items():
        if ioc_type not in SUPPORTED_TYPES:
            if ioc_type.startswith("custom:"):
                process_custom_iocs(ioc_type, values, processed, seen, report)
                continue
            for value in values:
                report.rejected.append(
                    ProcessingIssue(ioc_type, value, "unsupported IoC type")
                )
            continue

        for raw_value in values:
            normalized = normalize_ioc(ioc_type, raw_value)
            if normalized is None and can_allow_invalid_ioc_type(ioc_type):
                allowlisted_normalized = normalize_ioc_for_allowlist(ioc_type, raw_value)
                if allowlisted_normalized and (ioc_type, allowlisted_normalized) in allowlist:
                    normalized = allowlisted_normalized

            if normalized is None:
                report.rejected.append(
                    ProcessingIssue(ioc_type, raw_value, "invalid value for type")
                )
                continue

            key = (ioc_type, normalized)
            if key in seen:
                report.duplicates.append(key)
                continue

            seen.add(key)
            processed[ioc_type].append(normalized)

            if normalized != raw_value:
                report.normalized.append((ioc_type, raw_value, normalized))

    merge_extraction_normalizations(processed, report, extraction_normalized or [])
    drop_domains_already_covered_by_urls(processed, report, allowlist)

    report.output_counts = {
        ioc_type: len(values)
        for ioc_type, values in processed.items()
        if values or ioc_type in iocs
    }
    return processed, report


def filter_source_site_noise(
    iocs: IOCMap,
    source_url: str,
    report: ProcessingReport | None = None,
    allowlist: set[Tuple[str, str]] | None = None,
) -> IOCMap:
    allowlist = allowlist if allowlist is not None else load_ioc_allowlist()
    source_host = urlsplit(source_url).hostname
    if not source_host:
        return iocs

    filtered = dict(iocs)
    kept_urls = []
    for url in iocs.get("url", []):
        if is_source_site_noise_url(url, source_host) and ("url", url) not in allowlist:
            if report is not None:
                report.rejected.append(
                    ProcessingIssue("url", url, "source site navigation or asset URL")
                )
            continue
        kept_urls.append(url)

    filtered["url"] = kept_urls

    kept_domains = []
    for domain in iocs.get("domain", []):
        if is_benign_domain(domain) and ("domain", domain) not in allowlist:
            if report is not None:
                report.rejected.append(
                    ProcessingIssue("domain", domain, "known benign infrastructure domain")
                )
            continue
        kept_domains.append(domain)

    filtered["domain"] = kept_domains

    kept_emails = []
    for email in iocs.get("email-src", []):
        domain = email.rsplit("@", 1)[-1]
        if is_benign_domain(domain) and ("email-src", email) not in allowlist:
            if report is not None:
                report.rejected.append(
                    ProcessingIssue("email-src", email, "known benign email provider domain")
                )
            continue
        kept_emails.append(email)

    filtered["email-src"] = kept_emails
    if report is not None:
        sync_output_counts(report, filtered)
    return filtered


def load_ioc_allowlist(
    path: str | Path = DEFAULT_IOC_ALLOWLIST_PATH,
) -> set[Tuple[str, str]]:
    return load_ioc_list(path, allow_invalid_types=True)


def load_ioc_exceptions(
    path: str | Path = DEFAULT_IOC_EXCEPTIONS_PATH,
) -> set[Tuple[str, str]]:
    return load_ioc_list(path, allow_invalid_types=False)


def load_ioc_list(
    path: str | Path,
    allow_invalid_types: bool,
) -> set[Tuple[str, str]]:
    list_path = Path(path)
    if not list_path.exists():
        return set()

    entries: set[Tuple[str, str]] = set()
    for line in list_path.read_text(encoding="utf-8").splitlines():
        value = line.split("#", 1)[0].strip()
        if not value:
            continue

        explicit_type = None
        for ioc_type in SUPPORTED_TYPES:
            prefix = f"{ioc_type}:"
            if value.lower().startswith(prefix):
                explicit_type = ioc_type
                value = value[len(prefix) :].strip()
                break

        if explicit_type:
            normalized = normalize_ioc(explicit_type, value)
            if normalized is None and allow_invalid_types:
                normalized = normalize_ioc_for_allowlist(explicit_type, value)
            if normalized:
                entries.add((explicit_type, normalized))
            continue

        for ioc_type in SUPPORTED_TYPES:
            normalized = normalize_ioc(ioc_type, value)
            if normalized is None and allow_invalid_types:
                normalized = normalize_ioc_for_allowlist(ioc_type, value)
            if normalized:
                entries.add((ioc_type, normalized))

    return entries


def apply_ioc_exceptions(
    iocs: IOCMap,
    report: ProcessingReport | None = None,
    exceptions: set[Tuple[str, str]] | None = None,
) -> IOCMap:
    exceptions = exceptions if exceptions is not None else load_ioc_exceptions()
    if not exceptions:
        return iocs

    filtered: IOCMap = {}
    for ioc_type, values in iocs.items():
        kept_values = []
        for value in values:
            if (ioc_type, value) in exceptions:
                if report is not None:
                    report.rejected.append(
                        ProcessingIssue(ioc_type, value, "custom IoC exception")
                    )
                continue
            kept_values.append(value)
        filtered[ioc_type] = kept_values

    if report is not None:
        sync_output_counts(report, filtered)

    return filtered


def score_single_ioc(
    ioc_type: str,
    value: str,
    extraction_scope: str,
) -> Tuple[str, str]:
    if extraction_scope == "ioc_section":
        return "high", "extracted from dedicated IoC section"

    if ioc_type.startswith("custom:"):
        return apply_scope_bias(
            "medium",
            "custom regex match; review recommended",
            extraction_scope,
        )

    if ioc_type in {"md5", "sha1", "sha256"}:
        return apply_scope_bias(
            "high",
            "cryptographic hash with exact expected length",
            extraction_scope,
        )

    if ioc_type == "ip-dst":
        ip = ipaddress.ip_address(value)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return apply_scope_bias(
                "low",
                "non-public IP address",
                extraction_scope,
            )
        return apply_scope_bias(
            "high",
            "valid public IP address",
            extraction_scope,
        )

    if ioc_type == "url":
        parts = urlsplit(value)
        if parts.path and parts.path not in {"", "/"}:
            return apply_scope_bias(
                "high",
                "valid URL with path",
                extraction_scope,
            )
        return apply_scope_bias(
            "medium",
            "valid URL with host only",
            extraction_scope,
        )

    if ioc_type == "domain":
        labels = value.split(".")
        if len(labels) >= 3:
            return apply_scope_bias(
                "high",
                "valid fully qualified hostname",
                extraction_scope,
            )
        return apply_scope_bias(
            "medium",
            "valid registrable domain",
            extraction_scope,
        )

    if ioc_type == "email-src":
        return apply_scope_bias(
            "medium",
            "valid email address; review recommended before to_ids",
            extraction_scope,
        )

    return apply_scope_bias(
        "low",
        "valid format but unsupported confidence heuristic",
        extraction_scope,
    )


def apply_scope_bias(
    base_level: str,
    base_reason: str,
    extraction_scope: str,
) -> Tuple[str, str]:
    if extraction_scope == "ioc_section":
        return "high", "extracted from dedicated IoC section"

    if extraction_scope in {"full_article", "file"} and base_level == "high":
        return "medium", f"{base_reason}; extracted from broader source"

    return base_level, base_reason


def is_source_site_noise_url(url: str, source_host: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False

    host = parts.hostname
    if not host:
        return False

    source_host = source_host.lower()
    host = host.lower()
    if host != source_host and not host.endswith(f".{source_host}"):
        return False

    path = parts.path.lower()
    noise_markers = (
        "/wp-content/",
        "/wp-includes/",
        "/wp-json/",
        "/tag/",
        "/category/",
        "/author/",
        "/assets/",
        "/static/",
        "/themes/",
        "/dist/",
        "/legal-notices/",
    )
    if any(marker in path for marker in noise_markers):
        return True

    noise_extensions = (
        ".css",
        ".gif",
        ".ico",
        ".jpg",
        ".jpeg",
        ".js",
        ".map",
        ".png",
        ".svg",
        ".webp",
        ".woff",
        ".woff2",
    )
    return path.endswith(noise_extensions)


def normalize_ioc(ioc_type: str, value: str) -> Optional[str]:
    value = clean_value(value)
    if not value:
        return None

    if ioc_type == "url":
        return normalize_url(value)
    if ioc_type == "ip-dst":
        return normalize_ip(value)
    if ioc_type == "domain":
        return normalize_domain(value, reject_file_like=True, require_known_tld=True)
    if ioc_type == "email-src":
        return normalize_email(value)
    if ioc_type in HASH_LENGTHS:
        return normalize_hash(value, HASH_LENGTHS[ioc_type])

    return None


def normalize_ioc_for_allowlist(ioc_type: str, value: str) -> Optional[str]:
    value = clean_value(value)
    if not value:
        return None

    if ioc_type == "domain":
        return normalize_domain(value, reject_file_like=False, require_known_tld=False)
    if ioc_type == "url":
        return normalize_url(value)
    if ioc_type == "email-src":
        return normalize_email_allowing_default_blocked_domains(value)

    return normalize_ioc(ioc_type, value)


def can_allow_invalid_ioc_type(ioc_type: str) -> bool:
    return ioc_type in {"domain", "url", "email-src"}


def clean_value(value: str) -> str:
    value = str(value).strip()
    value = refang(value)
    return value.strip().strip(".,;:)]}>\"'")


def refang(value: str) -> str:
    replacements = {
        "hxxps[://]": "https://",
        "hxxp[://]": "http://",
        "hxxps://": "https://",
        "hxxp://": "http://",
        "HXXPS[://]": "https://",
        "HXXP[://]": "http://",
        "HXXPS://": "https://",
        "HXXP://": "http://",
        "[.]": ".",
        "(.)": ".",
        "{.}": ".",
        "[@]": "@",
        "(at)": "@",
        "[:]": ":",
    }

    result = value
    for old, new in replacements.items():
        result = result.replace(old, new)
    return result


def normalize_url(value: str) -> Optional[str]:
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"}:
        return None
    if not parts.netloc:
        return None

    host = parts.hostname
    if not host:
        return None

    normalized_host = normalize_host(host)
    if normalized_host is None:
        return None

    try:
        port = parts.port
    except ValueError:
        return None

    if port is not None and not (1 <= port <= 65535):
        return None

    netloc = normalized_host
    if port is not None:
        netloc = f"{netloc}:{port}"

    path = quote(posixpath.normpath(unquote(parts.path or "/")), safe="/%:@")
    if parts.path.endswith("/") and not path.endswith("/"):
        path += "/"
    if path == ".":
        path = "/"

    query = quote(unquote(parts.query), safe="=&?/:,%+@")
    fragment = quote(unquote(parts.fragment), safe="=&?/:,%+@")
    return urlunsplit((parts.scheme.lower(), netloc, path, query, fragment))


def normalize_host(host: str) -> Optional[str]:
    ip = normalize_ip(host)
    if ip:
        return ip
    return normalize_domain(host, reject_file_like=False, require_known_tld=False)


def normalize_ip(value: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def normalize_domain(
    value: str,
    reject_file_like: bool,
    require_known_tld: bool,
) -> Optional[str]:
    domain = value.rstrip(".").lower()
    if domain in IGNORED_DOMAINS:
        return None
    if "@" in domain or "/" in domain or ":" in domain:
        return None
    if normalize_ip(domain):
        return None

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if not DOMAIN_RE.match(domain):
        return None

    tld = domain.rsplit(".", 1)[1]
    if reject_file_like and tld in COMMON_FILE_EXTENSIONS:
        return None
    if require_known_tld and tld not in COMMON_TLDS:
        return None

    return domain


def is_benign_domain(value: str) -> bool:
    domain = value.lower().rstrip(".")
    if domain in BENIGN_EXACT_DOMAINS:
        return True
    return any(
        domain == suffix or domain.endswith(f".{suffix}")
        for suffix in BENIGN_DOMAIN_SUFFIXES
    )


def normalize_email(value: str) -> Optional[str]:
    email = value.lower()
    if not EMAIL_RE.match(email):
        return None

    local_part, domain = email.rsplit("@", 1)
    normalized_domain = normalize_domain(
        domain,
        reject_file_like=False,
        require_known_tld=True,
    )
    if not normalized_domain:
        return None

    return f"{local_part}@{normalized_domain}"


def normalize_email_allowing_default_blocked_domains(value: str) -> Optional[str]:
    email = value.lower()
    if not EMAIL_RE.match(email):
        return None

    local_part, domain = email.rsplit("@", 1)
    normalized_domain = normalize_domain(
        domain,
        reject_file_like=False,
        require_known_tld=False,
    )
    if not normalized_domain:
        return None

    return f"{local_part}@{normalized_domain}"


def normalize_hash(value: str, expected_length: int) -> Optional[str]:
    digest = value.lower()
    if len(digest) != expected_length:
        return None
    if not HEX_RE.match(digest):
        return None
    return digest


def drop_domains_already_covered_by_urls(
    iocs: IOCMap,
    report: ProcessingReport,
    allowlist: set[Tuple[str, str]],
) -> None:
    urls = iocs.get("url", [])
    domains = iocs.get("domain", [])
    if not urls or not domains:
        return

    hosts = {host for host in (url_host(url) for url in urls) if host}
    if not hosts:
        return

    kept_domains = []
    for domain in domains:
        if (domain in hosts or any(host.endswith(f".{domain}") for host in hosts)) and (
            "domain",
            domain,
        ) not in allowlist:
            report.rejected.append(
                ProcessingIssue("domain", domain, "already covered by URL host")
            )
            continue
        kept_domains.append(domain)

    iocs["domain"] = kept_domains


def url_host(url: str) -> Optional[str]:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def sync_output_counts(report: ProcessingReport, iocs: IOCMap) -> None:
    report.output_counts = {
        ioc_type: len(values)
        for ioc_type, values in iocs.items()
        if values or ioc_type in report.output_counts
    }


def merge_extraction_normalizations(
    iocs: IOCMap,
    report: ProcessingReport,
    extraction_normalized: List[Tuple[str, str, str]],
) -> None:
    if not extraction_normalized:
        return

    final_values = {
        (ioc_type, value)
        for ioc_type, values in iocs.items()
        for value in values
    }
    reported = set(report.normalized)
    reported_by_final = {
        (ioc_type, normalized): index
        for index, (ioc_type, _raw, normalized) in enumerate(report.normalized)
    }

    for ioc_type, raw_value, extracted_value in extraction_normalized:
        if ioc_type.startswith("custom:"):
            final_value = normalize_custom_ioc(extracted_value)
        else:
            final_value = normalize_ioc(ioc_type, extracted_value)

        if final_value is None:
            continue
        if (ioc_type, final_value) not in final_values:
            continue
        if raw_value == final_value:
            continue

        item = (ioc_type, raw_value, final_value)
        if item in reported:
            continue

        final_key = (ioc_type, final_value)
        existing_index = reported_by_final.get(final_key)
        if existing_index is not None:
            old_item = report.normalized[existing_index]
            reported.discard(old_item)
            report.normalized[existing_index] = item
            reported.add(item)
            continue

        report.normalized.append(item)
        reported.add(item)
        reported_by_final[final_key] = len(report.normalized) - 1


def process_custom_iocs(
    ioc_type: str,
    values: List[str],
    processed: IOCMap,
    seen: set[Tuple[str, str]],
    report: ProcessingReport,
) -> None:
    processed.setdefault(ioc_type, [])

    for raw_value in values:
        normalized = normalize_custom_ioc(raw_value)
        if normalized is None:
            report.rejected.append(
                ProcessingIssue(ioc_type, raw_value, "empty custom regex match")
            )
            continue

        key = (ioc_type, normalized)
        if key in seen:
            report.duplicates.append(key)
            continue

        seen.add(key)
        processed[ioc_type].append(normalized)

        if normalized != raw_value:
            report.normalized.append((ioc_type, raw_value, normalized))


def normalize_custom_ioc(value: str) -> Optional[str]:
    normalized = clean_value(value)
    if not normalized:
        return None
    return normalized
