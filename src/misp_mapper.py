from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class MISPAttributeData:
    type: str
    value: str
    category: str
    to_ids: bool = True
    comment: str = ""
    tags: List[str] = field(default_factory=list)


def build_attr(
    attr_type: str,
    value: str,
    category: str,
    to_ids: bool = True,
    comment: str = "",
    tags: Optional[List[str]] = None,
) -> MISPAttributeData:
    return MISPAttributeData(
        type=attr_type,
        value=value,
        category=category,
        to_ids=to_ids,
        comment=comment,
        tags=tags or [],
    )


def map_iocs_to_misp_attributes(
    iocs: Dict[str, List[str]],
    confidence: Optional[Dict[str, Dict[str, Dict[str, str]]]] = None,
) -> List[MISPAttributeData]:

    attributes: List[MISPAttributeData] = []

    for value in iocs.get("url", []):
        attributes.append(
            build_attr(
                attr_type="url",
                value=value,
                category="Network activity",
                to_ids=True,
                comment=build_comment("Extracted from article", "url", value, confidence),
                tags=build_tags("url", value, confidence),
            )
        )

    for value in iocs.get("ip-dst", []):
        attributes.append(
            build_attr(
                attr_type="ip-dst",
                value=value,
                category="Network activity",
                to_ids=True,
                comment=build_comment("Extracted from article", "ip-dst", value, confidence),
                tags=build_tags("ip-dst", value, confidence),
            )
        )

    for value in iocs.get("domain", []):
        attributes.append(
            build_attr(
                attr_type="domain",
                value=value,
                category="Network activity",
                to_ids=True,
                comment=build_comment("Extracted from article", "domain", value, confidence),
                tags=build_tags("domain", value, confidence),
            )
        )


    for value in iocs.get("email-src", []):
        attributes.append(
            build_attr(
                attr_type="email-src",
                value=value,
                category="Payload delivery",
                to_ids=False,
                comment=build_comment(
                    "Email extracted from article; review recommended",
                    "email-src",
                    value,
                    confidence,
                ),
                tags=build_tags("email-src", value, confidence),
            )
        )

    for value in iocs.get("md5", []):
        attributes.append(
            build_attr(
                attr_type="md5",
                value=value,
                category="Payload delivery",
                to_ids=True,
                comment=build_comment("Extracted from article", "md5", value, confidence),
                tags=build_tags("md5", value, confidence),
            )
        )

    for value in iocs.get("sha1", []):
        attributes.append(
            build_attr(
                attr_type="sha1",
                value=value,
                category="Payload delivery",
                to_ids=True,
                comment=build_comment("Extracted from article", "sha1", value, confidence),
                tags=build_tags("sha1", value, confidence),
            )
        )

    for value in iocs.get("sha256", []):
        attributes.append(
            build_attr(
                attr_type="sha256",
                value=value,
                category="Payload delivery",
                to_ids=True,
                comment=build_comment("Extracted from article", "sha256", value, confidence),
                tags=build_tags("sha256", value, confidence),
            )
        )

    for ioc_type, values in iocs.items():
        if not ioc_type.startswith("custom:"):
            continue
        for value in values:
            attributes.append(
                build_attr(
                    attr_type="text",
                    value=value,
                    category="External analysis",
                    to_ids=False,
                    comment=build_comment("Extracted by custom regex", ioc_type, value, confidence),
                    tags=build_tags(ioc_type, value, confidence),
                )
            )

    return deduplicate_attributes(attributes)


def build_comment(
    base_comment: str,
    ioc_type: str,
    value: str,
    confidence: Optional[Dict[str, Dict[str, Dict[str, str]]]],
) -> str:
    if not confidence:
        return base_comment

    data = confidence.get(ioc_type, {}).get(value)
    if not data:
        return base_comment

    level = data.get("level", "unknown")
    reason = data.get("reason", "not specified")
    return f"{base_comment}; confidence={level}; reason={reason}"


def build_tags(
    ioc_type: str,
    value: str,
    confidence: Optional[Dict[str, Dict[str, Dict[str, str]]]],
) -> List[str]:
    tags = [
        "source:article",
        "ioc-status:validated",
        f"ioc-type:{ioc_type}",
    ]

    if confidence:
        data = confidence.get(ioc_type, {}).get(value)
        if data:
            tags.append(f'confidence:{data.get("level", "unknown")}')

    return tags


def deduplicate_attributes(attributes: List[MISPAttributeData]) -> List[MISPAttributeData]:
    seen = set()
    output: List[MISPAttributeData] = []

    for attr in attributes:
        key = (attr.type, attr.value)
        if key in seen:
            continue
        seen.add(key)
        output.append(attr)

    return output
