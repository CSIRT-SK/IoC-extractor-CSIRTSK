from __future__ import annotations

import argparse
import logging
import sys
import warnings
from dataclasses import dataclass

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

try:
    import urllib3
except ImportError:
    urllib3 = None

from src.article_fetcher import fetch_article
from src.file_loader import load_input_file
from src.ioc_extractor import extract_iocs, load_custom_regex_patterns
from src.ioc_processor import (
    ConfidenceMap,
    ProcessingReport,
    apply_ioc_exceptions,
    filter_source_site_noise,
    load_ioc_allowlist,
    process_iocs_for_misp,
    score_ioc_confidence,
)
from src.json_exporter import save_iocs_to_json
from src.metrics import compute_runtime_metrics
from src.misp_exporter import (
    MISPEventDiff,
    create_event,
    find_existing_event_by_source_url,
    get_existing_event_diff,
    update_existing_event,
)
from src.misp_mapper import map_iocs_to_misp_attributes
from src.section_extractor import extract_ioc_section_from_text


warnings.filterwarnings("ignore")
logging.getLogger("pymisp").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests").setLevel(logging.ERROR)
if urllib3 is not None:
    urllib3.disable_warnings()


@dataclass
class InputContent:
    title: str
    source: str
    text: str
    extraction_scope: str


def print_preview(title: str, url: str, iocs: dict[str, list[str]]) -> None:
    print("\n=== PREVIEW ===")
    print(f"- Title: {title}")
    print(f"- URL:   {url}")
    print()

    total = 0
    for ioc_type, values in iocs.items():
        if not values:
            continue

        print(f"[{ioc_type}] ({len(values)})")
        for value in values:
            print(f"\t- {value}")
        print()

        total += len(values)

    print(f"[*] IoC Count: {total}\n")


def print_confidence_preview(confidence: ConfidenceMap) -> None:
    print("=== IOC CONFIDENCE ===")
    for ioc_type, values in confidence.items():
        if not values:
            continue

        print(f"[{ioc_type}]")
        for value, data in values.items():
            print(f"\t- {value}: {data['level']} ({data['reason']})")
        print()


def print_misp_preview(attributes) -> None:
    print("=== MISP ATTRIBUTE PREVIEW ===")
    for attr in attributes:
        print(
            f"\t- type={attr.type}, value={attr.value}, "
            f"category={attr.category}, to_ids={attr.to_ids}"
            #f"tags={attr.tags}"
        )
    print()


def print_misp_event_diff(diff: MISPEventDiff) -> None:
    print("=== MISP EVENT DIFF ===")
    print(f"- Existing MISP event ID: {diff.event_id}")
    print(f"- New attributes to be added: {len(diff.new_attributes)}")
    print(f"- New objects to be added: {len(diff.new_objects)}")
    print(f"- Attributes already present in the event: {len(diff.unchanged_attributes)}")
    print(f"- Objects already present in the event: {len(diff.unchanged_objects)}")

    if diff.new_attributes:
        print("\n[+] Attributes to be added:")
        for attr in diff.new_attributes:
            print(
                f"\t+ type={attr.type}, value={attr.value}, "
                f"category={attr.category}, to_ids={attr.to_ids}"
                #f"tags={attr.tags}"
            )
    if diff.new_objects:
        print("\n[+] Objects to be added:")
        for obj in diff.new_objects:
            print(
                f"\t+ type={obj.type}, value={obj.value}, "
                f"category={obj.category}, to_ids={obj.to_ids}"
                #f"tags={obj.tags}"
            )
    if not diff.new_attributes and not diff.new_objects:
        print("\n[-] Event already contains all extracted attributes.")

    if diff.unchanged_attributes:
        print("\n[*] Attributes with no changes:")
        for attr in diff.unchanged_attributes:
            print(f"\t= type={attr.type}, value={attr.value}")
    if diff.unchanged_objects:
        print("\n[*] Objects with no changes:")
        for obj in diff.unchanged_objects:
            print(f"\t= type={obj.type}, value={obj.value}")
    print()


def print_processing_report(report: ProcessingReport) -> None:
    print("=== IOC VALIDATION REPORT ===")
    print(f"Input:  {report.total_input}")
    print(f"Output: {report.total_output}")
    print(f"Normalized: {len(report.normalized)}")
    print(f"Duplicates: {len(report.duplicates)}")
    print(f"Rejected: {len(report.rejected)}")

    if report.rejected:
        print("\n[*] Rejected values (with reasons):")
        for issue in report.rejected:
            print(f"\t- [{issue.ioc_type}] {issue.value} ({issue.reason})")
    print()


def print_metrics(metrics: dict) -> None:
    print("=== METRICS ===")
    print(f"Raw IoCs: {metrics['total_raw_iocs']}")
    print(f"Valid IoCs: {metrics['total_valid_iocs']}")
    print(f"Rejected IoCs: {metrics['rejected']} ({metrics['rejection_ratio']:.2%})")
    print(f"Duplicates removed: {metrics['duplicates_removed']} ({metrics['deduplication_ratio']:.2%})")
    print(f"Normalized: {metrics['normalized']}")
    print(f"Valid ratio: {metrics['valid_ratio']:.2%}")

    if metrics["confidence"]:
        print("Confidence level:")
        for level, count in sorted(metrics["confidence"].items()):
            print(f"\t- {level}: {count}")
    print()


def looks_useful(text: str | None) -> bool:
    if not text:
        return False
    if len(text.strip()) < 50:
        return False

    lower = text.lower()
    markers = ["http", "hxxp", ".", "@", "sha", "md5", "ip", "domain"]
    return any(marker in lower for marker in markers)


def load_input_content(url: str | None, file_path: str | None) -> InputContent:
    if url:
        article = fetch_article(url)
        ioc_section = extract_ioc_section_from_text(article.text)

        if ioc_section and looks_useful(ioc_section):
            print("[+] IoCs found in a dedicated article section!\n")
            text_for_extraction = ioc_section
            extraction_scope = "ioc_section"
        else:
            print("[-] No dedicated IoC section found, whole article will be searched\n")
            text_for_extraction = article.text
            extraction_scope = "full_article"

        return InputContent(
            title=article.title,
            source=article.url,
            text=text_for_extraction,
            extraction_scope=extraction_scope,
        )

    if file_path:
        document = load_input_file(file_path)
        return InputContent(
            title=document.title,
            source=document.source,
            text=document.text,
            extraction_scope="file",
        )

    raise ValueError("Missing --url or --file parameters")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="IoC extractor from articles with MISP parser",
        #epilog=(
        #    "Poznámka: Pri vypracovaní projektu boli využité nástroje "
        #    "generatívnej umelej inteligencie na konzultáciu návrhu riešenia, "
        #    "úpravu zdrojového kódu, ladenie chýb a kontrolu implementácie. "
        #    "Výsledný návrh riešenia, implementačné rozhodnutia a zdrojový kód "
        #    "boli vypracované a overené autorom."
        #),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--url", help="article URL")
    input_group.add_argument("--file", help="CSV/PDF file path")
    parser.add_argument("--push", action="store_true", help="upload event to MISP after processing")
    parser.add_argument(
        "--save-json",
        help="JSON output path",
    )
    args = parser.parse_args()

    try:
        input_content = load_input_content(args.url, args.file)

        custom_patterns = load_custom_regex_patterns()
        extracted = extract_iocs(input_content.text, custom_patterns=custom_patterns)
        raw_iocs = extracted.as_dict()
        allowlist = load_ioc_allowlist()
        iocs, processing_report = process_iocs_for_misp(
            raw_iocs,
            allowlist=allowlist,
            extraction_normalized=extracted.normalized,
        )
        iocs = filter_source_site_noise(iocs, input_content.source, processing_report, allowlist=allowlist)
        iocs = apply_ioc_exceptions(iocs, processing_report)
        confidence = score_ioc_confidence(
            iocs,
            extraction_scope=input_content.extraction_scope,
        )
        metrics = compute_runtime_metrics(iocs, processing_report, confidence)

        print_preview(input_content.title, input_content.source, iocs)
        print_processing_report(processing_report)
        print_confidence_preview(confidence)
        print_metrics(metrics)

        misp_attributes = map_iocs_to_misp_attributes(iocs, confidence=confidence)
        print_misp_preview(misp_attributes)

        if args.save_json:
            output_path = save_iocs_to_json(
                output_path=args.save_json,
                title=input_content.title,
                source_url=input_content.source,
                extraction_scope=input_content.extraction_scope,
                iocs=iocs,
                confidence=confidence,
                metrics=metrics,
            )
            print(f"[+] JSON saved to: {output_path}")

        if not args.push:
            return 0

        confirm = input("[?] Create MISP event? [y/n]: ").strip().lower()
        if confirm != "y":
            print("[-] Cancelled")
            return 0

        existing_event_id = find_existing_event_by_source_url(input_content.source)
        if existing_event_id:
            diff = get_existing_event_diff(
                event_id=existing_event_id,
                title=input_content.title,
                source_url=input_content.source,
                attributes=misp_attributes,
            )
            print_misp_event_diff(diff)

            if not diff.has_changes:
                print(f"[!] Event already exists and has no new attributes, ID: {existing_event_id}")
                return 0

            update_confirm = input("[?] Update MISP event with these changes? [y/n]: ").strip().lower()
            if update_confirm != "y":
                print("[-] Update cancelled")
                return 0

            updated_diff = update_existing_event(
                event_id=existing_event_id,
                title=input_content.title,
                source_url=input_content.source,
                attributes=misp_attributes,
            )
            added_count = (
                len(diff.new_attributes)
                + len(diff.new_objects)
                - len(updated_diff.new_attributes)
                - len(updated_diff.new_objects)
            )
            print(
                f"[+] Done, updated MISP event with ID: {existing_event_id}, "
                f"[+] Amount of updated attributes: {added_count}"
            )
            return 0

        event_id, created = create_event(
            title=input_content.title,
            source_url=input_content.source,
            attributes=misp_attributes,
        )
        if created:
            print(f"[+] Done, created new MISP event with ID: {event_id}")
        else:
            print(f"Event already exists in MISP, using its ID: {event_id}")
        return 0

    except Exception as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
