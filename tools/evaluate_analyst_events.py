from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from time import perf_counter
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

from app import load_input_content
from src.ioc_extractor import extract_iocs, load_custom_regex_patterns
from src.ioc_processor import (
    apply_ioc_exceptions,
    filter_source_site_noise,
    load_ioc_allowlist,
    process_iocs_for_misp,
    score_ioc_confidence,
)
from src.metrics import aggregate_evaluations, compute_runtime_metrics, evaluate_iocs


ANALYST_DIR = ROOT / "IOC_analyst"
DEFAULT_OUTPUT_DIR = ROOT / "outputs" / "evaluation"
SUPPORTED_TYPES = {"url", "ip-dst", "domain", "email-src", "md5", "sha1", "sha256"}
IGNORED_METADATA_TYPES = {"link"}
IGNORED_REPORT_RELATIONS = {"link", "title"}


def _load_analyst_event(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload["response"][0]["Event"]


def _iter_event_attributes(event: dict[str, Any]) -> list[tuple[str | None, dict[str, Any], str | None]]:
    items: list[tuple[str | None, dict[str, Any], str | None]] = []

    for attr in event.get("Attribute", []):
        items.append((None, attr, None))

    for obj in event.get("Object", []):
        object_name = obj.get("name")
        for attr in obj.get("Attribute", []):
            items.append((object_name, attr, attr.get("object_relation")))

    return items


def _extract_source_url(event: dict[str, Any]) -> str:
    for object_name, attr, relation in _iter_event_attributes(event):
        if object_name == "report" and relation == "link":
            return attr.get("value", "")
    raise ValueError(f"Missing report link for analyst event '{event.get('info', '<unknown>')}'.")


def _collect_reference_values(event: dict[str, Any]) -> tuple[str, list[str], list[dict[str, str]]]:
    source_url = _extract_source_url(event)
    values: list[str] = []
    unsupported: list[dict[str, str]] = []

    for object_name, attr, relation in _iter_event_attributes(event):
        attr_type = attr.get("type", "")
        value = attr.get("value", "")
        comment = attr.get("comment", "")

        if object_name == "report" and relation in IGNORED_REPORT_RELATIONS:
            continue
        if attr_type in IGNORED_METADATA_TYPES:
            continue
        if not value:
            continue

        values.append(value)

        if attr_type in SUPPORTED_TYPES:
            continue
        if attr_type == "hostname":
            continue
        if attr_type == "text" and value.startswith("packages.npm.org/"):
            continue

        unsupported.append(
            {
                "type": attr_type,
                "value": value,
                "object": object_name or "",
                "relation": relation or "",
                "comment": comment,
            }
        )

    return source_url, values, unsupported


def _normalize_reference_iocs(values: list[str]) -> dict[str, list[str]]:
    joined = "\n".join(values)
    extracted = extract_iocs(joined, custom_patterns=load_custom_regex_patterns())
    normalized, _ = process_iocs_for_misp(extracted.as_dict(), allowlist=set())
    return {ioc_type: items for ioc_type, items in normalized.items() if items}


def _run_prediction(source_url: str) -> tuple[dict[str, list[str]], dict[str, Any], str, str, float]:
    started = perf_counter()
    input_content = load_input_content(source_url, None)
    extracted = extract_iocs(
        input_content.text,
        custom_patterns=load_custom_regex_patterns(),
    )
    raw_iocs = extracted.as_dict()
    allowlist = load_ioc_allowlist()
    iocs, processing_report = process_iocs_for_misp(raw_iocs, allowlist=allowlist)
    iocs = filter_source_site_noise(iocs, input_content.source, processing_report, allowlist=allowlist)
    iocs = apply_ioc_exceptions(iocs, processing_report)
    confidence = score_ioc_confidence(iocs, extraction_scope=input_content.extraction_scope)
    runtime_metrics = compute_runtime_metrics(iocs, processing_report, confidence)
    elapsed_ms = round((perf_counter() - started) * 1000, 2)
    return iocs, runtime_metrics, input_content.title, input_content.extraction_scope, elapsed_ms


def _evaluate_event(path: Path) -> dict[str, Any]:
    event = _load_analyst_event(path)
    source_url, reference_values, unsupported = _collect_reference_values(event)
    expected = _normalize_reference_iocs(reference_values)
    predicted, runtime_metrics, title, extraction_scope, elapsed_ms = _run_prediction(source_url)
    evaluation = evaluate_iocs(predicted, expected)

    return {
        "event_file": path.name,
        "event_info": event.get("info", ""),
        "source_url": source_url,
        "predicted_title": title,
        "extraction_scope": extraction_scope,
        "runtime_ms": elapsed_ms,
        "runtime_metrics": runtime_metrics,
        "expected_by_type": {ioc_type: len(values) for ioc_type, values in expected.items()},
        "predicted_by_type": {ioc_type: len(values) for ioc_type, values in predicted.items() if values},
        "unsupported_reference_items": unsupported,
        "unsupported_reference_count": len(unsupported),
        **evaluation,
    }


def _build_markdown(results: list[dict[str, Any]], aggregate: dict[str, Any]) -> str:
    lines = [
        "# Analyst Comparison Report",
        "",
        "## Aggregate",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Samples | {len(results)} |",
        f"| Precision | {aggregate['precision']:.2%} |",
        f"| Recall | {aggregate['recall']:.2%} |",
        f"| F1 | {aggregate['f1']:.2%} |",
        f"| True Positive | {aggregate['true_positive']} |",
        f"| False Positive | {aggregate['false_positive']} |",
        f"| False Negative | {aggregate['false_negative']} |",
        f"| Unsupported analyst items | {sum(item['unsupported_reference_count'] for item in results)} |",
        "",
        "## Per Event",
        "",
        "| Event | Scope | Valid IoC | Expected | Precision | Recall | F1 | Unsupported |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]

    for item in results:
        lines.append(
            f"| {item['event_file']} | {item['extraction_scope']} | "
            f"{item['predicted_total']} | {item['expected_total']} | "
            f"{item['precision']:.2%} | {item['recall']:.2%} | {item['f1']:.2%} | "
            f"{item['unsupported_reference_count']} |"
        )

    for item in results:
        lines.extend(
            [
                "",
                f"### {item['event_file']}",
                "",
                f"- Analyst event: `{item['event_info']}`",
                f"- Source: `{item['source_url']}`",
                f"- Extraction scope: `{item['extraction_scope']}`",
                f"- Runtime: `{item['runtime_ms']:.2f} ms`",
                f"- Predicted by type: `{json.dumps(item['predicted_by_type'], ensure_ascii=False)}`",
                f"- Expected by type: `{json.dumps(item['expected_by_type'], ensure_ascii=False)}`",
                f"- Precision / Recall / F1: `{item['precision']:.2%} / {item['recall']:.2%} / {item['f1']:.2%}`",
            ]
        )
        if item["false_positive_values"]:
            lines.append(f"- False positives: `{json.dumps(item['false_positive_values'], ensure_ascii=False)}`")
        if item["false_negative_values"]:
            lines.append(f"- False negatives: `{json.dumps(item['false_negative_values'], ensure_ascii=False)}`")
        if item["unsupported_reference_items"]:
            lines.append(
                f"- Unsupported analyst items: `{json.dumps(item['unsupported_reference_items'], ensure_ascii=False)}`"
            )

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare live extraction results against IOC_analyst MISP events.")
    parser.add_argument(
        "--analyst-dir",
        default=str(ANALYST_DIR),
        help="Directory with analyst MISP event JSON files.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Directory for JSON and Markdown reports.",
    )
    args = parser.parse_args()

    analyst_dir = Path(args.analyst_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    results = [_evaluate_event(path) for path in sorted(analyst_dir.glob("*.json"))]
    aggregate = aggregate_evaluations(results)
    payload = {
        "aggregate": aggregate,
        "results": results,
    }

    json_path = output_dir / "analyst_comparison.json"
    md_path = output_dir / "analyst_comparison.md"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(_build_markdown(results, aggregate), encoding="utf-8")

    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")
    print(
        f"Aggregate precision={aggregate['precision']:.2%}, "
        f"recall={aggregate['recall']:.2%}, f1={aggregate['f1']:.2%}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
