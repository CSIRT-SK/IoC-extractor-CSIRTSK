from __future__ import annotations

from typing import Dict, List, Set, Tuple

from src.ioc_processor import ConfidenceMap, IOCMap, ProcessingReport


def compute_runtime_metrics(
    iocs: IOCMap,
    report: ProcessingReport,
    confidence: ConfidenceMap,
) -> dict:
    confidence_counts: Dict[str, int] = {}
    for values in confidence.values():
        for data in values.values():
            level = data.get("level", "unknown")
            confidence_counts[level] = confidence_counts.get(level, 0) + 1

    by_type = {ioc_type: len(values) for ioc_type, values in iocs.items()}
    total_valid = sum(by_type.values())
    total_input = report.total_input
    rejected = len(report.rejected)
    duplicates = len(report.duplicates)

    return {
        "total_raw_iocs": total_input,
        "total_valid_iocs": total_valid,
        "duplicates_removed": duplicates,
        "rejected": rejected,
        "normalized": len(report.normalized),
        "by_type": by_type,
        "confidence": confidence_counts,
        "valid_ratio": safe_ratio(total_valid, total_input),
        "rejection_ratio": safe_ratio(rejected, total_input),
        "deduplication_ratio": safe_ratio(duplicates, total_input),
    }


def evaluate_iocs(predicted: IOCMap, expected: IOCMap) -> dict:
    predicted_set = flatten_iocs(predicted)
    expected_set = flatten_iocs(expected)

    true_positive = predicted_set & expected_set
    false_positive = predicted_set - expected_set
    false_negative = expected_set - predicted_set

    precision = safe_ratio(len(true_positive), len(true_positive) + len(false_positive))
    recall = safe_ratio(len(true_positive), len(true_positive) + len(false_negative))
    f1 = safe_ratio(2 * precision * recall, precision + recall)

    return {
        "expected_total": len(expected_set),
        "predicted_total": len(predicted_set),
        "true_positive": len(true_positive),
        "false_positive": len(false_positive),
        "false_negative": len(false_negative),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_values": sorted_pairs(false_positive),
        "false_negative_values": sorted_pairs(false_negative),
    }


def aggregate_evaluations(evaluations: List[dict]) -> dict:
    totals = {
        "expected_total": 0,
        "predicted_total": 0,
        "true_positive": 0,
        "false_positive": 0,
        "false_negative": 0,
    }

    for evaluation in evaluations:
        for key in totals:
            totals[key] += int(evaluation.get(key, 0))

    precision = safe_ratio(
        totals["true_positive"],
        totals["true_positive"] + totals["false_positive"],
    )
    recall = safe_ratio(
        totals["true_positive"],
        totals["true_positive"] + totals["false_negative"],
    )
    f1 = safe_ratio(2 * precision * recall, precision + recall)

    return {
        **totals,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def flatten_iocs(iocs: IOCMap) -> Set[Tuple[str, str]]:
    return {
        (ioc_type, value)
        for ioc_type, values in iocs.items()
        for value in values
    }


def safe_ratio(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 4)


def sorted_pairs(values: Set[Tuple[str, str]]) -> List[dict]:
    return [
        {"type": ioc_type, "value": value}
        for ioc_type, value in sorted(values)
    ]
