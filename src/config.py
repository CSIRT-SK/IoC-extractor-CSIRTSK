from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any


DEFAULT_APP_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "app_config.json"


@dataclass(frozen=True)
class MISPConfig:
    distribution: int = 0
    sharing_group_id: int = 0
    analysis: int = 2
    publish_event: bool = False
    allow_xdr_export: bool = False
    enrich_event: bool = False
    dissect_urls: bool = False


@dataclass(frozen=True)
class ReportConfig:
    print_confidence: bool = False,
    print_validation_report: bool = False,
    print_attribute_preview: bool = False,
    print_metrics: bool = False,
    print_quick_preview: bool = True


@dataclass(frozen=True)
class AppConfig:
    misp: MISPConfig = MISPConfig()
    report: ReportConfig = ReportConfig()


def coerce_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    raise ValueError(f"Invalid boolean value for '{field_name}': {value!r}")


def coerce_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"Invalid integer value for '{field_name}': {value!r}")
    return value


def load_app_config(path: str | Path = DEFAULT_APP_CONFIG_PATH) -> AppConfig:
    config_path = Path(path)
    if not config_path.exists():
        return AppConfig()

    payload = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Application config must be a JSON object.")

    misp_payload = payload.get("misp", {})
    if not isinstance(misp_payload, dict):
        raise ValueError("'misp' config section must be a JSON object.")
    
    report_payload = payload.get("report", {})
    if not isinstance(report_payload, dict):
        raise ValueError("'report' config section must be a JSON object.")

    return AppConfig(
        misp=MISPConfig(
            distribution=coerce_int(misp_payload.get("distribution", 1), "misp.distribution"),
            sharing_group_id=coerce_int(misp_payload.get("sharing_group_id", 0), "misp.sharing_group_id"),
            analysis=coerce_int(misp_payload.get("analysis", 2), "misp.analysis"),
            publish_event=coerce_bool(misp_payload.get("publish_event", False), "misp.publish_event"),
            allow_xdr_export=coerce_bool(misp_payload.get("allow_xdr_export", False), "misp.allow_xdr_export"),
            enrich_event=coerce_bool(misp_payload.get("enrich_event", False), "misp.enrich_event"),
            dissect_urls=coerce_bool(misp_payload.get("dissect_urls", False), "misp.dissect_urls")
        ),
        report=ReportConfig(
            print_confidence=coerce_bool(report_payload.get("print_confidence", False), "report.print_confidence"),
            print_validation_report=coerce_bool(report_payload.get("print_validation_report", False), "report.print_validation_report"),
            print_attribute_preview=coerce_bool(report_payload.get("print_attribute_preview", False), "report.print_attribute_preview"),
            print_metrics=coerce_bool(report_payload.get("print_metrics", False), "report.print_metrics"),
            print_quick_preview=coerce_bool(report_payload.get("print_quick_preview", True), "report.print_quick_preview")
        )
    )


@lru_cache(maxsize=1)
def get_app_config() -> AppConfig:
    return load_app_config()


def reset_app_config_cache() -> None:
    get_app_config.cache_clear()
