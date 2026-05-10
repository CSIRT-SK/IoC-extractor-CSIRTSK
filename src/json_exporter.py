from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional


def save_iocs_to_json(
    output_path: str,
    title: str,
    source_url: str,
    extraction_scope: str,
    iocs: Dict[str, List[str]],
    confidence: Optional[Dict[str, Dict[str, Dict[str, str]]]] = None,
    metrics: Optional[dict] = None,
) -> Path:
    data = {
        "title": title,
        "source_url": source_url,
        "extraction_scope": extraction_scope,
        "iocs": iocs,
        "confidence": confidence or {},
        "metrics": metrics or {},
        "counts": {ioc_type: len(values) for ioc_type, values in iocs.items()},
        "total_iocs": sum(len(values) for values in iocs.values()),
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    return path
