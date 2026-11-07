"""Exportación inicial de resultados OSINT a JSON."""
import json
from pathlib import Path
from datetime import datetime, timezone

def export_json(payload: dict, output_path: str = "reports/osint_data.json") -> str:
    document = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": "OSINT Intelligence Collector",
        "data": payload,
    }
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(path)
