"""Exportación de resultados OSINT a JSON."""
import json
from pathlib import Path
from datetime import datetime, timezone


def build_json_report(payload):
    """Devuelve el informe JSON como texto, sin escribir archivos."""
    document = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": "OSINT Intelligence Collector",
        "data": payload,
    }
    return json.dumps(document, indent=2, ensure_ascii=False)


def export_json(payload, output_path="reports/osint_data.json"):
    """Guarda un informe JSON y devuelve la ruta creada."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_json_report(payload), encoding="utf-8")
    return str(path)
