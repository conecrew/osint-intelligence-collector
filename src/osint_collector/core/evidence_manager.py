"""Modelo mínimo para registrar evidencias trazables."""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

@dataclass
class Evidence:
    subject: str
    attribute: str
    value: Any
    source: str
    classification: str = "pending"
    confidence: str = "unknown"
    observed_at: str = ""

    def __post_init__(self):
        if not self.observed_at:
            self.observed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return asdict(self)
