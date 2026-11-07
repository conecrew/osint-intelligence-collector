"""Modelo sencillo para registrar evidencias trazables.

Se evita dataclasses para mantener compatibilidad con Python 3.6.
"""
from datetime import datetime, timezone


class Evidence(object):
    def __init__(self, subject, attribute, value, source,
                 classification="pending", confidence="unknown",
                 observed_at=None):
        self.subject = subject
        self.attribute = attribute
        self.value = value
        self.source = source
        self.classification = classification
        self.confidence = confidence
        self.observed_at = observed_at or datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        return {
            "subject": self.subject,
            "attribute": self.attribute,
            "value": self.value,
            "source": self.source,
            "classification": self.classification,
            "confidence": self.confidence,
            "observed_at": self.observed_at,
        }
