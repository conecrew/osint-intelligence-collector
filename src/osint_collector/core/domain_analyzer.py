"""Validación y normalización básica de dominios (sin realizar escaneos)."""
import re

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

def normalize_domain(value: str) -> str:
    """Normaliza un nombre DNS ingresado por el usuario."""
    domain = value.strip().lower().rstrip(".")
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/", 1)[0].split(":", 1)[0]
    if not _DOMAIN_RE.fullmatch(domain):
        raise ValueError("El valor no parece ser un nombre de dominio válido.")
    return domain
