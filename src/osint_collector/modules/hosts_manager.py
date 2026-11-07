"""Funciones de solo lectura y propuesta para /etc/hosts.

La escritura real se implementará más adelante con backup, validación,
confirmación interactiva y rollback. Este prototipo no modifica archivos.
"""
from pathlib import Path

def read_hosts_file(path: str = "/etc/hosts") -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")

def propose_hosts_entry(ip_address: str, domain: str) -> str:
    """Genera una propuesta; nunca escribe en /etc/hosts."""
    return f"{ip_address}\t{domain}\n"
