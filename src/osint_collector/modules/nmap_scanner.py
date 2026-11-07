"""Integración inicial de Nmap NSE ssl-cert.

Escaneo activo: exige confirmación explícita y que el host esté en la lista
de alcance autorizada. El resultado XML se devuelve sin ejecutar shell.
"""
import shutil
import subprocess
import xml.etree.ElementTree as ET

def run_ssl_cert_scan(target: str, *, authorized: bool, approved_targets: list[str], timeout: int = 90) -> dict:
    if not authorized:
        raise PermissionError("Se requiere confirmación explícita de autorización.")
    if target not in approved_targets:
        raise PermissionError("El objetivo no figura en el alcance aprobado.")
    binary = shutil.which("nmap")
    if not binary:
        raise RuntimeError("Nmap no está instalado o no está disponible en PATH.")
    command = [binary, "-Pn", "-p", "443", "--script", "ssl-cert", "-oX", "-", target]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    result = {"target": target, "returncode": completed.returncode, "stderr": completed.stderr, "certificates": []}
    if completed.stdout.strip():
        root = ET.fromstring(completed.stdout)
        for host in root.findall("host"):
            for port in host.findall("./ports/port"):
                for script in port.findall("script"):
                    if script.get("id") == "ssl-cert":
                        result["certificates"].append({"port": port.get("portid"), "output": script.get("output", "")})
    return result
