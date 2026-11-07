"""Dashboard Streamlit para reconocimiento OSINT pasivo."""
import json
import os
import sys

# Permite ejecutar el dashboard desde el repositorio sin instalar el paquete.
_PROJECT_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _PROJECT_SRC not in sys.path:
    sys.path.insert(0, _PROJECT_SRC)

import streamlit as st

from osint_collector.core.collection_service import collect_domain_intelligence
from osint_collector.core.domain_analyzer import normalize_domain
from osint_collector.modules.nmap_scanner import run_ssl_cert_scan
from osint_collector.modules.hosts_manager import read_hosts_file
from osint_collector.reporting.report_generator import build_json_report
from osint_collector.visualization.graph_engine import graph_to_dot

st.set_page_config(
    page_title="OSINT Intelligence Collector",
    page_icon="⌁",
    layout="wide"
)

st.markdown("""
<style>
.stApp { background: #050807; color: #d8e5dc; }
[data-testid="stSidebar"] { background: #0a100d; border-right: 1px solid #183526; }
h1, h2, h3 { color: #7CFF9B !important; font-family: monospace; }
p, label, div { font-family: 'Consolas', 'Courier New', monospace; }
.stTextInput input { background: #101914; color: #d8e5dc; border: 1px solid #28543a; }
.stButton button { background: #10291b; color: #8cffaa; border: 1px solid #38a65d; }
.metric-card { background: #0b130e; border: 1px solid #1c432b; padding: 16px; border-radius: 8px; }
.muted { color: #8ba394; font-size: 0.85rem; }
</style>
""", unsafe_allow_html=True)

if "osint_result" not in st.session_state:
    st.session_state["osint_result"] = None
if "nmap_result" not in st.session_state:
    st.session_state["nmap_result"] = None

with st.sidebar:
    st.markdown("## ⌁ OSINT // COLLECTOR")
    st.caption("INTELLIGENCE WORKSPACE · INTEGRATED BUILD")
    target = st.text_input("DOMINIO OBJETIVO", placeholder="example.org")
    authorized = st.checkbox(
        "Confirmo que tengo autorización para analizar este dominio",
        value=False
    )
    include_external = st.checkbox("Ejecutar conectores externos (RDAP, WHOIS, CT, APIs y HTTP)", value=False)
    run_recon = st.button("INITIALIZE PASSIVE RECON")
    st.markdown("### ACTIVE VALIDATION")
    active_nmap = st.checkbox("Habilitar Nmap NSE (solo puerto 443)", value=False)
    run_nmap = st.button("RUN AUTHORIZED NMAP CHECK", disabled=not active_nmap)
    st.markdown("---")
    st.markdown("### MÓDULOS")
    st.checkbox("Domain Analyzer", value=True, disabled=True)
    st.checkbox("DNS Intelligence", value=True, disabled=True)
    st.checkbox("Evidence Manager", value=True, disabled=True)
    st.checkbox("Relationship Graph", value=True, disabled=True)
    st.checkbox("JSON Reporting", value=True, disabled=True)
    st.checkbox("Local Hosts (solo lectura)", value=False, key="show_hosts")
    st.checkbox("RDAP / WHOIS", value=True, disabled=True)
    st.checkbox("Certificate Transparency", value=True, disabled=True)
    st.checkbox("SecurityTrails", value=True, disabled=True)
    st.checkbox("Shodan / Censys", value=True, disabled=True)
    st.checkbox("VirusTotal", value=True, disabled=True)
    st.checkbox("Technology Detection (HTTP)", value=True, disabled=True)
    st.checkbox("Nmap NSE (activo, 443/ssl-cert)", value=False, disabled=True)
    st.caption("Los conectores externos requieren internet; algunos necesitan claves API.")

if run_recon:
    if not target.strip():
        st.error("Ingresá un dominio antes de iniciar el análisis.")
    elif not authorized:
        st.error("Confirmá que tenés autorización para analizar el dominio.")
    else:
        with st.spinner("Consultando fuentes OSINT y construyendo evidencias..."):
            try:
                st.session_state["osint_result"] = collect_domain_intelligence(target, include_external=include_external)
            except Exception as exc:
                st.session_state["osint_result"] = None
                st.error("No se pudo completar el reconocimiento: %s" % exc)

if run_nmap:
    if not target.strip():
        st.error("Ingresá el dominio autorizado.")
    elif not authorized:
        st.error("Confirmá autorización antes de ejecutar Nmap.")
    elif not active_nmap:
        st.error("Habilitá expresamente el control Nmap.")
    else:
        try:
            normalized = normalize_domain(target)
            with st.spinner("Ejecutando comprobación activa limitada a TCP/443 y ssl-cert..."):
                st.session_state["nmap_result"] = run_ssl_cert_scan(
                    normalized, authorized=True, approved_targets=[normalized], timeout=90
                )
        except Exception as exc:
            st.session_state["nmap_result"] = {"error": str(exc)}

result = st.session_state.get("osint_result")

st.markdown("# OSINT INTELLIGENCE COLLECTOR")
st.markdown(
    '<p class="muted">OPEN SOURCE INTELLIGENCE · INFRASTRUCTURE MAPPER · INTEGRATED BUILD</p>',
    unsafe_allow_html=True
)

if result is None:
    st.info("Ingresá un dominio autorizado en el panel lateral y ejecutá INITIALIZE PASSIVE RECON.")
    col1, col2, col3 = st.columns(3)
    for col, title, value in [
        (col1, "TARGET", target or "NO TARGET"),
        (col2, "MODULES ONLINE", "5"),
        (col3, "INTELLIGENCE STATUS", "STANDBY"),
    ]:
        with col:
            st.markdown(
                '<div class="metric-card"><div class="muted">%s</div><h3>%s</h3></div>' %
                (title, value), unsafe_allow_html=True
            )
else:
    summary = result["summary"]
    col1, col2, col3 = st.columns(3)
    for col, title, value in [
        (col1, "TARGET", result["target"]),
        (col2, "DNS RECORDS", str(summary["record_count"])),
        (col3, "RELATIONSHIPS", str(summary["relationship_count"])),
    ]:
        with col:
            st.markdown(
                '<div class="metric-card"><div class="muted">%s</div><h3>%s</h3></div>' %
                (title, value), unsafe_allow_html=True
            )

    st.markdown("---")
    left, center, right = st.columns([1, 2, 1])
    with left:
        st.markdown("### [01] DNS INTELLIGENCE")
        for record_type, values in result["records"].items():
            st.markdown("**%s**" % record_type)
            if values:
                for value in values:
                    st.write(value)
            else:
                st.caption("Sin registros observados")
        if result["errors"]:
            with st.expander("Detalles de consultas DNS"):
                for record_type, message in result["errors"].items():
                    st.write("%s: %s" % (record_type, message))

    with center:
        st.markdown("### [02] RELATIONSHIP MAP")
        if result["relationships"]:
            dot = graph_to_dot(result["graph"])
            try:
                st.graphviz_chart(dot)
            except Exception:
                st.code(dot, language="dot")
        else:
            st.info("No se encontraron relaciones DNS para representar.")

    with right:
        st.markdown("### [03] ENTITY DETAILS")
        st.write("Entidades: %s" % summary["entity_count"])
        st.write("Evidencias: %s" % summary["evidence_count"])
        st.write("Relaciones: %s" % summary["relationship_count"])
        st.caption("Cada evidencia conserva fuente, fecha, clasificación y confianza.")

    st.markdown("---")
    if result.get("external_results"):
        st.markdown("### [04] EXTERNAL INTELLIGENCE PROVIDERS")
        for provider in result["external_results"]:
            label = "%s · %s" % (provider["provider"], provider["status"].upper())
            with st.expander(label):
                if provider.get("message"):
                    st.write(provider["message"])
                st.json(provider.get("data", {}))
                st.caption("Tipo de fuente: %s · Observado: %s" % (
                    provider.get("source_type"), provider.get("observed_at")))

    with st.expander("EVIDENCE REGISTER"):
        st.json(result["evidence"])

    report_payload = dict((key, value) for key, value in result.items() if key != "graph")
    report_data = build_json_report(report_payload)
    st.download_button(
        "DOWNLOAD JSON REPORT",
        data=report_data,
        file_name="osint_%s.json" % result["target"],
        mime="application/json"
    )

nmap_result = st.session_state.get("nmap_result")
if nmap_result:
    st.markdown("---")
    st.markdown("### [05] NMAP NSE · ACTIVE CHECK")
    st.warning("Consulta activa limitada a TCP/443 con el script ssl-cert. Ejecutar solo con autorización.")
    st.json(nmap_result)

if st.session_state.get("show_hosts"):
    st.markdown("---")
    st.markdown("### LOCAL HOSTS · READ ONLY")
    try:
        st.code(read_hosts_file(), language="text")
    except Exception as exc:
        st.warning("No se pudo leer /etc/hosts: %s" % exc)

st.markdown("---")
st.caption(
    "AUTHORIZED RESEARCH ONLY · PASSIVE INTELLIGENCE FIRST · NMAP REQUIRES EXPLICIT APPROVAL"
)
