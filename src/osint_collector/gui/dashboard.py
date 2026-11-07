"""Prototipo visual del dashboard OSINT (Streamlit)."""
import streamlit as st

st.set_page_config(page_title="OSINT Intelligence Collector", page_icon="⌁", layout="wide")

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

with st.sidebar:
    st.markdown("## ⌁ OSINT // COLLECTOR")
    st.caption("INTELLIGENCE WORKSPACE · DEV BUILD")
    target = st.text_input("DOMINIO OBJETIVO", placeholder="example.org")
    st.checkbox("Confirmo que tengo autorización", value=False, key="authorized")
    st.divider()
    st.markdown("### MÓDULOS")
    for module in ["DNS Intelligence", "WHOIS / RDAP", "Certificate Intelligence",
                   "Nmap NSE", "Shodan / Censys", "VirusTotal",
                   "Technology Detection", "Local DNS / Hosts"]:
        st.checkbox(module, value=False, disabled=True)
    st.caption("Los conectores se habilitarán progresivamente.")

st.markdown("# OSINT INTELLIGENCE COLLECTOR")
st.markdown('<p class="muted">OPEN SOURCE INTELLIGENCE · INFRASTRUCTURE MAPPER · DEVELOPMENT BUILD</p>', unsafe_allow_html=True)
st.warning("PROYECTO EN DESARROLLO — los módulos de recopilación todavía no están conectados.")

col1, col2, col3 = st.columns(3)
for col, title, value in [(col1, "TARGET", target or "NO TARGET"),
                          (col2, "MODULES ONLINE", "0 / 8"),
                          (col3, "INTELLIGENCE STATUS", "STANDBY")]:
    with col:
        st.markdown(f'<div class="metric-card"><div class="muted">{title}</div><h3>{value}</h3></div>', unsafe_allow_html=True)

left, center, right = st.columns([1, 2, 1])
with left:
    st.markdown("### [01] RECON")
    st.write("Dominio, alcance y fuentes de información.")
    st.button("INITIALIZE RECON", disabled=True, help="Se habilitará cuando los módulos básicos estén implementados.")
with center:
    st.markdown("### [02] RELATIONSHIP MAP")
    st.info("El grafo de dominios, IP, ASN, certificados y servicios aparecerá aquí cuando exista información correlacionada.")
    st.code("DOMAIN  ── resolves_to ──>  IP\n   │                         │\n   └── has_certificate ──> CERT", language="text")
with right:
    st.markdown("### [03] ENTITY DETAILS")
    st.write("Seleccioná una entidad del grafo para consultar sus evidencias.")
    st.caption("SOURCE · TIMESTAMP · CONFIDENCE · CLASSIFICATION")

st.divider()
st.caption("AUTHORIZED RESEARCH ONLY · PASSIVE OSINT FIRST · ACTIVE SCANS REQUIRE EXPLICIT SCOPE")
