# OSINT Intelligence Collector

> **Estado:** 🚧 Desarrollo activo — primera integración funcional en la rama `feature/integrated-dashboard`.

Plataforma modular de **Open Source Intelligence (OSINT)** desarrollada en Python para recopilar, normalizar, correlacionar y visualizar información pública sobre dominios e infraestructura digital dentro de un alcance autorizado.

El proyecto nace como una herramienta de aprendizaje e investigación aplicada a los contenidos de C1B3RWALL Academy / Universidad de Salamanca. Su desarrollo será progresivo: los módulos se incorporarán, probarán y documentarán a medida que avance el aprendizaje.

## Identidad visual

La interfaz utiliza una estética **dark / hacker**, con fondo negro, paneles oscuros, tipografía monoespaciada y acentos verde neón.

## Estado de la integración

La rama `feature/integrated-dashboard` conecta los componentes que ya existen en el repositorio:

- Validación y normalización del dominio.
- Consultas DNS pasivas A, AAAA, MX, NS, TXT y CNAME.
- Registro de evidencias con fuente, fecha, clasificación y confianza.
- Construcción de entidades y relaciones con NetworkX.
- Representación del grafo mediante Graphviz/DOT en el dashboard.
- Exportación de resultados a JSON.
- Lectura de `/etc/hosts` en modo solo lectura.
- Pruebas unitarias y flujo de integración continua.

Los conectores externos ya están incorporados en esta rama: RDAP, WHOIS clásico opcional, Certificate Transparency (crt.sh), SecurityTrails, Shodan, Censys, VirusTotal y detección ligera de tecnologías HTTP. Cada proveedor informa `ok`, `no_data`, `missing_credentials`, `dependency_missing` o `error`; un fallo no interrumpe a los demás. Nmap NSE también está conectado como acción separada, limitada a TCP/443 y `ssl-cert`, con confirmación explícita y alcance aprobado.

## Arquitectura

| Componente | Responsabilidad | Estado |
|---|---|---|
| Domain Analyzer | Validación y normalización de dominios | Integrado |
| DNS Intelligence | A, AAAA, MX, NS, TXT y CNAME | Integración inicial |
| Evidence Manager | Procedencia y trazabilidad de observaciones | Integrado |
| Graph Engine | Entidades y relaciones | Integrado |
| Report Generator | Exportación JSON | Integrado |
| Local DNS & Hosts Manager | Lectura de hosts y propuesta controlada | Solo lectura / propuesta |
| Nmap / NSE | Inspecciones activas autorizadas | Módulo separado, no conectado al dashboard |
| WHOIS / RDAP | Datos de registro | Pendiente |
| SecurityTrails | Subdominios e historial DNS | Pendiente |
| Certificate Intelligence | Certificados TLS y CT logs | Pendiente |
| Shodan / Censys | Servicios e infraestructura observada | Pendiente |
| VirusTotal | Reputación e indicadores | Pendiente |
| Technology Detection | Tecnologías web | Pendiente |
| GUI Dashboard | Interfaz gráfica dark / hacker | Integración inicial |

## Diseño de interfaz

El dashboard se organiza en tres áreas:

1. **Panel lateral:** dominio objetivo, confirmación de autorización y módulos.
2. **Área central:** resumen del reconocimiento y grafo de relaciones.
3. **Panel de detalle:** registros DNS, evidencias, fuente, fecha, clasificación y confianza.

Tecnologías: Streamlit para la interfaz, NetworkX para el grafo y Graphviz/DOT para representarlo.

## Clasificación de activos y evidencias

Los resultados no se considerarán automáticamente propiedad del objetivo. Se utilizarán categorías explícitas:

- **Confirmado:** dentro del alcance autorizado y verificado.
- **Asociado:** existe una relación técnica, aún sin confirmar titularidad o alcance.
- **Histórico:** evidencia correspondiente a un momento anterior.
- **Tercero:** proveedor, CDN, WAF, hosting o infraestructura compartida.
- **Pendiente:** información insuficiente para clasificar.

Cada evidencia deberá registrar, cuando corresponda: fuente, fecha/hora de consulta, dato observado, contexto, vigencia y nivel de confianza.

## Seguridad y uso responsable

- Utilizar únicamente dominios y sistemas propios o para los que exista autorización.
- Las consultas pasivas y las pruebas activas se distinguen claramente.
- Nmap no se ejecutará contra objetivos arbitrarios: requiere confirmación explícita y alcance aprobado.
- No se automatizará la evasión de WAF, CDN u otros controles de terceros.
- Las claves API se guardarán fuera del repositorio, mediante variables de entorno o archivos locales excluidos por Git.
- La lectura de `/etc/hosts` es de solo lectura. Cualquier futura escritura requerirá propuesta, confirmación, copia de seguridad y rollback.
- Google Colab podrá generar propuestas, pero modificar el `/etc/hosts` de una sesión remota no modifica el equipo personal del usuario.

## Instalación en un entorno moderno

Se recomienda Python 3.10 o superior.

```bash
git clone https://github.com/conecrew/osint-intelligence-collector.git
cd osint-intelligence-collector
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=src streamlit run src/osint_collector/gui/dashboard.py
```

## Vista previa en Ubuntu 18.04 / Python 3.6

La rama de integración incluye un archivo separado con dependencias mínimas para la computadora Ceibal:

```bash
pip install -r requirements-ceibal-py36.txt
PYTHONPATH=src streamlit run src/osint_collector/gui/dashboard.py
```

Este archivo no reemplaza `requirements.txt` ni convierte todos los conectores modernos en compatibles con Python 3.6. Es únicamente una configuración de vista previa del dashboard y de los módulos básicos.

## Estructura

```text
.
├── .github/workflows/     # pruebas automatizadas
├── docs/                  # documentación y decisiones de arquitectura
├── src/osint_collector/
│   ├── core/              # dominio, evidencias y orquestación
│   ├── modules/           # conectores y analizadores técnicos
│   ├── gui/               # dashboard Streamlit
│   ├── reporting/         # exportación de informes
│   └── visualization/     # grafo de relaciones
├── tests/                 # pruebas
├── requirements.txt
└── README.md
```

## Pruebas

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

GitHub Actions ejecuta las pruebas con Python 3.10 y 3.11.

## Hoja de ruta

- [x] Crear repositorio y documentar el propósito.
- [x] Definir arquitectura modular y criterios de evidencia.
- [x] Crear prototipo visual oscuro.
- [x] Integrar Domain Analyzer, DNS pasivo, evidencias, grafo y JSON en una rama de desarrollo.
- [x] Agregar pruebas iniciales y CI.
- [ ] Completar WHOIS/RDAP y Certificate Intelligence.
- [ ] Incorporar fuentes OSINT mediante APIs oficiales.
- [ ] Completar correlación, deduplicación y clasificación.
- [ ] Integrar Nmap con interfaz de alcance y autorización.
- [ ] Completar Local DNS & Hosts Manager con confirmación y rollback.
- [ ] Pruebas con laboratorios propios, documentación y versión inicial.

## Licencia

A definir cuando se establezca el alcance de distribución del proyecto.
