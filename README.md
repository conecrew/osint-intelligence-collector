# OSINT Intelligence Collector

> **Estado:** 🚧 En desarrollo activo — versión inicial de arquitectura y prototipo.

Plataforma modular de **Open Source Intelligence (OSINT)** desarrollada en Python para recopilar, normalizar, correlacionar y visualizar información pública sobre dominios e infraestructura digital dentro de un alcance autorizado.

El proyecto nace como una herramienta de aprendizaje e investigación aplicada a los contenidos de C1B3RWALL Academy / Universidad de Salamanca. Su desarrollo será progresivo: los módulos se incorporarán, probarán y documentarán a medida que avance el aprendizaje.

## Identidad visual

La interfaz prevista tendrá una estética **dark / hacker**, con fondo negro, paneles oscuros, tipografía monoespaciada y acentos verde neón. Es una decisión visual para el dashboard; no representa ni promueve actividades maliciosas.

## Objetivos

- Analizar dominios y recopilar información DNS y de registro.
- Relacionar dominios, subdominios, direcciones IP, ASN, certificados y servicios.
- Integrar fuentes OSINT y APIs oficiales cuando estén disponibles.
- Incorporar Nmap y sus scripts NSE para verificaciones activas expresamente autorizadas.
- Correlacionar evidencias, registrar procedencia y asignar niveles de confianza.
- Visualizar relaciones mediante un grafo interactivo inspirado en herramientas de análisis de enlaces.
- Generar informes reproducibles en JSON, TXT y PDF.
- Incluir una operación controlada de consulta DNS local y administración de `/etc/hosts`, con confirmación previa.

## Arquitectura prevista

| Componente | Responsabilidad | Estado |
|---|---|---|
| Domain Analyzer | Validación y normalización de dominios | Prototipo inicial |
| DNS Intelligence | Registros y resolución DNS | Planificado |
| WHOIS / RDAP | Datos de registro | Planificado |
| SecurityTrails | Subdominios e historial DNS | Planificado |
| Certificate Intelligence | Certificados TLS y CT logs | Planificado |
| Nmap / NSE | Inspecciones activas autorizadas; XML como salida estructurada | Planificado |
| Shodan / Censys | Servicios e infraestructura observada | Planificado |
| VirusTotal | Reputación e indicadores | Planificado |
| Technology Detection | Tecnologías web | Planificado |
| Intelligence Engine | Correlación, deduplicación y confianza | Planificado |
| Graph Engine | Relaciones y visualización | Planificado |
| Report Generator | Exportación JSON, TXT y PDF | Planificado |
| Local DNS & Hosts Manager | Comparación DNS local y propuesta controlada para hosts | Planificado |
| GUI Dashboard | Interfaz gráfica dark / hacker | Prototipo visual |

## Diseño de interfaz

El dashboard se proyecta con tres áreas:

1. **Panel lateral:** dominio objetivo, alcance autorizado, configuración y selección de módulos.
2. **Área central:** resumen del reconocimiento y grafo de relaciones.
3. **Panel de detalle:** evidencia del nodo seleccionado, fuente, fecha, clasificación y confianza.

Tecnologías consideradas: Streamlit para la interfaz, NetworkX y PyVis para el análisis y la visualización de grafos.

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
- Las consultas pasivas y las pruebas activas se distinguirán claramente.
- Nmap no se ejecutará contra objetivos arbitrarios: se requerirá una confirmación explícita de autorización y alcance.
- No se automatizará la evasión de WAF, CDN u otros controles de terceros.
- Las claves API se guardarán fuera del repositorio, mediante variables de entorno o archivos locales excluidos por Git.
- La modificación de `/etc/hosts` nunca será silenciosa: se mostrará la propuesta y se solicitará confirmación antes de escribir. Se prevén copia de seguridad, validación y restauración.
- Google Colab podrá generar propuestas, pero modificar el `/etc/hosts` de una sesión remota no modifica el equipo personal del usuario.

## Instalación (entorno local)

Se recomienda Python 3.10 o superior.

```bash
git clone https://github.com/conecrew/osint-intelligence-collector.git
cd osint-intelligence-collector
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run src/osint_collector/gui/dashboard.py
```

En Windows, activar el entorno virtual con `.venv\\Scripts\\activate`.

## Estructura inicial

```text
.
├── docs/                  # documentación y decisiones de arquitectura
├── src/osint_collector/
│   ├── core/              # dominio, evidencias y correlación
│   ├── modules/           # conectores y analizadores
│   ├── gui/               # dashboard Streamlit
│   ├── reporting/         # exportación de informes
│   └── visualization/     # grafo de relaciones
├── tests/                 # pruebas
├── notebooks/             # experimentación en Google Colab
├── requirements.txt
└── README.md
```

## Hoja de ruta

- [x] Crear repositorio independiente y documentar el propósito.
- [x] Definir arquitectura modular, criterios de evidencia y enfoque de seguridad.
- [ ] Implementar y probar Domain Analyzer.
- [ ] Incorporar DNS Intelligence y WHOIS/RDAP.
- [ ] Incorporar Certificate Intelligence y Nmap NSE (salida XML).
- [ ] Integrar fuentes OSINT mediante APIs oficiales.
- [ ] Desarrollar correlación y grafo interactivo.
- [ ] Completar Local DNS & Hosts Manager con confirmación y rollback.
- [ ] Construir dashboard y exportación de informes.
- [ ] Pruebas, ejemplos de laboratorio y documentación de uso.

## Estado actual

Este repositorio representa la **base inicial de un proyecto en proceso**, no una herramienta OSINT completa. Los conectores externos, el escaneo Nmap, la correlación avanzada y las operaciones de sistema se implementarán y validarán por etapas.

## Licencia

A definir cuando se establezca el alcance de distribución del proyecto.
