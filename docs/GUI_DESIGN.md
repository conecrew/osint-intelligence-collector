# Diseño de interfaz gráfica

## Dirección visual

Dashboard de estética dark / hacker: fondo negro carbón, superficies gris muy oscuro, texto claro y acentos verde neón. La estética es únicamente visual y busca una experiencia de consola de análisis legible.

## Distribución

1. Barra lateral: dominio, alcance, módulos y configuración.
2. Área central: resumen del objetivo y grafo interactivo.
3. Panel de detalles: entidad seleccionada, relaciones, evidencia, fuente, fecha y confianza.

## Tecnologías

Streamlit para la aplicación, NetworkX para el modelo de grafo y PyVis para la visualización interactiva. El prototipo actual es una primera pantalla; el grafo se conectará cuando existan datos normalizados.
