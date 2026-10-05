# 🔒 KANEDA — Auditor de Seguridad y Funciones Inseguras en C

> 📖 **Manual de Usuario:** Para una guía exhaustiva de comandos, banderas, arquitectura y ejemplos, consultá el [Manual de Uso](MANUAL.md).

KANEDA es una herramienta pedagógica para la detección temprana de funciones C prohibidas o inseguras (`gets`, `strcpy`, `sprintf`, `scanf("%s")`, `system`), vulnerabilidades de tipo `Format String` y llamadas a sistema no autorizadas.

---

## 🎯 Alcance

### Qué cubre
- Auditoría pedagógica de seguridad estática en código C con su propio catálogo de 7 reglas (`KAN001`-`KAN007`). Sus códigos son `KANxxx`, no `0x30XXh`: esa numeración pertenece a `gaff` y no se emite desde acá.
- Detección estricta de funciones vulnerables a desbordamiento de búfer (`gets`, `strcpy`, `strcat`, `sprintf`, `scanf` con `%s` sin límite de ancho).
- Detección de vulnerabilidades de cadena de formato (`printf` o `fprintf` con variable como formato directo sin especificadores).
- Prohibición terminante de invocación de subprocesos y comandos del sistema (`system`, `popen`).
- Detección de llamadas al sistema restringidas o no autorizadas (red, sockets, bifurcación no controlada).

### Qué no cubre (Límites y Delegación)
- Propiedad de la detección de funciones inseguras (`gets`, `strcpy`, `sprintf`, `scanf("%s")`): es de `kaneda`. `gaff` (`0x5004h`, `0x5006h`, `0x5008h`) solo señala el uso desde el estilo y `spunkmeyer` lo hace como antipatrón didáctico; no son la fuente de verdad de seguridad.
- Confinamiento y sandbox en tiempo de ejecución (delegado a `nostromo`).
- Análisis dinámico de sanitizers en memoria (delegado a `tetsuo`).
- Depuración post-mortem de crashes (delegado a `hal`).

---

## 📋 Requisitos

### Requisitos de Sistema y Entorno
- Multiplataforma. Python >= 3.10.

### Dependencias Externas y Binarios
- Ninguno obligatorio (análisis estático con Tree-Sitter AST).

### Integración en el Ecosistema
- CLI `kaneda`. Plugin registrado en `ripley.plugins` (`security`). Subcomando `kaneda doctor`.

---

## Uso Rápido

```bash
# 1. Auditar archivos C o carpetas de código
kaneda audit src/ main.c

# 2. Salida estructurada JSON
kaneda audit src/ --json

# 3. Listar catálogo de reglas (con su CWE) o exportarlo versionado
kaneda rules
kaneda rules --json

# 4. Explicar una regla: riesgo, CWE, cómo corregirla y un ejemplo antes y después
kaneda explain KAN002
```

kaneda es el dueño del catálogo de funciones inseguras: cada regla lleva su CWE (CWE-120,
CWE-134…) y, si existe, la regla del apunte que la cubre; `kaneda rules --json` lo exporta con
`version_catalogo` para que lo referencien las otras herramientas. Con `audit --json` sale además
`hallazgos`, la forma común del ecosistema (`yutani.hallazgos`).

**Supresión con motivo.** Si en una línea el uso es correcto, se suprime con un comentario en esa
línea o en la anterior: `// kaneda:ignore KAN002 el destino se reservó con strlen + 1`. Sin
códigos se suprime cualquier regla de esa línea. Las supresiones no hacen fallar la auditoría, pero
se informan con su motivo (en `suprimidas` del JSON) para que el docente las vea.

<!-- p1:referencia:inicio — generado por p1-tools/scripts/readme_generado.py: no editar a mano -->

## Referencia rápida

### Requisitos

- Python ≥ 3.11 y [uv](https://docs.astral.sh/uv/getting-started/installation/).

### Comandos

| Comando | Descripción |
|:--|:--|
| `kaneda audit` | Audita código C en busca de funciones vulnerables a buffer overflow y llamadas restringidas. |
| `kaneda report` | Genera directamente la sección de reporte Markdown de KANEDA para Dredd. |
| `kaneda rules` | Lista las reglas de seguridad auditadas por KANEDA. |
| `kaneda explain` | Explica una regla: el riesgo, su CWE, cómo corregirla y un ejemplo antes y después (QoL #577). |
| `kaneda doctor` | Verifica el estado del entorno de auditoría de seguridad KANEDA (Tree-Sitter C, Python, GCC). |

Ayuda de cada comando: `kaneda <comando> -h`.

### Salida JSON

Con `--json`, estos comandos emiten el resultado como JSON por la salida estándar, para usarlo desde scripts, ripley o dredd: `kaneda audit`, `kaneda rules`, `kaneda doctor`. El de `doctor --json` lleva `schema_version` y `ok`.

### Códigos de salida

| Código | Significado |
|:--|:--|
| `0` | Terminó bien (en `doctor`: está todo lo requerido). |
| `1` | El comando encontró problemas (hallazgos, pruebas que fallan, un umbral que no se alcanza) o un dato no se pudo usar (un archivo ilegible, un formato inválido). |
| `2` | Error de uso: comando, opción o argumento inválido. |

<!-- p1:referencia:fin -->
