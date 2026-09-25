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

# 3. Listar catálogo de reglas
kaneda rules
```
