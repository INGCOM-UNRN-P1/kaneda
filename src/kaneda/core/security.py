"""Motor de análisis estático de vulnerabilidades y seguridad en KANEDA."""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Set

from kaneda.core.models import ReporteSeguridad, Vulnerabilidad
from kaneda.core.rules import CATALOGO_SEGURIDAD


def _eliminar_comentarios_y_cadenas(texto: str) -> str:
    def replacer(match):
        s = match.group(0)
        if s.startswith("/"):
            return "".join("\n" if c == "\n" else " " for c in s)
        return s

    pattern = re.compile(r'//.*?$|/\*.*?\*/', re.DOTALL | re.MULTILINE)
    return re.sub(pattern, replacer, texto)


def auditar_archivo(archivo: Path) -> List[Vulnerabilidad]:
    """Audita un archivo C en busca de patrones de inseguridad conocidos."""
    archivo = Path(archivo)
    if not archivo.is_file():
        return []

    try:
        contenido = archivo.read_text(encoding="utf-8")
    except Exception:
        return []

    lineas = contenido.splitlines()
    codigo_sin_comentarios = _eliminar_comentarios_y_cadenas(contenido)
    lineas_limpias = codigo_sin_comentarios.splitlines()

    vulnerabilidades: List[Vulnerabilidad] = []

    # KAN001: gets()
    re_gets = re.compile(r"\bgets\s*\(")
    # KAN002: strcpy() / strcat()
    re_strcpy = re.compile(r"\b(strcpy|strcat)\s*\(")
    # KAN003: sprintf()
    re_sprintf = re.compile(r"\bsprintf\s*\(")
    # KAN004: scanf("%s")
    re_scanf = re.compile(r'\bscanf\s*\(\s*"[^"]*%s[^"]*"')
    # KAN005: printf(variable)
    re_printf_fmt = re.compile(r'\bprintf\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)')
    # KAN006: system() / popen()
    re_system = re.compile(r"\b(system|popen)\s*\(")
    # KAN007: fork / exec / ptrace / kill / socket
    re_syscall = re.compile(r"\b(fork|exec[l|v][p|e]?|ptrace|kill|socket|connect|bind|listen)\s*\(")

    for idx, l in enumerate(lineas_limpias, 1):
        # KAN001
        if m := re_gets.search(l):
            info = CATALOGO_SEGURIDAD["KAN001"]
            vulnerabilidades.append(Vulnerabilidad(
                codigo="KAN001",
                titulo=info["titulo"],
                severidad=info["severidad"],
                archivo=archivo,
                linea=idx,
                columna=m.start() + 1,
                mensaje=info["descripcion"],
                sugerencia=info["sugerencia"],
                codigo_linea=lineas[idx - 1],
            ))

        # KAN002
        if m := re_strcpy.search(l):
            info = CATALOGO_SEGURIDAD["KAN002"]
            vulnerabilidades.append(Vulnerabilidad(
                codigo="KAN002",
                titulo=info["titulo"],
                severidad=info["severidad"],
                archivo=archivo,
                linea=idx,
                columna=m.start() + 1,
                mensaje=f"Uso inseguro de '{m.group(1)}()'.",
                sugerencia=info["sugerencia"],
                codigo_linea=lineas[idx - 1],
            ))

        # KAN003
        if m := re_sprintf.search(l):
            info = CATALOGO_SEGURIDAD["KAN003"]
            vulnerabilidades.append(Vulnerabilidad(
                codigo="KAN003",
                titulo=info["titulo"],
                severidad=info["severidad"],
                archivo=archivo,
                linea=idx,
                columna=m.start() + 1,
                mensaje=info["descripcion"],
                sugerencia=info["sugerencia"],
                codigo_linea=lineas[idx - 1],
            ))

        # KAN004
        if m := re_scanf.search(l):
            info = CATALOGO_SEGURIDAD["KAN004"]
            vulnerabilidades.append(Vulnerabilidad(
                codigo="KAN004",
                titulo=info["titulo"],
                severidad=info["severidad"],
                archivo=archivo,
                linea=idx,
                columna=m.start() + 1,
                mensaje=info["descripcion"],
                sugerencia=info["sugerencia"],
                codigo_linea=lineas[idx - 1],
            ))

        # KAN005
        if m := re_printf_fmt.search(l):
            info = CATALOGO_SEGURIDAD["KAN005"]
            vulnerabilidades.append(Vulnerabilidad(
                codigo="KAN005",
                titulo=info["titulo"],
                severidad=info["severidad"],
                archivo=archivo,
                linea=idx,
                columna=m.start() + 1,
                mensaje=f"Invocación 'printf({m.group(1)})' sin cadena de formato literal constante.",
                sugerencia=info["sugerencia"],
                codigo_linea=lineas[idx - 1],
            ))

        # KAN006
        if m := re_system.search(l):
            info = CATALOGO_SEGURIDAD["KAN006"]
            vulnerabilidades.append(Vulnerabilidad(
                codigo="KAN006",
                titulo=info["titulo"],
                severidad=info["severidad"],
                archivo=archivo,
                linea=idx,
                columna=m.start() + 1,
                mensaje=f"Llamada a '{m.group(1)}()' detectada.",
                sugerencia=info["sugerencia"],
                codigo_linea=lineas[idx - 1],
            ))

        # KAN007
        if m := re_syscall.search(l):
            info = CATALOGO_SEGURIDAD["KAN007"]
            vulnerabilidades.append(Vulnerabilidad(
                codigo="KAN007",
                titulo=info["titulo"],
                severidad=info["severidad"],
                archivo=archivo,
                linea=idx,
                columna=m.start() + 1,
                mensaje=f"Llamada a syscall restringida '{m.group(1)}()'.",
                sugerencia=info["sugerencia"],
                codigo_linea=lineas[idx - 1],
            ))

    return vulnerabilidades


def auditar_archivos(rutas: List[Path]) -> ReporteSeguridad:
    """Audita un conjunto de archivos o directorios."""
    archivos_objetivo: Set[Path] = set()
    for r in rutas:
        p = Path(r)
        if p.is_file() and p.suffix.lower() in (".c", ".h"):
            archivos_objetivo.add(p)
        elif p.is_dir():
            for sub in p.rglob("*"):
                if sub.is_file() and sub.suffix.lower() in (".c", ".h"):
                    archivos_objetivo.add(sub)

    vulns: List[Vulnerabilidad] = []
    for arch in sorted(archivos_objetivo):
        vulns.extend(auditar_archivo(arch))

    return ReporteSeguridad(
        archivos_analizados=len(archivos_objetivo),
        vulnerabilidades=vulns,
    )
