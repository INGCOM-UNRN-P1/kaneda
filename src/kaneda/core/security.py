"""Motor de análisis estático de vulnerabilidades y seguridad en KANEDA usando Tree-Sitter AST."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Set

import tree_sitter_c as tsc
from tree_sitter import Language, Parser, Node

from kaneda.core.models import ReporteSeguridad, Vulnerabilidad
from kaneda.core.rules import CATALOGO_SEGURIDAD
from kaneda.core.preprocesador import enmascarar_bloques_inactivos

_C_LANGUAGE: Optional[Language] = None
_PARSER: Optional[Parser] = None


def get_c_parser() -> Parser:
    global _C_LANGUAGE, _PARSER
    if _PARSER is None:
        _C_LANGUAGE = Language(tsc.language())
        _PARSER = Parser(_C_LANGUAGE)
    return _PARSER


def _find_identifier(node: Node) -> Optional[str]:
    if node.type in ("identifier", "type_identifier", "field_identifier"):
        return node.text.decode("utf-8", errors="replace")
    for child in node.children:
        res = _find_identifier(child)
        if res:
            return res
    return None


def auditar_archivo(archivo: Path) -> List[Vulnerabilidad]:
    """Audita un archivo C en busca de patrones de inseguridad conocidos usando Tree-Sitter AST."""
    archivo = Path(archivo)
    if not archivo.is_file():
        return []

    try:
        contenido = archivo.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    # El contenido de un `#if 0` no se compila: enmascararlo evita reportar
    # hallazgos sobre código deliberadamente desactivado.
    contenido = enmascarar_bloques_inactivos(contenido)

    lineas = contenido.splitlines()
    source_bytes = contenido.encode("utf-8")
    parser = get_c_parser()
    tree = parser.parse(source_bytes)

    vulnerabilidades: List[Vulnerabilidad] = []

    def _traverse(node: Node) -> None:
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            args_node = node.child_by_field_name("arguments")
            if func_node:
                func_name = _find_identifier(func_node)
                idx = node.start_point.row + 1
                col = node.start_point.column + 1
                linea_cod = lineas[node.start_point.row] if node.start_point.row < len(lineas) else ""

                # KAN001: gets()
                if func_name == "gets":
                    info = CATALOGO_SEGURIDAD["KAN001"]
                    vulnerabilidades.append(Vulnerabilidad(
                        codigo="KAN001",
                        titulo=info["titulo"],
                        severidad=info["severidad"],
                        archivo=archivo,
                        linea=idx,
                        columna=col,
                        mensaje=info["descripcion"],
                        sugerencia=info["sugerencia"],
                        codigo_linea=linea_cod,
                    ))

                # KAN002: strcpy() / strcat()
                elif func_name in ("strcpy", "strcat"):
                    info = CATALOGO_SEGURIDAD["KAN002"]
                    vulnerabilidades.append(Vulnerabilidad(
                        codigo="KAN002",
                        titulo=info["titulo"],
                        severidad=info["severidad"],
                        archivo=archivo,
                        linea=idx,
                        columna=col,
                        mensaje=f"Uso inseguro de '{func_name}()'.",
                        sugerencia=info["sugerencia"],
                        codigo_linea=linea_cod,
                    ))

                # KAN003: sprintf()
                elif func_name == "sprintf":
                    info = CATALOGO_SEGURIDAD["KAN003"]
                    vulnerabilidades.append(Vulnerabilidad(
                        codigo="KAN003",
                        titulo=info["titulo"],
                        severidad=info["severidad"],
                        archivo=archivo,
                        linea=idx,
                        columna=col,
                        mensaje=info["descripcion"],
                        sugerencia=info["sugerencia"],
                        codigo_linea=linea_cod,
                    ))

                # KAN004: scanf("%s")
                elif func_name == "scanf" and args_node:
                    for arg in args_node.children:
                        if arg.type == "string_literal" and "%s" in arg.text.decode("utf-8", errors="replace"):
                            info = CATALOGO_SEGURIDAD["KAN004"]
                            vulnerabilidades.append(Vulnerabilidad(
                                codigo="KAN004",
                                titulo=info["titulo"],
                                severidad=info["severidad"],
                                archivo=archivo,
                                linea=idx,
                                columna=col,
                                mensaje=info["descripcion"],
                                sugerencia=info["sugerencia"],
                                codigo_linea=linea_cod,
                            ))
                            break

                # KAN005: printf(variable)
                elif func_name == "printf" and args_node:
                    real_args = [a for a in args_node.children if a.type not in ("(", ")", ",")]
                    if len(real_args) == 1 and real_args[0].type in ("identifier", "field_expression", "call_expression"):
                        var_name = real_args[0].text.decode("utf-8", errors="replace")
                        info = CATALOGO_SEGURIDAD["KAN005"]
                        vulnerabilidades.append(Vulnerabilidad(
                            codigo="KAN005",
                            titulo=info["titulo"],
                            severidad=info["severidad"],
                            archivo=archivo,
                            linea=idx,
                            columna=col,
                            mensaje=f"Invocación 'printf({var_name})' sin cadena de formato literal constante.",
                            sugerencia=info["sugerencia"],
                            codigo_linea=linea_cod,
                        ))

                # KAN006: system() / popen()
                elif func_name in ("system", "popen"):
                    info = CATALOGO_SEGURIDAD["KAN006"]
                    vulnerabilidades.append(Vulnerabilidad(
                        codigo="KAN006",
                        titulo=info["titulo"],
                        severidad=info["severidad"],
                        archivo=archivo,
                        linea=idx,
                        columna=col,
                        mensaje=f"Llamada a '{func_name}()' detectada.",
                        sugerencia=info["sugerencia"],
                        codigo_linea=linea_cod,
                    ))

                # KAN007: fork / exec / ptrace / kill / socket / connect / bind / listen
                elif func_name in ("fork", "execl", "execv", "execvp", "execle", "execve", "ptrace", "kill", "socket", "connect", "bind", "listen"):
                    info = CATALOGO_SEGURIDAD["KAN007"]
                    vulnerabilidades.append(Vulnerabilidad(
                        codigo="KAN007",
                        titulo=info["titulo"],
                        severidad=info["severidad"],
                        archivo=archivo,
                        linea=idx,
                        columna=col,
                        mensaje=f"Llamada a syscall restringida '{func_name}()'.",
                        sugerencia=info["sugerencia"],
                        codigo_linea=linea_cod,
                    ))

        for child in node.children:
            _traverse(child)

    _traverse(tree.root_node)
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
