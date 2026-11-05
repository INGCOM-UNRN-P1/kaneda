"""Motor de análisis estático de vulnerabilidades y seguridad en KANEDA usando Tree-Sitter AST."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

import tree_sitter_c as tsc
from tree_sitter import Language, Node, Parser, Query, QueryCursor

from kaneda.core.models import ReporteSeguridad, Vulnerabilidad
from kaneda.core.rules import CATALOGO_SEGURIDAD
from kaneda.core.preprocesador import enmascarar_bloques_inactivos
from kaneda.core.supresion import leer_supresiones, suprimida

_C_LANGUAGE: Optional[Language] = None
_PARSER: Optional[Parser] = None
_CONSULTA: Optional[Query] = None

# Todas las reglas son sobre llamadas: la consulta las encuentra y `_REGLAS` decide por el nombre. Sin
# recorrer el árbol desde Python, un programa muy anidado ya no agota la pila del intérprete.
LLAMADAS = """
(call_expression
  function: [(identifier) @funcion
             (parenthesized_expression (identifier) @funcion)]
  arguments: (argument_list) @argumentos) @llamada
"""


def _texto(info: Dict[str, Optional[str]], clave: str) -> str:
    """Un campo de texto del catálogo (los opcionales, como el CWE, pueden ser None)."""
    return info.get(clave) or ""


def _codigo_fuente(nodo: Node) -> str:
    return (nodo.text or b"").decode("utf-8", errors="replace")


def get_c_parser() -> Parser:
    global _C_LANGUAGE, _PARSER
    if _PARSER is None:
        _C_LANGUAGE = Language(tsc.language())
        _PARSER = Parser(_C_LANGUAGE)
    return _PARSER


def _consulta_de_llamadas() -> Query:
    global _CONSULTA
    if _CONSULTA is None:
        get_c_parser()
        assert _C_LANGUAGE is not None
        _CONSULTA = Query(_C_LANGUAGE, LLAMADAS)
    return _CONSULTA


def _argumentos(nodo: Node) -> List[Node]:
    return [a for a in nodo.children if a.type not in ("(", ")", ",")]


def _descripcion(codigo: str) -> Callable[[str, Node], Optional[str]]:
    return lambda _funcion, _argumentos_nodo: _texto(CATALOGO_SEGURIDAD[codigo], "descripcion")


def _lectura_sin_limite(_funcion: str, argumentos: Node) -> Optional[str]:
    """KAN004: `%s` en scanf y sus variantes sobre archivo o cadena, la misma lectura sin límite."""
    con_s = any(a.type == "string_literal" and "%s" in _codigo_fuente(a) for a in argumentos.children)
    return _texto(CATALOGO_SEGURIDAD["KAN004"], "descripcion") if con_s else None


def _formato_variable(funcion: str, argumentos: Node) -> Optional[str]:
    """KAN005: la cadena de formato es el argumento 0 en printf y el 1 en fprintf."""
    reales = _argumentos(argumentos)
    posicion = 0 if funcion == "printf" else 1
    if len(reales) != posicion + 1 or reales[posicion].type not in (
            "identifier", "field_expression", "call_expression", "subscript_expression"):
        return None
    variable = _codigo_fuente(reales[posicion])
    llamada = variable if posicion == 0 else f"{_codigo_fuente(reales[0])}, {variable}"
    return f"Invocación '{funcion}({llamada})' sin cadena de formato literal constante."


def _por_nombre(plantilla: str) -> Callable[[str, Node], Optional[str]]:
    return lambda funcion, _argumentos_nodo: plantilla.format(funcion=funcion)


def _reglas() -> Dict[str, tuple]:
    """Función de C → (regla, cómo decide el mensaje; None si esa llamada está bien)."""
    reglas = {"gets": ("KAN001", _descripcion("KAN001")), "sprintf": ("KAN003", _descripcion("KAN003"))}
    reglas.update({f: ("KAN002", _por_nombre("Uso inseguro de '{funcion}()'.")) for f in ("strcpy", "strcat")})
    reglas.update({f: ("KAN004", _lectura_sin_limite) for f in ("scanf", "fscanf", "sscanf")})
    reglas.update({f: ("KAN005", _formato_variable) for f in ("printf", "fprintf")})
    reglas.update({f: ("KAN006", _por_nombre("Llamada a '{funcion}()' detectada.")) for f in ("system", "popen")})
    reglas.update({f: ("KAN007", _por_nombre("Llamada a syscall restringida '{funcion}()'."))
                   for f in ("fork", "execl", "execv", "execvp", "execle", "execve", "ptrace", "kill", "socket",
                             "connect", "bind", "listen")})
    return reglas


_REGLAS = _reglas()


def auditar_archivo(archivo: Path) -> List[Vulnerabilidad]:
    """Audita un archivo C en busca de patrones de inseguridad conocidos usando Tree-Sitter AST."""
    archivo = Path(archivo)
    if not archivo.is_file():
        return []

    try:
        contenido = archivo.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    contenido_original = contenido
    # El contenido de un `#if 0` no se compila: enmascararlo evita reportar
    # hallazgos sobre código deliberadamente desactivado.
    contenido = enmascarar_bloques_inactivos(contenido)

    lineas = contenido.splitlines()
    tree = get_c_parser().parse(contenido.encode("utf-8"))

    coincidencias = [c for _, c in QueryCursor(_consulta_de_llamadas()).matches(tree.root_node)]
    # En el orden del fuente, y la llamada de afuera antes que la que va en sus argumentos.
    coincidencias.sort(key=lambda c: (c["llamada"][0].start_byte, -c["llamada"][0].end_byte))

    vulnerabilidades: List[Vulnerabilidad] = []
    for coincidencia in coincidencias:
        funcion = _codigo_fuente(coincidencia["funcion"][0])
        if funcion not in _REGLAS:
            continue
        codigo, mensaje_de = _REGLAS[funcion]
        mensaje = mensaje_de(funcion, coincidencia["argumentos"][0])
        if mensaje is None:
            continue
        llamada = coincidencia["llamada"][0]
        info = CATALOGO_SEGURIDAD[codigo]
        fila = llamada.start_point.row
        vulnerabilidades.append(Vulnerabilidad(
            codigo=codigo,
            titulo=_texto(info, "titulo"),
            severidad=_texto(info, "severidad"),
            archivo=archivo,
            linea=fila + 1,
            columna=llamada.start_point.column + 1,
            mensaje=mensaje,
            sugerencia=_texto(info, "sugerencia"),
            codigo_linea=lineas[fila] if fila < len(lineas) else "",
        ))

    supresiones = leer_supresiones(contenido_original.splitlines())
    unicas: List[Vulnerabilidad] = []
    vistas: Set[tuple[str, int]] = set()
    for v in vulnerabilidades:
        clave = (v.codigo, v.linea)
        if clave in vistas:
            continue
        vistas.add(clave)
        v.suprimida, v.motivo_supresion = suprimida(v.codigo, v.linea, supresiones)
        unicas.append(v)
    return unicas


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
        vulnerabilidades=[v for v in vulns if not v.suprimida],
        suprimidas=[v for v in vulns if v.suprimida],
    )
