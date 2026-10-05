"""Supresión en línea con motivo (QoL #583).

    strcpy(destino, origen);  // kaneda:ignore KAN002 el destino se reservó con strlen(origen) + 1

o en la línea anterior. Sin códigos se suprime cualquier regla de esa línea. El motivo es lo que
queda después de los códigos: la supresión se informa igual (con su motivo) para que el docente la
vea, y una sin motivo se marca como tal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

_DIRECTIVA = re.compile(r"(?://|/\*)\s*kaneda:ignore\b(?P<resto>[^\n]*?)(?:\*/)?\s*$", re.IGNORECASE)
_CODIGO = re.compile(r"KAN\d{3}", re.IGNORECASE)


@dataclass
class Supresion:
    codigos: Optional[List[str]]  # None: todas las reglas
    motivo: str


def leer_supresiones(lineas: List[str]) -> Dict[int, Supresion]:
    """Número de línea (desde 1) → supresión que la cubre (la de la misma línea o la anterior)."""
    supresiones: Dict[int, Supresion] = {}
    for n, linea in enumerate(lineas, 1):
        m = _DIRECTIVA.search(linea)
        if not m:
            continue
        resto = m.group("resto").strip(" :=-")
        codigos = [c.upper() for c in _CODIGO.findall(resto)]
        motivo = _CODIGO.sub("", resto).strip(" ,:;-—")
        sup = Supresion(codigos or None, motivo)
        solo_comentario = linea.strip().startswith(("//", "/*"))
        supresiones[n + 1 if solo_comentario else n] = sup
    return supresiones


def suprimida(codigo: str, linea: int, supresiones: Dict[int, Supresion]) -> Tuple[bool, str]:
    sup = supresiones.get(linea)
    if sup and (sup.codigos is None or codigo in sup.codigos):
        return True, sup.motivo
    return False, ""
