"""Modelos de datos para el motor de auditoría de seguridad en KANEDA."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Vulnerabilidad:
    """Representa una vulnerabilidad o función insegura detectada."""
    codigo: str                 # KAN001, KAN002...
    titulo: str
    severidad: str              # "CRITICO", "ALTO", "MEDIO", "BAJO"
    archivo: Path
    linea: int
    columna: int
    mensaje: str
    sugerencia: str
    codigo_linea: str = ""
    # Con `// kaneda:ignore`: no cuenta, pero se informa con su motivo (QoL #583).
    suprimida: bool = False
    motivo_supresion: str = ""

    @property
    def cwe(self) -> Optional[str]:
        from kaneda.core.rules import CATALOGO_SEGURIDAD

        return CATALOGO_SEGURIDAD.get(self.codigo, {}).get("cwe")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "codigo": self.codigo,
            "cwe": self.cwe,
            "titulo": self.titulo,
            "severidad": self.severidad,
            "archivo": str(self.archivo),
            "linea": self.linea,
            "columna": self.columna,
            "mensaje": self.mensaje,
            "sugerencia": self.sugerencia,
            "codigo_linea": self.codigo_linea,
            **({"motivo_supresion": self.motivo_supresion or "(sin motivo)"} if self.suprimida else {}),
        }


@dataclass
class ReporteSeguridad:
    """Reporte consolidado de auditoría de seguridad."""
    archivos_analizados: int
    vulnerabilidades: List[Vulnerabilidad] = field(default_factory=list)
    suprimidas: List[Vulnerabilidad] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return len(self.vulnerabilidades) == 0

    @property
    def total_criticas(self) -> int:
        return sum(1 for v in self.vulnerabilidades if v.severidad in ("CRITICO", "ALTO"))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "ok": self.ok,
            "archivos_analizados": self.archivos_analizados,
            "total_vulnerabilidades": len(self.vulnerabilidades),
            "total_criticas": self.total_criticas,
            "vulnerabilidades": [v.to_dict() for v in self.vulnerabilidades],
            "suprimidas": [v.to_dict() for v in self.suprimidas],
            # La forma común del ecosistema (yutani.hallazgos), para dredd y el apunte.
            "hallazgos": [a_hallazgo(v) for v in self.vulnerabilidades],
        }


_SEVERIDAD_COMUN = {"CRITICO": "error", "ALTO": "error", "MEDIO": "advertencia", "BAJO": "estilo"}


def a_hallazgo(v: Vulnerabilidad) -> Dict[str, Any]:
    from yutani.hallazgos import enlace_apunte, hallazgo

    from kaneda.core.rules import CATALOGO_SEGURIDAD

    datos: Dict[str, Any] = hallazgo("kaneda", v.codigo, "seguridad", _SEVERIDAD_COMUN.get(v.severidad, "advertencia"),
                                     v.mensaje, archivo=str(v.archivo), linea=v.linea, columna=v.columna,
                                     sugerencia=v.sugerencia or None)
    regla = CATALOGO_SEGURIDAD.get(v.codigo, {}).get("regla_catedra")
    if regla:
        datos["enlace"] = enlace_apunte("seguridad", regla)
    datos["cwe"] = v.cwe
    return datos
