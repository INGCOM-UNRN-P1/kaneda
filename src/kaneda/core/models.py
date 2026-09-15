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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "codigo": self.codigo,
            "titulo": self.titulo,
            "severidad": self.severidad,
            "archivo": str(self.archivo),
            "linea": self.linea,
            "columna": self.columna,
            "mensaje": self.mensaje,
            "sugerencia": self.sugerencia,
            "codigo_linea": self.codigo_linea,
        }


@dataclass
class ReporteSeguridad:
    """Reporte consolidado de auditoría de seguridad."""
    archivos_analizados: int
    vulnerabilidades: List[Vulnerabilidad] = field(default_factory=list)

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
        }
