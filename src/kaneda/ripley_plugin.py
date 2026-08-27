"""Plugin de KANEDA para integración transparente con RIPLEY."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from kaneda.core.security import auditar_archivos


class KanedaPlugin:
    """Plugin de auditoría de seguridad y llamadas restringidas para Ripley."""

    name = "security_audit"
    version = "0.1.0"

    def is_available(self) -> bool:
        return True

    def execute(self, workspace: Path, manifest_config: Dict[str, Any]) -> Dict[str, Any]:
        reporte = auditar_archivos([workspace])
        observaciones = []

        for v in reporte.vulnerabilidades:
            observaciones.append({
                "codigo": v.codigo,
                "severidad": "ERROR" if v.severidad in ("CRITICO", "ALTO") else "WARNING",
                "archivo": str(v.archivo),
                "linea": v.linea,
                "columna": v.columna,
                "mensaje": f"{v.titulo}: {v.mensaje}",
                "sugerencia": v.sugerencia,
            })

        return {
            "ok": reporte.ok,
            "total_vulnerabilidades": len(reporte.vulnerabilidades),
            "total_criticas": reporte.total_criticas,
            "observaciones": observaciones,
        }
