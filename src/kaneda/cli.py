"""CLI de KANEDA — Auditor pedagógico de seguridad y llamadas a sistema en C."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from kaneda import __version__
from kaneda.core.rules import CATALOGO_SEGURIDAD
from kaneda.core.security import auditar_archivos

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    name="kaneda",
    help="🔒 KANEDA — Auditor pedagógico de seguridad C, buffer overflows y llamadas a sistema restringidas.",
    add_completion=True,
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]KANEDA[/bold cyan] versión [bold]{__version__}[/bold]")
        raise typer.Exit(code=0)


@app.callback()
def main_callback(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Muestra la versión de KANEDA.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    pass


@app.command("audit")
def audit_cmd(
    rutas: List[Path] = typer.Argument(..., help="Archivos C/H o directorios a auditar."),
    json_output: bool = typer.Option(False, "--json", help="Salida estructurada en JSON."),
    strict: bool = typer.Option(False, "--strict", help="Falla si se detecta cualquier advertencia menor."),
) -> None:
    """Audita código C en busca de funciones vulnerables a buffer overflow y llamadas restringidas."""
    reporte = auditar_archivos(rutas)

    if json_output:
        print(json.dumps(reporte.to_dict(), indent=2, ensure_ascii=False))
        raise typer.Exit(code=0 if reporte.ok else 1)

    if reporte.ok:
        console.print(Panel(
            f"[bold green]✓ No se detectaron vulnerabilidades ni funciones prohibidas en los {reporte.archivos_analizados} archivos analizados.[/bold green]",
            title="KANEDA Security Check OK",
            border_style="green",
        ))
        raise typer.Exit(code=0)

    console.print(f"\n[bold red]⚠️ Se detectaron {len(reporte.vulnerabilidades)} problemas de seguridad:[/bold red]\n")

    tabla = Table(title="Vulnerabilidades de Seguridad Detectadas")
    tabla.add_column("Ubicación", style="cyan")
    tabla.add_column("Código", justify="center", style="bold yellow")
    tabla.add_column("Severidad", justify="center")
    tabla.add_column("Detalle")
    tabla.add_column("Sugerencia de Remediación", style="dim")

    for v in reporte.vulnerabilidades:
        color_sev = "bold red" if v.severidad in ("CRITICO", "ALTO") else "yellow"
        tabla.add_row(
            f"{v.archivo.name}:{v.linea}",
            v.codigo,
            f"[{color_sev}]{v.severidad}[/{color_sev}]",
            v.titulo,
            v.sugerencia,
        )

    console.print(tabla)
    raise typer.Exit(code=1)


@app.command("rules")
def rules_cmd() -> None:
    """Lista las reglas de seguridad auditadas por KANEDA."""
    tabla = Table(title=f"Catálogo de Reglas de Seguridad KANEDA ({len(CATALOGO_SEGURIDAD)} reglas)")
    tabla.add_column("Código", justify="center", style="bold cyan")
    tabla.add_column("Severidad", justify="center")
    tabla.add_column("Título", style="bold")
    tabla.add_column("Descripción")

    for cod, info in sorted(CATALOGO_SEGURIDAD.items()):
        color = "red" if info["severidad"] in ("CRITICO", "ALTO") else "yellow"
        tabla.add_row(cod, f"[{color}]{info['severidad']}[/{color}]", info["titulo"], info["descripcion"])

    console.print(tabla)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
