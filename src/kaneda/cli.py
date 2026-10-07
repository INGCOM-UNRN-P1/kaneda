"""CLI de KANEDA — Auditor pedagógico de seguridad y llamadas a sistema en C."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import typer
from yutani.cli import crear_app
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from kaneda import __version__
from kaneda.core.rules import CATALOGO_SEGURIDAD, CATALOGO_VERSION
from kaneda.core.security import auditar_archivos

console = Console()
err_console = Console(stderr=True)

# Contrato de línea de comandos del ecosistema (-h/--help, --version/-v, errores de datos como
# mensajes) y textos de Typer en español, desde yutani (N-ECO-14).
app = crear_app(
    "kaneda",
    __version__,
    "🔒 KANEDA — Auditor pedagógico de seguridad C, buffer overflows y llamadas a sistema restringidas.",
    add_completion=True,
)


def generar_seccion_markdown(reporte) -> str:
    """Genera sección de auditoría de seguridad para Dredd."""
    status = "ok" if reporte.ok else "fail"
    lines = [
        f"<!-- dredd-section: kaneda, tool=kaneda, version=1.0.0, status={status} -->\n",
        "## Auditoría de Seguridad y Syscalls (Kaneda)\n",
    ]
    lines.append(f"- **Archivos analizados:** {reporte.archivos_analizados}")
    lines.append(f"- **Vulnerabilidades detectadas:** {len(reporte.vulnerabilidades)}")
    lines.append("")
    if reporte.ok:
        lines.append("> [!TIP]\n> **Código Seguro:** No se detectaron funciones prohibidas (`gets`, `strcpy`, `sprintf`), buffers vulnerables ni llamadas a sistema no autorizadas.\n")
    else:
        lines.append("| Archivo | Línea | Código | Severidad | Vulnerabilidad | Sugerencia |")
        lines.append("| :--- | :---: | :---: | :---: | :--- | :--- |")
        for v in reporte.vulnerabilidades:
            nom_limpio = v.archivo.name.replace("|", "&#124;")
            tit_limpio = v.titulo.replace("|", "&#124;")
            sug_limpio = v.sugerencia.replace("|", "&#124;")
            lines.append(f"| `{nom_limpio}` | {v.linea} | `{v.codigo}` | **{v.severidad}** | {tit_limpio} | {sug_limpio} |")
        lines.append("")
    return "\n".join(lines)


@app.command("audit")
def audit_cmd(
    rutas: List[Path] = typer.Argument(..., exists=True, help="Archivos C/H o directorios a auditar."),
    json_output: bool = typer.Option(False, "--json", help="Salida estructurada en JSON."),
    output_md: Optional[Path] = typer.Option(None, "--md", "--output-md", "-o", help="Generar sección de reporte en formato Markdown para fusión en Dredd."),
    strict: bool = typer.Option(False, "--strict", hidden=True, help="Sin efecto: cualquier hallazgo ya hace fallar la auditoría (se acepta por compatibilidad)."),
) -> None:
    """Audita código C en busca de funciones vulnerables a buffer overflow y llamadas restringidas."""
    reporte = auditar_archivos(rutas)

    if output_md:
        md_text = generar_seccion_markdown(reporte)
        output_md.parent.mkdir(parents=True, exist_ok=True)
        output_md.write_text(md_text, encoding="utf-8")
        console.print(f"[green]✓ Sección Markdown generada en:[/green] [cyan]{output_md}[/cyan]")
        raise typer.Exit(code=0 if reporte.ok else 1)

    if json_output:
        print(json.dumps(reporte.to_dict(), indent=2, ensure_ascii=False))
        raise typer.Exit(code=0 if reporte.ok else 1)

    for v in reporte.suprimidas:
        console.print(f"[dim]Suprimida {v.codigo} en {v.archivo.name}:{v.linea} — {v.motivo_supresion or '(sin motivo)'}[/dim]")

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


@app.command("report")
def report_cmd(
    rutas: List[Path] = typer.Argument(..., exists=True, help="Archivos C/H o directorios a auditar."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Ruta de destino del archivo Markdown."),
) -> None:
    """Genera directamente la sección de reporte Markdown de KANEDA para Dredd."""
    reporte = auditar_archivos(rutas)
    md_content = generar_seccion_markdown(reporte)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(md_content, encoding="utf-8")
        console.print(f"[green]✓ Reporte Markdown generado en:[/green] [cyan]{output}[/cyan]")
    else:
        print(md_content)
    if not reporte.ok:
        raise typer.Exit(code=1)


@app.command("rules")
def rules_cmd(
    json_output: bool = typer.Option(False, "--json", "-j", help="Exportar el catálogo versionado (con CWE y regla del apunte) en JSON."),
) -> None:
    """Lista las reglas de seguridad auditadas por KANEDA."""
    if json_output:
        print(json.dumps({
            "schema_version": "1.0.0",
            "herramienta": "kaneda",
            "version_catalogo": CATALOGO_VERSION,
            "reglas": [{"codigo": cod, **info} for cod, info in sorted(CATALOGO_SEGURIDAD.items())],
        }, indent=2, ensure_ascii=False))
        return
    tabla = Table(title=f"Catálogo de Reglas de Seguridad KANEDA ({len(CATALOGO_SEGURIDAD)} reglas)")
    tabla.add_column("Código", justify="center", style="bold cyan")
    tabla.add_column("Severidad", justify="center")
    tabla.add_column("CWE", justify="center", style="magenta")
    tabla.add_column("Título", style="bold")
    tabla.add_column("Descripción")

    for cod, info in sorted(CATALOGO_SEGURIDAD.items()):
        color = "red" if info["severidad"] in ("CRITICO", "ALTO") else "yellow"
        tabla.add_row(cod, f"[{color}]{info['severidad']}[/{color}]", info.get("cwe") or "—", info["titulo"], info["descripcion"])

    console.print(tabla)
    console.print("[dim]`kaneda explain KAN002` explica una regla con un ejemplo; `--json` exporta el catálogo.[/dim]")


@app.command("explain")
def explain_cmd(
    regla: str = typer.Argument(..., help="Código de la regla (por ejemplo KAN002)."),
) -> None:
    """Explica una regla: el riesgo, su CWE, cómo corregirla y un ejemplo antes y después (QoL #577)."""
    info = CATALOGO_SEGURIDAD.get(regla.strip().upper())
    if info is None:
        err_console.print(f"[red]Error:[/red] no existe la regla '{regla}'. Las reglas son: {', '.join(sorted(CATALOGO_SEGURIDAD))}.")
        raise typer.Exit(code=2)
    cwe = info.get("cwe")
    enlaces = []
    if cwe:
        enlaces.append(f"{cwe}: https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html")
    if info.get("regla_catedra"):
        from yutani.hallazgos import enlace_apunte

        enlaces.append(f"Regla {info['regla_catedra']} del apunte: {enlace_apunte('seguridad', info['regla_catedra'])}")
    console.print(Panel(
        f"[bold]{info['titulo']}[/bold] ({info['severidad']})\n\n{info['descripcion']}\n\n"
        f"[bold green]Cómo corregirlo:[/bold green] {info['sugerencia']}\n\n"
        f"[bold red]✗ Antes:[/bold red]\n{info.get('ejemplo_incorrecto') or '—'}\n\n"
        f"[bold green]✓ Después:[/bold green]\n{info.get('ejemplo_correcto') or '—'}"
        + ("\n\n" + "\n".join(enlaces) if enlaces else "")
        + f"\n\n[dim]Si en una línea es correcto, suprimilo con un motivo: // kaneda:ignore {regla.upper()} <motivo>[/dim]",
        title=f"KANEDA · {regla.upper()}",
    ))


@app.command("doctor")
def doctor_cmd(
    json_output: bool = typer.Option(False, "--json", help="Emitir diagnóstico en formato JSON estructurado."),
) -> None:
    """Verifica el estado del entorno de auditoría de seguridad KANEDA (Tree-Sitter C, Python, GCC)."""
    import shutil
    import sys
    diagnostico = []

    # 1. Python runtime
    py_ok = sys.version_info >= (3, 10)
    diagnostico.append({
        "componente": "Python Runtime",
        "estado": "OK" if py_ok else "ERROR",
        "requerido": True,
        "detalle": f"Python {sys.version.split()[0]}",
    })

    # 2. Tree-Sitter C parser
    ts_ok = False
    try:
        import tree_sitter_c as tsc
        from tree_sitter import Language, Parser
        lang = Language(tsc.language())
        Parser(lang)
        ts_ok = True
        ts_det = "Gramática C AST cargada exitosamente"
    except Exception as e:
        ts_det = str(e)
    diagnostico.append({
        "componente": "Tree-Sitter C Grammar",
        "estado": "OK" if ts_ok else "ERROR",
        "requerido": True,
        "detalle": ts_det,
    })

    # 3. GCC compiler
    gcc_path = shutil.which("gcc")
    diagnostico.append({
        "componente": "Compilador GCC",
        "estado": "OK" if gcc_path else "ADVERTENCIA",
        "requerido": False,
        "detalle": gcc_path or "No encontrado (opcional para compilar código auditado)",
    })

    todo_ok = py_ok and ts_ok

    if json_output:
        payload = {
            "schema_version": "1.0.0",
            "herramienta": "kaneda",
            "ok": todo_ok,
            "componentes": diagnostico,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        raise typer.Exit(code=0 if todo_ok else 1)

    tabla = Table(title="🏥 Diagnóstico del Entorno KANEDA (doctor)", border_style="cyan")
    tabla.add_column("Componente", style="bold white")
    tabla.add_column("Estado", justify="center")
    tabla.add_column("Detalle")

    for c in diagnostico:
        color = "bold green" if c["estado"] == "OK" else ("bold yellow" if c["estado"] == "ADVERTENCIA" else "bold red")
        simbolo = "✓" if c["estado"] == "OK" else ("⚠️" if c["estado"] == "ADVERTENCIA" else "✗")
        tabla.add_row(str(c["componente"]), f"[{color}]{simbolo} {c['estado']}[/{color}]", str(c["detalle"]))

    console.print(tabla)
    if not todo_ok:
        console.print("\n[bold red]Ejecutá `pip install tree-sitter tree-sitter-c` para reparar dependencias faltantes.[/bold red]")
        raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
