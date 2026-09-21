"""KANEDA-D0102: toda dependencia runtime declarada debe importarse en `src/`."""

import re
import tomllib
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]


def test_no_hay_dependencias_runtime_sin_uso():
    deps = tomllib.loads((RAIZ / "pyproject.toml").read_text(encoding="utf-8"))["project"]["dependencies"]
    fuente = "\n".join(p.read_text(encoding="utf-8") for p in (RAIZ / "src").rglob("*.py"))
    sin_uso = []
    for dep in deps:
        modulo = re.split(r"[<>=!~ ]", dep, maxsplit=1)[0].replace("-", "_")
        if not re.search(rf"^\s*(import|from)\s+{modulo}\b", fuente, re.MULTILINE):
            sin_uso.append(dep)
    assert not sin_uso, f"dependencias declaradas y nunca importadas: {sin_uso}"


def test_docs_no_atribuyen_a_kaneda_la_numeracion_0x30xxh():
    """KANEDA-D0802: los códigos emitidos son KAN00x; `0x30XXh` es de gaff."""
    from kaneda.core.rules import CATALOGO_SEGURIDAD

    assert all(re.fullmatch(r"KAN\d{3}", c) for c in CATALOGO_SEGURIDAD)
    for doc in ("README.md", "manual/index.md"):
        texto = (RAIZ / doc).read_text(encoding="utf-8")
        assert not re.search(r"reglas[^\n]*0x30[0-9A-Fa-fX]{2}h", texto.replace("no `0x30XXh`", "")), doc
