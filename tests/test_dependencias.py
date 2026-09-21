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
