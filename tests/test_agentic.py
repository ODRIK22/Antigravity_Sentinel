"""
Pruebas unitarias para el bucle agéntico de autocorrección (--auto-fix).
"""

from pathlib import Path
from sentinel.core.analyzer import IssueItem
from sentinel.core.agentic import AgenticFixLoop


def test_agentic_fix_loop_execution(tmp_path: Path) -> None:
    target = tmp_path / "app.py"
    target.write_text("def test(): pass", encoding="utf-8")

    issues = [
        IssueItem(
            file_path=str(target),
            line_number=1,
            severity="MEDIA",
            code="TYP001",
            message="Falta tipo de retorno",
        )
    ]

    loop = AgenticFixLoop(target, issues, max_iterations=1)
    # Simular ejecución del bucle
    success = loop.execute_loop()

    # Verificar que el backup fue creado
    assert (tmp_path / "app.py.bak").exists()
