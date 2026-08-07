"""
Pruebas unitarias para la generación de Artifacts de parches y modo interactivo.
"""

from pathlib import Path
from sentinel.core.analyzer import IssueItem
from sentinel.core.patcher import generate_patch_artifact, apply_patch_interactively


def test_generate_patch_artifact_with_semantic_remediation(tmp_path: Path) -> None:
    dummy_file = tmp_path / "codigo.py"
    dummy_file.write_text("eval(x)", encoding="utf-8")

    issues = [
        IssueItem(
            file_path=str(dummy_file),
            line_number=1,
            severity="ALTA",
            code="SEC001",
            message="Uso inseguro de eval()",
        )
    ]

    out_dir = tmp_path / "artifacts"
    artifact_file = generate_patch_artifact(dummy_file, issues, output_dir=out_dir)

    assert artifact_file.exists()
    content = artifact_file.read_text(encoding="utf-8")
    assert "Propuesta de Parche de Remediación Semántica" in content
    assert "ast.literal_eval" in content


def test_apply_patch_interactively_creates_backup(tmp_path: Path) -> None:
    source_file = tmp_path / "target.py"
    source_file.write_text("print('test')", encoding="utf-8")

    issues = [
        IssueItem(
            file_path=str(source_file),
            line_number=1,
            severity="MEDIA",
            code="TYP001",
            message="Falta tipo de retorno",
        )
    ]

    # Auto confirm para simulación no interactiva
    applied = apply_patch_interactively(source_file, issues, auto_confirm=True)
    assert applied is True

    # Verificar que existe archivo backup .bak
    backup_file = tmp_path / "target.py.bak"
    assert backup_file.exists()
    assert backup_file.read_text(encoding="utf-8") == "print('test')"

    # Verificar que el contenido fuente fue actualizado
    updated_content = source_file.read_text(encoding="utf-8")
    assert "SENTINEL PATCH APPLIED" in updated_content
