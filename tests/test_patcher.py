"""
Pruebas unitarias para la generación de Artifacts de parches con plantillas semánticas.
"""

from pathlib import Path
from sentinel.core.analyzer import IssueItem
from sentinel.core.patcher import generate_patch_artifact


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
