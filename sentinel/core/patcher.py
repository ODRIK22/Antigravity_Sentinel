"""
Generador de propuestas de parches interactivos mediante Artifacts (Zero Trust).
"""

from pathlib import Path
from typing import Sequence
from sentinel.core.analyzer import IssueItem


def generate_patch_artifact(
    target_file: Path,
    issues: Sequence[IssueItem],
    output_dir: Path | None = None
) -> Path:
    """
    Genera una propuesta de parche en un archivo Artifact Markdown (.md) sin modificar el código fuente original.

    Args:
        target_file: Archivo analizado.
        issues: Incidencias encontradas.
        output_dir: Directorio de salida para guardar la recomendación.

    Returns:
        Ruta del archivo Artifact creado.
    """
    if output_dir is None:
        out_dir = Path.cwd() / ".specify" / "artifacts"
    else:
        out_dir = output_dir

    out_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = out_dir / f"patch_{target_file.stem}.md"

    content_lines: list[str] = [
        f"# Propuesta de Parche de Calidad: `{target_file.name}`",
        "",
        "> [!NOTE]",
        "> Este archivo es una propuesta de corrección sugerida bajo la política **Zero Trust**.",
        "> El código fuente original no ha sido modificado.",
        "",
        "## Incidencias Atendidas",
        "",
    ]

    for issue in issues:
        content_lines.append(f"- **[Línea {issue.line_number}] [{issue.code}]**: {issue.message}")

    content_lines.extend([
        "",
        "## Sugerencia de Cambios Requeridos",
        "",
        "```diff",
        f"--- {target_file.name}",
        f"+++ {target_file.name} (Propuesta Sentinel)",
        "@@ Resumen de Mejoras @@",
        "+ # Asegurar anotaciones de tipo y codificación utf-8 explícita",
        "```",
        "",
        "---",
        "*Generado automáticamente por Antigravity Sentinel.*",
    ])

    artifact_path.write_text("\n".join(content_lines), encoding="utf-8")
    return artifact_path
