"""
Generador de propuestas de parches interactivos con plantillas de remediación semántica (Zero Trust).
"""

from pathlib import Path
from typing import Sequence
from sentinel.core.analyzer import IssueItem

REMEDIATION_TEMPLATES: dict[str, str] = {
    "TYP001": "+ # Añadir tipo de retorno explícito (ejemplo: -> None o -> int)\n+ def funcion(...) -> TipoRetorno:",
    "TYP002": "+ # Especificar tipo en argumento (ejemplo: param: str o param: Dict[str, Any])",
    "SEC001": "- eval(user_input)\n+ # Reemplazar eval por ast.literal_eval() o parseo seguro JSON\n+ import ast\n+ valor_seguro = ast.literal_eval(user_input)",
    "SEC002": "- API_KEY = \"SECRET_KEY_EXPOSED\"\n+ # Usar variables de entorno en lugar de cadenas de texto plano\n+ import os\n+ API_KEY = os.environ.get(\"API_KEY\")",
    "SEC003": "- element.innerHTML = userInput;\n+ // Usar textContent o sanitización DOMPurify para prevenir XSS\n+ element.textContent = userInput;",
    "SEC004": "- db_uri = \"postgres://user:pass@host:5432/db\"\n+ # Extraer credenciales a un archivo .env no público o gestor de secretos\n+ db_uri = os.environ.get(\"DATABASE_URL\")",
    "SEC005": "- <script src=\"https://cdn.example.com/lib.js\"></script>\n+ <!-- Incluir atributo Subresource Integrity (SRI) y crossorigin -->\n+ <script src=\"https://cdn.example.com/lib.js\" integrity=\"sha384-...\" crossorigin=\"anonymous\"></script>",
    "SEC006": "- db.users.find({ $where: \"this.name == '\" + userInput + \"'\" })\n+ // Reemplazar $where por consultas parametrizadas puras de MongoDB\n+ db.users.find({ name: userInput })",
    "TAINT001": "- eval(tainted_input)\n+ # Sanitizar entrada antes de procesar o usar mapeo estricto\n+ sanitized_input = sanitize_text_input(tainted_input)\n+ result = safe_process(sanitized_input)",
    "IO001": "- open(filename, 'r')\n+ open(filename, 'r', encoding='utf-8')",
}


def generate_patch_artifact(
    target_file: Path,
    issues: Sequence[IssueItem],
    output_dir: Path | None = None
) -> Path:
    """
    Genera una propuesta de parche en un archivo Artifact Markdown (.md) utilizando plantillas de remediación semántica contextuales.

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
        f"# Propuesta de Parche de Remediación Semántica: `{target_file.name}`",
        "",
        "> [!NOTE]",
        "> Este archivo contiene plantillas de remediación semántica sugeridas bajo la política **Zero Trust**.",
        "> El código fuente original no ha sido modificado.",
        "",
        "## Incidencias Detectadas y Recomendaciones Semánticas",
        "",
    ]

    for issue in issues:
        content_lines.append(f"### 📍 [Línea {issue.line_number}] [{issue.code}] ({issue.severity})")
        content_lines.append(f"**Mensaje:** {issue.message}")

        template = REMEDIATION_TEMPLATES.get(
            issue.code,
            "+ # Aplicar refactorización limpia y sanitización de entradas según guías OWASP"
        )

        content_lines.extend([
            "",
            "```diff",
            f"--- {target_file.name} (Original)",
            f"+++ {target_file.name} (Remediación Sugerida)",
            template,
            "```",
            "",
        ])

    content_lines.extend([
        "---",
        "*Generado automáticamente por Antigravity Sentinel (v0.5.0).*",
    ])

    artifact_path.write_text("\n".join(content_lines), encoding="utf-8")
    return artifact_path
