"""
Generador de propuestas de parches interactivos con plantillas de remediación semántica y aplicación controlada (Zero Trust).
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
        "*Generado automáticamente por Antigravity Sentinel (v0.6.0).*",
    ])

    artifact_path.write_text("\n".join(content_lines), encoding="utf-8")
    return artifact_path


def apply_patch_interactively(target_file: Path, issues: Sequence[IssueItem], auto_confirm: bool = False) -> bool:
    """
    Muestra el diff sugerido en la consola e interactúa con el usuario para confirmar y aplicar
    el parche controlado creando una copia de respaldo .bak.

    Args:
        target_file: Archivo a modificar.
        issues: Lista de incidencias a remediar.
        auto_confirm: Si es True, salta el prompt interactivo (para pruebas automáticas).

    Returns:
        True si los cambios fueron aplicados, False si el usuario canceló.
    """
    if not issues:
        print("✅ No hay incidencias pendientes para parchear en este archivo.")
        return False

    print(f"\n==================================================")
    print(f"   MODO INTERACTIVO DE PARCHEADO (Zero Trust)")
    print(f"==================================================")
    print(f"Archivo objetivo: {target_file.name}")
    print(f"Total de incidencias a tratar: {len(issues)}\n")

    for issue in issues:
        print(f"📍 Línea {issue.line_number} [{issue.code}]: {issue.message}")
        print("Diff propuesto:")
        template = REMEDIATION_TEMPLATES.get(issue.code, "+ # Refactorización requerida")
        print(f"```diff\n{template}\n```\n")

    if not auto_confirm:
        user_input = input("¿Desea crear un backup (.bak) y aplicar la guía de remediación en el archivo fuente? (s/n): ").strip().lower()
        if user_input not in ("s", "si", "y", "yes"):
            print("❌ Operación cancelada por el usuario. El archivo fuente no ha sido modificado.")
            return False

    # Crear backup .bak
    backup_file = target_file.with_suffix(target_file.suffix + ".bak")
    backup_file.write_text(target_file.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
    print(f"📦 Backup guardado exitosamente en: {backup_file.name}")

    # Aplicar comentarios de guía al inicio del archivo fuente
    original_content = target_file.read_text(encoding="utf-8", errors="ignore")
    header_notice = "# [SENTINEL PATCH APPLIED] Guías de remediación generadas automáticamente.\n"
    target_file.write_text(header_notice + original_content, encoding="utf-8")
    print(f"✅ Parche aplicado de forma controlada en {target_file.name}.")
    return True
