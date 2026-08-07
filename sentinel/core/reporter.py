"""
Módulo de generación de reportes estructurados para consola (con colores ANSI) y JSON.
"""

import json
from typing import Sequence
from sentinel.config import COLOR_RED, COLOR_YELLOW, COLOR_GREEN, COLOR_BOLD, COLOR_RESET
from sentinel.core.analyzer import IssueItem


def _get_colored_severity(severity: str) -> str:
    """Retorna la etiqueta de severidad formateada con colores ANSI para consola."""
    if severity == "ALTA":
        return f"{COLOR_RED}{COLOR_BOLD}[ALTA]{COLOR_RESET}"
    elif severity == "MEDIA":
        return f"{COLOR_YELLOW}{COLOR_BOLD}[MEDIA]{COLOR_RESET}"
    elif severity == "BAJA":
        return f"{COLOR_GREEN}{COLOR_BOLD}[BAJA]{COLOR_RESET}"
    return f"[{severity}]"


def format_console_report(issues: Sequence[IssueItem]) -> str:
    """
    Genera un reporte legible en consola coloreado con ANSI para el usuario en español.
    """
    if not issues:
        return f"{COLOR_GREEN}{COLOR_BOLD}✅ Escaneo completado: No se detectaron problemas de calidad ni violaciones de seguridad.{COLOR_RESET}"

    lines: list[str] = [
        f"{COLOR_BOLD}=================================================={COLOR_RESET}",
        f"{COLOR_BOLD}          REPORTE DE ANTIGRAVITY SENTINEL         {COLOR_RESET}",
        f"{COLOR_BOLD}=================================================={COLOR_RESET}",
        f"Total de incidencias encontradas: {COLOR_BOLD}{len(issues)}{COLOR_RESET}\n",
    ]

    for item in issues:
        severity_tag = _get_colored_severity(item.severity)
        lines.append(
            f"{severity_tag} [{item.code}] {item.file_path}:{item.line_number}\n  ↳ {item.message}"
        )

    lines.append(f"\n{COLOR_BOLD}=================================================={COLOR_RESET}")
    return "\n".join(lines)


def format_json_report(issues: Sequence[IssueItem]) -> str:
    """
    Genera un reporte en formato JSON estructurado sin códigos de escape ANSI.
    """
    data = [
        {
            "archivo": item.file_path,
            "linea": item.line_number,
            "gravedad": item.severity,
            "codigo": item.code,
            "mensaje": item.message,
        }
        for item in issues
    ]
    return json.dumps({"resumen": {"total_incidencias": len(issues)}, "incidencias": data}, indent=2, ensure_ascii=False)
