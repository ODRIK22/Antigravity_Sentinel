"""
Módulo de generación de reportes estructurados para consola y JSON.
"""

import json
from typing import Sequence
from sentinel.core.analyzer import IssueItem


def format_console_report(issues: Sequence[IssueItem]) -> str:
    """
    Genera un reporte legible en consola para el usuario en español.
    """
    if not issues:
        return "✅ Escaneo completado: No se detectaron problemas de calidad ni violaciones de tipos."

    lines: list[str] = [
        "==================================================",
        "          REPORTE DE ANTIGRAVITY SENTINEL         ",
        "==================================================",
        f"Total de incidencias encontradas: {len(issues)}\n",
    ]

    for item in issues:
        lines.append(
            f"[{item.severity}] [{item.code}] {item.file_path}:{item.line_number}\n  ↳ {item.message}"
        )

    lines.append("\n==================================================")
    return "\n".join(lines)


def format_json_report(issues: Sequence[IssueItem]) -> str:
    """
    Genera un reporte en formato JSON estructurado.
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
