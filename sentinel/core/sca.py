"""
Módulo de Análisis de Componentes de Software (SCA - Software Composition Analysis) para Antigravity Sentinel.
"""

import json
import re
from pathlib import Path
from typing import Sequence
from sentinel.core.analyzer import IssueItem

# Catálogo liviano de patrones de vulnerabilidades conocidas y versiones obsoletas
VULNERABLE_PACKAGES: dict[str, tuple[str, str, str]] = {
    # Nombre del paquete: (Versión insegura regex / condición, Severidad, Mensaje de recomendación)
    "requests": (r"^(?:[0-1]\.|2\.(?:[0-9]|1[0-9]|2[0-9]|30)\.)", "ALTA", "Vulnerabilidad SCA: 'requests' versión < 2.31.0 es susceptible a fugas de cabeceras de autenticación."),
    "urllib3": (r"^(?:0\.|1\.(?:[0-9]|1[0-9]|2[0-5])\.)", "MEDIA", "Vulnerabilidad SCA: 'urllib3' versión < 1.26.5 tiene problemas de seguridad conocidos."),
    "flask": (r"^(?:[0-1]\.|2\.[0-2]\.)", "MEDIA", "Vulnerabilidad SCA: 'flask' versión < 2.3.0 debe actualizarse a la rama principal segura."),
    "django": (r"^(?:[0-2]\.|3\.|4\.[0-1]\.)", "ALTA", "Vulnerabilidad SCA: 'django' versión < 4.2.0 posee vulnerabilidades críticas conocidas."),
    "express": (r"^(?:[0-3]\.|4\.(?:[0-9]|1[0-8])\.)", "ALTA", "Vulnerabilidad SCA: 'express' versión < 4.19.2 es vulnerable a la inyección de respuesta HTTP."),
    "lodash": (r"^(?:[0-3]\.|4\.(?:[0-9]|1[0-6])\.)", "ALTA", "Vulnerabilidad SCA: 'lodash' versión < 4.17.21 posee vulnerabilidad de Prototype Pollution."),
    "axios": (r"^(?:0\.|1\.[0-5]\.)", "MEDIA", "Vulnerabilidad SCA: 'axios' versión < 1.6.0 es vulnerable a Server-Side Request Forgery (SSRF)."),
}


def analyze_requirements_txt(file_path: Path) -> list[IssueItem]:
    """Analiza archivos requirements.txt en busca de librerías vulnerables o sin fijación de versión."""
    issues: list[IssueItem] = []
    if not file_path.exists() or not file_path.is_file():
        return issues

    try:
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        for idx, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Extracción simple de paquete y versión (p.ej. requests==2.25.1)
            match = re.match(r"^([a-zA-Z0-9_\-]+)\s*(?:==|<=|<|>=|>)?\s*([0-9\.]+)?", line)
            if match:
                pkg_name = match.group(1).lower()
                pkg_ver = match.group(2) or ""

                if pkg_name in VULNERABLE_PACKAGES:
                    pattern, severity, msg = VULNERABLE_PACKAGES[pkg_name]
                    if pkg_ver and re.search(pattern, pkg_ver):
                        issues.append(
                            IssueItem(
                                file_path=str(file_path),
                                line_number=idx,
                                severity=severity,
                                code="SCA001",
                                message=f"{msg} (Versión detectada: {pkg_ver})",
                            )
                        )
                    elif not pkg_ver:
                        issues.append(
                            IssueItem(
                                file_path=str(file_path),
                                line_number=idx,
                                severity="BAJA",
                                code="SCA002",
                                message=f"Falta fijación de versión estricta (pinning) para la dependencia '{pkg_name}'.",
                            )
                        )
    except Exception as exc:
        issues.append(
            IssueItem(
                file_path=str(file_path),
                line_number=1,
                severity="MEDIA",
                code="ERR002",
                message=f"Error al analizar requirements.txt: {str(exc)}",
            )
        )

    return issues


def analyze_package_json(file_path: Path) -> list[IssueItem]:
    """Analiza archivos package.json de Node.js en busca de librerías vulnerables."""
    issues: list[IssueItem] = []
    if not file_path.exists() or not file_path.is_file():
        return issues

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))

        for pkg_name, ver_str in deps.items():
            pkg_clean = pkg_name.lower()
            clean_ver = re.sub(r"[^0-9\.]", "", ver_str)

            if pkg_clean in VULNERABLE_PACKAGES:
                pattern, severity, msg = VULNERABLE_PACKAGES[pkg_clean]
                if clean_ver and re.search(pattern, clean_ver):
                    issues.append(
                        IssueItem(
                            file_path=str(file_path),
                            line_number=1,
                            severity=severity,
                            code="SCA001",
                            message=f"{msg} (Versión en package.json: {ver_str})",
                        )
                    )
    except Exception as exc:
        issues.append(
            IssueItem(
                file_path=str(file_path),
                line_number=1,
                severity="MEDIA",
                code="ERR002",
                message=f"Error al analizar package.json: {str(exc)}",
            )
        )

    return issues


def analyze_dependencies(file_path: Path) -> Sequence[IssueItem]:
    """
    Función principal de análisis SCA para evaluar archivos de manifiesto de dependencias.
    """
    if file_path.name == "requirements.txt":
        return analyze_requirements_txt(file_path)
    elif file_path.name == "package.json":
        return analyze_package_json(file_path)
    return []
