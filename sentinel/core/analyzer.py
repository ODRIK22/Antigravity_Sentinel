"""
Motor de análisis estático híbrido (AST de Python + Motor Regex Multilenguaje + SRI HTML) para Antigravity Sentinel.
"""

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from sentinel.config import SUPPORTED_EXTENSIONS


@dataclass(frozen=True)
class IssueItem:
    """Representa una incidencia de calidad o seguridad detectada."""
    file_path: str
    line_number: int
    severity: str  # "ALTA", "MEDIA", "BAJA"
    code: str      # p.ej. "SEC001", "SEC002", "SEC005", "TYP001"
    message: str


@dataclass(frozen=True)
class RegexSecurityPattern:
    """Representa una regla de coincidencia basada en expresiones regulares."""
    code: str
    severity: str
    pattern: re.Pattern[str]
    message: str


# Reglas de patrones de seguridad multilenguaje
SECURITY_PATTERNS: tuple[RegexSecurityPattern, ...] = (
    # SEC002: Credenciales, tokens y llaves privadas expuestas
    RegexSecurityPattern(
        code="SEC002",
        severity="ALTA",
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        message="Detección de Access Key ID de AWS expuesta en texto plano.",
    ),
    RegexSecurityPattern(
        code="SEC002",
        severity="ALTA",
        pattern=re.compile(r"ghp_[a-zA-Z0-9]{36}"),
        message="Detección de Token de Acceso Personal de GitHub expuesto.",
    ),
    RegexSecurityPattern(
        code="SEC002",
        severity="ALTA",
        pattern=re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
        message="Detección de Llave Privada expuesta en el código.",
    ),
    RegexSecurityPattern(
        code="SEC002",
        severity="ALTA",
        pattern=re.compile(r"(?:api[_-]?key|secret[_-]?key|password|passwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]", re.IGNORECASE),
        message="Asignación directa de credenciales o clave secreta en texto plano.",
    ),
    # SEC003: Funciones de ejecución peligrosa multilenguaje
    RegexSecurityPattern(
        code="SEC003",
        severity="ALTA",
        pattern=re.compile(r"\b(?:eval|exec)\s*\("),
        message="Uso de función de ejecución dinámica peligrosa (eval/exec).",
    ),
    RegexSecurityPattern(
        code="SEC003",
        severity="MEDIA",
        pattern=re.compile(r"\.innerHTML\s*="),
        message="Asignación directa a innerHTML (Riesgo potencial de Cross-Site Scripting XSS).",
    ),
    RegexSecurityPattern(
        code="SEC003",
        severity="ALTA",
        pattern=re.compile(r"\b(?:shell_exec|passthru|system)\s*\("),
        message="Llamada a función de ejecución de comandos del sistema operativo.",
    ),
    # SEC004: Cadenas de base de datos sin encriptar o con credenciales expuestas
    RegexSecurityPattern(
        code="SEC004",
        severity="ALTA",
        pattern=re.compile(r"(?:mongodb|postgres|postgresql|mysql)://[^:]+:[^@]+@"),
        message="Cadena de conexión a base de datos con credenciales expuestas en texto plano.",
    ),
    # SEC005: Enlaces a CDNs externas en HTML sin atributo Subresource Integrity (SRI)
    RegexSecurityPattern(
        code="SEC005",
        severity="MEDIA",
        pattern=re.compile(r"<(?:script\s+[^>]*src|link\s+[^>]*href)=['\"]https?://[^'\"]+['\"](?![^>]*\bintegrity=)[^>]*>", re.IGNORECASE),
        message="Inclusión de recurso CDN externo en HTML sin el atributo de seguridad Subresource Integrity (SRI).",
    ),
)


class ASTQualityVisitor(ast.NodeVisitor):
    """Recorre el árbol AST de Python recolectando advertencias de tipado y seguridad defensiva."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.issues: list[IssueItem] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Verifica que las funciones posean anotación de retorno y tipos en argumentos."""
        if node.returns is None and node.name != "__init__":
            self.issues.append(
                IssueItem(
                    file_path=self.file_path,
                    line_number=node.lineno,
                    severity="MEDIA",
                    code="TYP001",
                    message=f"La función '{node.name}' no especifica anotación de tipo de retorno.",
                )
            )

        for arg in node.args.args:
            if arg.annotation is None and arg.arg != "self" and arg.arg != "cls":
                self.issues.append(
                    IssueItem(
                        file_path=self.file_path,
                        line_number=node.lineno,
                        severity="MEDIA",
                        code="TYP002",
                        message=f"El argumento '{arg.arg}' en la función '{node.name}' carece de anotación de tipo.",
                    )
                )

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Inspecciona llamadas a funciones en busca de usos como open() sin encoding."""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name == "open":
                has_encoding = any(kw.arg == "encoding" for kw in node.keywords)
                if not has_encoding:
                    self.issues.append(
                        IssueItem(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            severity="BAJA",
                            code="IO001",
                            message="Llamada a 'open()' sin especificar explícitamente el parámetro 'encoding'.",
                        )
                    )

        self.generic_visit(node)


def analyze_file(file_path: Path) -> Sequence[IssueItem]:
    """
    Analiza de forma estática cualquier archivo de código fuente soportado (Python, JS, TS, PHP, HTML, JSON, .env, etc.).

    Args:
        file_path: Ruta del archivo a analizar.

    Returns:
        Secuencia de incidencias detectadas.
    """
    if not file_path.exists() or (file_path.suffix not in SUPPORTED_EXTENSIONS and file_path.name != ".env"):
        return []

    issues: list[IssueItem] = []

    try:
        source_code = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        return [
            IssueItem(
                file_path=str(file_path),
                line_number=1,
                severity="ALTA",
                code="ERR001",
                message=f"Error al leer el archivo: {str(exc)}",
            )
        ]

    lines = source_code.splitlines()

    # 1. Análisis por Reglas de Patrones (Regex Multilenguaje)
    for line_idx, line in enumerate(lines, start=1):
        for rule in SECURITY_PATTERNS:
            if rule.pattern.search(line):
                issues.append(
                    IssueItem(
                        file_path=str(file_path),
                        line_number=line_idx,
                        severity=rule.severity,
                        code=rule.code,
                        message=rule.message,
                    )
                )

    # 2. Análisis sintáctico preciso AST (exclusivo para archivos Python)
    if file_path.suffix == ".py":
        try:
            tree = ast.parse(source_code, filename=str(file_path))
            visitor = ASTQualityVisitor(file_path=str(file_path))
            visitor.visit(tree)
            issues.extend(visitor.issues)
        except Exception:
            pass

    return issues
