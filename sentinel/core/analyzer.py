"""
Motor de análisis estático híbrido (AST de Python + Universal AST Multi-lenguaje + SRI HTML + NoSQL Injection) para Antigravity Sentinel.
"""

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from sentinel.config import SUPPORTED_EXTENSIONS
from sentinel.core.rules import get_rules_for_extension


@dataclass(frozen=True)
class IssueItem:
    """Representa una incidencia de calidad o seguridad detectada."""
    file_path: str
    line_number: int
    severity: str  # "ALTA", "MEDIA", "BAJA"
    code: str      # p.ej. "SEC001", "SEC002", "SEC005", "SEC006", "TAINT001", "TAINT003", "TYP001"
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
    # SEC006: Inyección NoSQL (Uso peligroso del operador $where en MongoDB)
    RegexSecurityPattern(
        code="SEC006",
        severity="ALTA",
        pattern=re.compile(r"[\{\s,]\$where\s*:", re.IGNORECASE),
        message="Riesgo de Inyección NoSQL detectado por el uso del operador $where en consultas a MongoDB.",
    ),
)

INPUT_SOURCES: set[str] = {"req.body", "req.query", "req.params", "input_data", "user_input", "sys.argv", "input"}
CRITICAL_SINKS: set[str] = {"eval", "exec", "system", "os.system", "subprocess.call", "query.find", "execute"}


class ASTQualityVisitor(ast.NodeVisitor):
    """Recorre el árbol AST de Python ejecutando Taint Analysis ligero e inspección de calidad."""

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.issues: list[IssueItem] = []
        self.tainted_vars: set[str] = set()

    def visit_Assign(self, node: ast.Assign) -> None:
        """Rastrear si una variable recibe datos desde una fuente de entrada de usuario (Source)."""
        value_str = ""
        if isinstance(node.value, ast.Name):
            value_str = node.value.id
        elif isinstance(node.value, ast.Attribute):
            value_str = f"{node.value.value.id if isinstance(node.value.value, ast.Name) else ''}.{node.value.attr}"
        elif isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
            value_str = node.value.func.id

        is_tainted_source = any(source in value_str for source in INPUT_SOURCES) or value_str in self.tainted_vars

        if is_tainted_source:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Verifica que las funciones posean anotaciones de retorno y parámetros, e inspecciona Taint en argumentos."""
        for arg in node.args.args:
            if arg.arg in ("user_input", "input_data", "payload", "raw_data"):
                self.tainted_vars.add(arg.arg)

            if arg.annotation is None and arg.arg not in ("self", "cls"):
                self.issues.append(
                    IssueItem(
                        file_path=self.file_path,
                        line_number=node.lineno,
                        severity="MEDIA",
                        code="TYP002",
                        message=f"El argumento '{arg.arg}' en la función '{node.name}' carece de anotación de tipo.",
                    )
                )

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

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Inspecciona si una variable contaminada (tainted) fluye hacia un Sink crítico."""
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in CRITICAL_SINKS or any(sink in func_name for sink in ("eval", "exec", "system")):
            for arg in node.args:
                arg_name = ""
                if isinstance(arg, ast.Name):
                    arg_name = arg.id
                elif isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
                    arg_name = arg.value.id

                if arg_name in self.tainted_vars:
                    self.issues.append(
                        IssueItem(
                            file_path=self.file_path,
                            line_number=node.lineno,
                            severity="ALTA",
                            code="TAINT001",
                            message=f"Taint Analysis: Variable no sanitizada '{arg_name}' fluye desde la entrada hasta la función crítica '{func_name}'.",
                        )
                    )

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


def _strip_comments(line: str) -> str:
    """Elimina comentarios de una línea de código para evitar falsos positivos."""
    stripped = line.strip()
    if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
        return ""
    if "#" in line:
        line = line.split("#")[0]
    elif "//" in line and not ("http://" in line or "https://" in line):
        line = line.split("//")[0]
    return line


def analyze_file(file_path: Path) -> Sequence[IssueItem]:
    """
    Analiza de forma estática cualquier archivo de código fuente soportado ejecutando Taint Analysis y filtrado de comentarios.

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

    # 1. Análisis por Reglas de Patrones con Filtrado de Comentarios
    for line_idx, raw_line in enumerate(lines, start=1):
        clean_line = _strip_comments(raw_line)
        if not clean_line.strip():
            continue

        for rule in SECURITY_PATTERNS:
            if rule.pattern.search(clean_line):
                issues.append(
                    IssueItem(
                        file_path=str(file_path),
                        line_number=line_idx,
                        severity=rule.severity,
                        code=rule.code,
                        message=rule.message,
                    )
                )

    # 2. Análisis por AST Universal (PHP, Go, JS/TS, Python)
    from sentinel.core.universal_ast import UniversalASTAnalyzer
    universal_ast = UniversalASTAnalyzer(file_path)
    issues.extend(universal_ast.analyze())

    # 3. Taint Analysis y AST Avanzado específico para archivos Python
    if file_path.suffix == ".py":
        try:
            tree = ast.parse(source_code, filename=str(file_path))
            visitor = ASTQualityVisitor(file_path=str(file_path))
            visitor.visit(tree)
            issues.extend(visitor.issues)
        except Exception:
            pass

    return issues
