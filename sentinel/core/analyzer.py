"""
Motor de análisis estático basado en AST (Abstract Syntax Tree) para Python 3.11+.
"""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class IssueItem:
    """Representa una incidencia de calidad o seguridad detectada."""
    file_path: str
    line_number: int
    severity: str  # "ALTA", "MEDIA", "BAJA"
    code: str      # p.ej. "SEC001", "TYP001"
    message: str


class ASTQualityVisitor(ast.NodeVisitor):
    """Recorre el árbol AST recolectando advertencias de tipado y seguridad defensiva."""

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
        """Inspecciona llamadas a funciones en busca de usos inseguros como eval() o exec()."""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ("eval", "exec"):
                self.issues.append(
                    IssueItem(
                        file_path=self.file_path,
                        line_number=node.lineno,
                        severity="ALTA",
                        code="SEC001",
                        message=f"Uso inseguro detectado: Llamada a la función integrada '{func_name}'.",
                    )
                )
            elif func_name == "open":
                # Verifica si se especifica la codificación encoding="utf-8"
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
    Analiza un archivo de código Python de forma estática leyendo su árbol AST.

    Args:
        file_path: Ruta del archivo .py a analizar.

    Returns:
        Secuencia de incidencias detectadas.
    """
    if not file_path.exists() or file_path.suffix != ".py":
        return []

    try:
        source_code = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source_code, filename=str(file_path))
        visitor = ASTQualityVisitor(file_path=str(file_path))
        visitor.visit(tree)
        return visitor.issues
    except Exception as exc:
        return [
            IssueItem(
                file_path=str(file_path),
                line_number=1,
                severity="ALTA",
                code="ERR001",
                message=f"Error al analizar sintaxis del archivo: {str(exc)}",
            )
        ]
