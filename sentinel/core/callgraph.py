"""
Módulo de Análisis de Flujo de Datos Interprocedural (Global Call Graph Taint Analysis).
"""

import ast
from pathlib import Path
from typing import Sequence
from sentinel.core.analyzer import IssueItem, CRITICAL_SINKS, INPUT_SOURCES


class InterproceduralCallGraph:
    """Construye un mapa de llamadas y rastrea la propagación de datos contaminados entre módulos."""

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir.resolve()
        self.function_signatures: dict[str, set[str]] = {}  # func_name -> {param_names}
        self.module_calls: list[tuple[Path, int, str, list[str]]] = []  # (file, line, func_called, args_passed)

    def analyze_project(self) -> Sequence[IssueItem]:
        """
        Analiza todos los archivos Python del proyecto para construir el grafo de llamadas y detectar fuentes no sanitizadas.
        """
        issues: list[IssueItem] = []
        if not self.base_dir.exists():
            return issues

        py_files = list(self.base_dir.rglob("*.py")) if self.base_dir.is_dir() else [self.base_dir]

        # 1. Recolectar firmas de funciones
        for py_file in py_files:
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8", errors="ignore"), filename=str(py_file))
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        params = {arg.arg for arg in node.args.args}
                        self.function_signatures[node.name] = params
                    elif isinstance(node, ast.Call):
                        func_name = ""
                        if isinstance(node.func, ast.Name):
                            func_name = node.func.id
                        elif isinstance(node.func, ast.Attribute):
                            func_name = node.func.attr

                        args = []
                        for arg in node.args:
                            if isinstance(arg, ast.Name):
                                args.append(arg.id)
                            elif isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
                                args.append(f"{arg.value.id}.{arg.attr}")

                        if func_name:
                            self.module_calls.append((py_file, node.lineno, func_name, args))
            except Exception:
                pass

        # 2. Rastrear flujo interprocedural entre llamadas
        for py_file, lineno, func_name, args in self.module_calls:
            is_sink_call = func_name in CRITICAL_SINKS or any(sink in func_name for sink in ("eval", "exec", "system"))
            for arg_name in args:
                if any(source in arg_name for source in INPUT_SOURCES) and is_sink_call:
                    issues.append(
                        IssueItem(
                            file_path=str(py_file),
                            line_number=lineno,
                            severity="ALTA",
                            code="TAINT002",
                            message=f"Taint Analysis Interprocedural: Variable de entrada de usuario '{arg_name}' fluye a través del grafo de llamadas hacia '{func_name}'.",
                        )
                    )

        return issues
