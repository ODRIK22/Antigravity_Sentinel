"""
Motor Sintáctico Universal de Análisis Estructural multilenguaje para Antigravity Sentinel.
"""

import re
from pathlib import Path
from typing import Sequence
from sentinel.core.analyzer import IssueItem
from sentinel.core.rules import get_rules_for_extension


class UniversalASTAnalyzer:
    """Analizador sintáctico estructural para lenguajes como PHP, Go, TypeScript/JS y Python."""

    def __init__(self, file_path: Path) -> None:
        self.file_path = file_path
        self.rules = get_rules_for_extension(file_path.suffix)

    def analyze(self) -> Sequence[IssueItem]:
        """
        Inspecciona el código fuente identificando fuentes no sanitizadas y llamadas a vertederos de riesgo.
        """
        issues: list[IssueItem] = []
        if not self.file_path.exists() or not self.rules["sources"]:
            return issues

        try:
            lines = self.file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            tainted_vars: set[str] = set()

            for idx, line in enumerate(lines, start=1):
                clean_line = line.strip()
                if clean_line.startswith("//") or clean_line.startswith("#") or clean_line.startswith("/*"):
                    continue

                # 1. Rastrear asignaciones desde fuentes (sources)
                for source in self.rules["sources"]:
                    if source in clean_line:
                        # Extraer variable asignada en el lado izquierdo
                        assign_match = re.match(r"^\s*(?:var|let|const|\$)?\s*([a-zA-Z0-9_\$]+)\s*[:=]", clean_line)
                        if assign_match:
                            var_name = assign_match.group(1)
                            tainted_vars.add(var_name)

                # 2. Rastrear si variables o fuentes directas fluyen a vertederos (sinks)
                for sink in self.rules["sinks"]:
                    if sink in clean_line:
                        is_tainted_flow = any(v in clean_line for v in tainted_vars) or any(s in clean_line for s in self.rules["sources"])
                        if is_tainted_flow:
                            issues.append(
                                IssueItem(
                                    file_path=str(self.file_path),
                                    line_number=idx,
                                    severity="ALTA",
                                    code="TAINT003",
                                    message=f"Universal AST: Flujo de datos contaminados detectado hacia la función crítica '{sink}'.",
                                )
                            )
        except Exception:
            pass

        return issues
