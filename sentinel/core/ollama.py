"""
Conector opcional para IA Local (Ollama) con extracción de contexto enriquecido (Zero Trust / 100% Offline).
"""

import json
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from sentinel.config import OLLAMA_DEFAULT_HOST, OLLAMA_DEFAULT_MODEL
from sentinel.core.analyzer import IssueItem


@dataclass(frozen=True)
class OllamaExplanationResult:
    """Resultado del análisis explicativo local generado por Ollama."""
    success: bool
    explanation: str
    model_used: str


class OllamaClient:
    """Cliente HTTP liviano para interactuar con instancias locales de Ollama en localhost:11434."""

    def __init__(self, host: str = OLLAMA_DEFAULT_HOST, model: str = OLLAMA_DEFAULT_MODEL) -> None:
        self.host = host.rstrip("/")
        self.model = model

    def _extract_surrounding_context(self, file_path: str, line_number: int, context_lines: int = 5) -> str:
        """Extrae el bloque de código circundante (+/- context_lines) alrededor de la línea con incidencia."""
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return ""

        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            start = max(0, line_number - context_lines - 1)
            end = min(len(lines), line_number + context_lines)

            context_snippet = []
            for idx in range(start, end):
                current_line = idx + 1
                prefix = "->" if current_line == line_number else "  "
                context_snippet.append(f"{prefix} {current_line:4d} | {lines[idx]}")

            return "\n".join(context_snippet)
        except Exception:
            return ""

    def explain_issues(self, file_path: str, issues: list[IssueItem]) -> OllamaExplanationResult:
        """
        Envía un resumen enriquecido con el contexto circundante de las incidencias a Ollama local
        para obtener una explicación técnica y contextual precisa.

        Args:
            file_path: Ruta del archivo auditado.
            issues: Lista de incidencias detectadas.

        Returns:
            Objeto OllamaExplanationResult con la respuesta o mensaje de falla resiliente.
        """
        if not issues:
            return OllamaExplanationResult(
                success=True,
                explanation="No se encontraron incidencias que requieran explicación local.",
                model_used=self.model,
            )

        prompt_lines: list[str] = [
            f"Actúa como un arquitecto senior de seguridad AppSec. Revisa estas {len(issues)} incidencias detectadas en {file_path} y su contexto circundante. Provee una explicación detallada en español sobre el riesgo y cómo refactorizar el código de forma segura:",
            "",
        ]

        for issue in issues:
            prompt_lines.append(f"### Incidencia Línea {issue.line_number} [{issue.code}] ({issue.severity}): {issue.message}")
            snippet = self._extract_surrounding_context(issue.file_path, issue.line_number)
            if snippet:
                prompt_lines.extend([
                    "Contexto del Código:",
                    "```",
                    snippet,
                    "```",
                ])
            prompt_lines.append("")

        prompt = "\n".join(prompt_lines)
        url = f"{self.host}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }

        try:
            req_data = json.dumps(payload).encode("utf-8")
            request = urllib.request.Request(
                url,
                data=req_data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            # Timeout corto de 5 segundos para evitar bloqueos
            with urllib.request.urlopen(request, timeout=5) as response:
                if response.status == 200:
                    resp_body = response.read().decode("utf-8")
                    data = json.loads(resp_body)
                    explanation_text = str(data.get("response", "Sin respuesta de Ollama."))
                    return OllamaExplanationResult(
                        success=True,
                        explanation=explanation_text,
                        model_used=self.model,
                    )
        except urllib.error.URLError as err:
            return OllamaExplanationResult(
                success=False,
                explanation=f"No se pudo conectar a la IA local Ollama en {self.host}. Verifica que Ollama esté en ejecución. (Detalle: {str(err.reason)})",
                model_used=self.model,
            )
        except Exception as exc:
            return OllamaExplanationResult(
                success=False,
                explanation=f"Error al comunicar con la IA local Ollama: {str(exc)}",
                model_used=self.model,
            )

        return OllamaExplanationResult(
            success=False,
            explanation="Respuesta inesperada del servidor local Ollama.",
            model_used=self.model,
        )
