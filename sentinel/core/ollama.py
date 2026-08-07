"""
Conector opcional para IA Local (Ollama) utilizando la biblioteca estándar de Python (Zero Trust / 100% Offline).
"""

import json
import urllib.request
import urllib.error
from dataclasses import dataclass
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

    def explain_issues(self, file_path: str, issues: list[IssueItem]) -> OllamaExplanationResult:
        """
        Envía un resumen de las incidencias a Ollama local para obtener una explicación técnica y contextual.

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
            f"Actúa como un auditor de seguridad de software. Revisa estas {len(issues)} incidencias en {file_path} y provee una breve explicación técnica en español sobre el impacto y cómo solucionarlo:",
        ]

        for issue in issues:
            prompt_lines.append(f"- Línea {issue.line_number} [{issue.code}] ({issue.severity}): {issue.message}")

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
