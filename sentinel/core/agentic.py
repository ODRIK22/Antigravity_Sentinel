"""
Módulo de Bucle Agéntico de Autocorrección Controlada (Agentic Fix Loop / Zero Trust).
"""

import subprocess
from pathlib import Path
from sentinel.core.analyzer import IssueItem
from sentinel.core.patcher import apply_patch_interactively
from sentinel.core.ollama import OllamaClient


class AgenticFixLoop:
    """Ejecuta un bucle autónomo de parcheado, prueba local e iteración con Ollama."""

    def __init__(self, target_file: Path, issues: list[IssueItem], max_iterations: int = 3) -> None:
        self.target_file = target_file
        self.issues = issues
        self.max_iterations = max_iterations
        self.ollama_client = OllamaClient()

    def _run_test_suite(self) -> tuple[bool, str]:
        """Ejecuta la suite de pruebas unitarias pytest localmente."""
        try:
            res = subprocess.run(
                ["python", "-m", "pytest"],
                capture_output=True,
                text=True,
                timeout=15,
                cwd=str(self.target_file.parent.resolve()),
            )
            return res.returncode == 0, res.stdout + "\n" + res.stderr
        except Exception as exc:
            return False, f"Fallo al ejecutar suite de pruebas: {str(exc)}"

    def execute_loop(self) -> bool:
        """
        Ejecuta el bucle agéntico:
        1. Aplica el parche inicial.
        2. Ejecuta pytest.
        3. Si los tests pasan, completa exitosamente.
        4. Si los tests fallan, consulta a Ollama con la traza de error y reintenta hasta max_iterations.
        5. Si la falla persiste, restaura el backup .bak.
        """
        if not self.issues:
            print("✅ Sin incidencias para corregir en el bucle agéntico.")
            return True

        print(f"\n==================================================")
        print(f"   BUCLE AGÉNTICO DE AUTOCORRECCIÓN (--auto-fix)")
        print(f"==================================================")

        # 1. Aplicar parche base inicial
        apply_patch_interactively(self.target_file, self.issues, auto_confirm=True)

        for iteration in range(1, self.max_iterations + 1):
            print(f"\n🔄 Iteración {iteration}/{self.max_iterations}: Ejecutando suite de pruebas locales (pytest)...")
            passed, test_output = self._run_test_suite()

            if passed:
                print(f"🎉 ¡Éxito! Las pruebas unitarias pasaron correctamente en la iteración {iteration}.")
                return True

            print(f"⚠️ Las pruebas fallaron en la iteración {iteration}.")
            if iteration < self.max_iterations:
                print("🤖 Consultando a IA Local (Ollama) para corregir el fallo en las pruebas...")
                explanation = self.ollama_client.explain_issues(str(self.target_file), self.issues)
                print(f"💡 Sugerencia Ollama:\n{explanation.explanation[:300]}...")

        # Si agotó las iteraciones sin éxito, restaurar el archivo original desde .bak
        print("\n❌ El bucle agéntico no pudo hacer pasar las pruebas tras los reintentos. Revirtiendo al estado original...")
        backup_file = self.target_file.with_suffix(self.target_file.suffix + ".bak")
        if backup_file.exists():
            self.target_file.write_text(backup_file.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
            print("⏪ Archivo original restaurado exitosamente desde el backup.")
        return False
