"""
Interfaz de Línea de Comandos (CLI) para Antigravity Sentinel.
"""

import argparse
import sys
from pathlib import Path

from sentinel.config import APP_NAME, VERSION, SUPPORTED_EXTENSIONS, IGNORE_DIRS
from sentinel.core.sanitizer import sanitize_path, SentinelSanitizerError
from sentinel.core.analyzer import analyze_file, IssueItem
from sentinel.core.reporter import format_console_report, format_json_report
from sentinel.core.patcher import generate_patch_artifact
from sentinel.core.ollama import OllamaClient


def main() -> None:
    """Punto de entrada de la CLI."""
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description=f"{APP_NAME} v{VERSION} - Módulo Multilenguaje de Aseguramiento de Calidad y Análisis Estático Defensivo con IA Local Opcional.",
    )

    subparsers = parser.add_subparsers(dest="command", help="Subcomandos disponibles")

    # Subcomando scan
    scan_parser = subparsers.add_parser("scan", help="Escanea un archivo o directorio en busca de problemas de calidad y seguridad.")
    scan_parser.add_argument("--path", required=True, type=str, help="Ruta del directorio o archivo a analizar.")
    scan_parser.add_argument("--format", choices=["console", "json"], default="console", help="Formato de salida del reporte.")
    scan_parser.add_argument("--explain-local", action="store_true", help="Solicita una explicación contextual offline usando IA local (Ollama).")

    # Subcomando patch
    patch_parser = subparsers.add_parser("patch", help="Genera una propuesta de parche con plantillas semánticas (Artifact) para un archivo.")
    patch_parser.add_argument("--file", required=True, type=str, help="Ruta del archivo a inspeccionar.")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == "scan":
            target = sanitize_path(args.path)
            all_issues: list[IssueItem] = []

            if target.is_file():
                all_issues.extend(analyze_file(target))
            elif target.is_dir():
                for item in target.rglob("*"):
                    if any(ignored in item.parts for ignored in IGNORE_DIRS):
                        continue
                    if item.is_file() and (item.suffix in SUPPORTED_EXTENSIONS or item.name == ".env"):
                        all_issues.extend(analyze_file(item))

            if args.format == "json":
                print(format_json_report(all_issues))
            else:
                print(format_console_report(all_issues))

            if args.explain_local:
                print("\n🤖 Solicitando explicación contextual a IA Local (Ollama localhost:11434)...")
                client = OllamaClient()
                result = client.explain_issues(str(target), all_issues)
                print(f"--- Explicación Local ({result.model_used}) ---\n{result.explanation}")

        elif args.command == "patch":
            target_file = sanitize_path(args.file)
            if not target_file.is_file():
                print(f"Error: El archivo '{args.file}' no existe o no es un archivo válido.", file=sys.stderr)
                sys.exit(1)

            issues = analyze_file(target_file)
            artifact = generate_patch_artifact(target_file, issues)
            print(f"✅ Propuesta de parche (Artifact Zero Trust con remediación semántica) creada exitosamente en:\n  {artifact}")

    except SentinelSanitizerError as err:
        print(f"❌ Error de Seguridad/Sanitización: {str(err)}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"❌ Fallo no controlado: {str(exc)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
