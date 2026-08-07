"""
Interfaz de Línea de Comandos (CLI) para Antigravity Sentinel.
"""

import argparse
import sys
from pathlib import Path

from sentinel.config import APP_NAME, VERSION, SUPPORTED_EXTENSIONS
from sentinel.core.sanitizer import sanitize_path, SentinelSanitizerError
from sentinel.core.analyzer import analyze_file, IssueItem
from sentinel.core.reporter import format_console_report, format_json_report, format_sarif_report
from sentinel.core.patcher import generate_patch_artifact, apply_patch_interactively
from sentinel.core.ollama import OllamaClient
from sentinel.core.ignore import SentinelIgnoreManager
from sentinel.core.sca import analyze_dependencies
from sentinel.core.watcher import FileSystemWatcher
from sentinel.core.callgraph import InterproceduralCallGraph
from sentinel.core.agentic import AgenticFixLoop
from sentinel.core.mcp_server import SentinelMCPServer


def main() -> None:
    """Punto de entrada de la CLI."""
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description=f"{APP_NAME} v{VERSION} - Agente de Seguridad e Inteligencia Local (MCP, Agentic Loop, Call Graph).",
    )

    subparsers = parser.add_subparsers(dest="command", help="Subcomandos disponibles")

    # Subcomando scan
    scan_parser = subparsers.add_parser("scan", help="Escanea un archivo o directorio en busca de problemas de calidad y seguridad.")
    scan_parser.add_argument("--path", required=True, type=str, help="Ruta del directorio o archivo a analizar.")
    scan_parser.add_argument("--format", choices=["console", "json", "sarif"], default="console", help="Formato de salida del reporte.")
    scan_parser.add_argument("--explain-local", action="store_true", help="Solicita una explicación contextual offline usando IA local (Ollama).")

    # Subcomando sca
    sca_parser = subparsers.add_parser("sca", help="Escanea dependencias del proyecto (Software Composition Analysis).")
    sca_parser.add_argument("--path", required=True, type=str, help="Ruta del directorio o archivo de manifiesto.")
    sca_parser.add_argument("--format", choices=["console", "json"], default="console", help="Formato de salida del reporte.")

    # Subcomando watch
    watch_parser = subparsers.add_parser("watch", help="Inicia la monitorización en tiempo real del sistema de archivos.")
    watch_parser.add_argument("--path", required=True, type=str, help="Ruta del directorio a monitorizar.")

    # Subcomando patch
    patch_parser = subparsers.add_parser("patch", help="Genera propuestas de parches o aplícalos de forma autónoma o interactiva.")
    patch_parser.add_argument("--file", required=True, type=str, help="Ruta del archivo a inspeccionar.")
    patch_parser.add_argument("--apply-patch", action="store_true", help="Revisa y aplica los cambios de forma interactiva.")
    patch_parser.add_argument("--auto-fix", action="store_true", help="Ejecuta el bucle agéntico autónomo de autocorrección e iteración con tests.")

    # Subcomando mcp
    mcp_parser = subparsers.add_parser("mcp", help="Inicia el Servidor MCP nativo sobre stdin/stdout para integración con IDEs.")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == "scan":
            target = sanitize_path(args.path)
            base_dir = target if target.is_dir() else target.parent
            ignore_mgr = SentinelIgnoreManager(base_dir)
            scan_issues: list[IssueItem] = []

            if target.is_file():
                if not ignore_mgr.is_ignored(target):
                    scan_issues.extend(analyze_file(target))
            elif target.is_dir():
                for item in target.rglob("*"):
                    if ignore_mgr.is_ignored(item):
                        continue
                    if item.is_file() and (item.suffix in SUPPORTED_EXTENSIONS or item.name == ".env"):
                        scan_issues.extend(analyze_file(item))

                # Ejecutar análisis de grafo de llamadas interprocedural
                call_graph = InterproceduralCallGraph(target)
                scan_issues.extend(call_graph.analyze_project())

            if args.format == "json":
                print(format_json_report(scan_issues))
            elif args.format == "sarif":
                print(format_sarif_report(scan_issues))
            else:
                print(format_console_report(scan_issues))

            if args.explain_local:
                print("\n🤖 Solicitando explicación contextual enriquecida a IA Local (Ollama localhost:11434)...")
                client = OllamaClient()
                result = client.explain_issues(str(target), scan_issues)
                print(f"--- Explicación Local ({result.model_used}) ---\n{result.explanation}")

        elif args.command == "sca":
            target = sanitize_path(args.path)
            base_dir = target if target.is_dir() else target.parent
            ignore_mgr = SentinelIgnoreManager(base_dir)
            sca_issues: list[IssueItem] = []

            if target.is_file():
                if not ignore_mgr.is_ignored(target):
                    sca_issues.extend(analyze_dependencies(target))
            elif target.is_dir():
                for item in (target / "requirements.txt", target / "package.json"):
                    if item.exists() and not ignore_mgr.is_ignored(item):
                        sca_issues.extend(analyze_dependencies(item))

            if args.format == "json":
                print(format_json_report(sca_issues))
            else:
                print(format_console_report(sca_issues))

        elif args.command == "watch":
            target = sanitize_path(args.path)
            watcher = FileSystemWatcher(target)
            watcher.start_watch()

        elif args.command == "patch":
            target_file = sanitize_path(args.file)
            if not target_file.is_file():
                print(f"Error: El archivo '{args.file}' no existe o no es un archivo válido.", file=sys.stderr)
                sys.exit(1)

            issues = list(analyze_file(target_file))

            if args.auto_fix:
                agentic_loop = AgenticFixLoop(target_file, issues)
                agentic_loop.execute_loop()
            elif args.apply_patch:
                apply_patch_interactively(target_file, issues)
            else:
                artifact = generate_patch_artifact(target_file, issues)
                print(f"✅ Propuesta de parche creada exitosamente en:\n  {artifact}")

        elif args.command == "mcp":
            mcp_server = SentinelMCPServer()
            mcp_server.start_stdio_loop()

    except SentinelSanitizerError as err:
        print(f"❌ Error de Seguridad/Sanitización: {str(err)}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"❌ Fallo no controlado: {str(exc)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
