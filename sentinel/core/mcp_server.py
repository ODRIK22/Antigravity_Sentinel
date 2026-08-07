"""
Servidor MCP Nativo (Model Context Protocol) JSON-RPC 2.0 sobre stdin/stdout para Antigravity Sentinel.
"""

import json
import sys
from pathlib import Path
from typing import Any
from sentinel.config import APP_NAME, VERSION
from sentinel.core.analyzer import analyze_file
from sentinel.core.sca import analyze_dependencies
from sentinel.core.ollama import OllamaClient


class SentinelMCPServer:
    """Servidor MCP que expone las herramientas de auditoría de Sentinel a asistentes IDE y agentes."""

    def __init__(self) -> None:
        self.tools = [
            {
                "name": "sentinel_scan",
                "description": "Ejecuta un escaneo estático de calidad y seguridad en un archivo de código.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Ruta del archivo a analizar"}
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "sentinel_sca",
                "description": "Analiza dependencias en requirements.txt o package.json.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Ruta del manifiesto de dependencias"}
                    },
                    "required": ["path"]
                }
            },
            {
                "name": "sentinel_explain",
                "description": "Obtiene explicaciones contextuales de seguridad usando IA local (Ollama).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Ruta del archivo analizado"}
                    },
                    "required": ["path"]
                }
            }
        ]

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Procesa solicitudes JSON-RPC 2.0."""
        msg_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": APP_NAME, "version": VERSION}
                }
            }
        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": self.tools}
            }
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            file_path = Path(str(arguments.get("path", "")))

            if tool_name == "sentinel_scan":
                issues = analyze_file(file_path) if file_path.exists() else []
                res_data = [
                    {"linea": i.line_number, "codigo": i.code, "gravedad": i.severity, "mensaje": i.message}
                    for i in issues
                ]
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(res_data, ensure_ascii=False)}]}
                }
            elif tool_name == "sentinel_sca":
                issues = analyze_dependencies(file_path) if file_path.exists() else []
                res_data = [
                    {"linea": i.line_number, "codigo": i.code, "gravedad": i.severity, "mensaje": i.message}
                    for i in issues
                ]
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(res_data, ensure_ascii=False)}]}
                }
            elif tool_name == "sentinel_explain":
                issues = analyze_file(file_path) if file_path.exists() else []
                client = OllamaClient()
                result = client.explain_issues(str(file_path), list(issues))
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": result.explanation}]}
                }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Método no encontrado: {method}"}
        }

    def start_stdio_loop(self) -> None:
        """Inicia el bucle de servidor JSON-RPC 2.0 sobre stdin/stdout."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
                response = self.handle_request(request)
                if response:
                    sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
                    sys.stdout.flush()
            except Exception as exc:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Error de parseo JSON: {str(exc)}"}
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
