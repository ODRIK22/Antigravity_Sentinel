# Antigravity Sentinel 🛡️

![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Type Checking](https://img.shields.io/badge/mypy-strict-brightgreen.svg)
![Tests Pass](https://img.shields.io/badge/tests-23%20passed-success.svg)
![Protocol](https://img.shields.io/badge/MCP-JSON--RPC%202.0-blue.svg)
![SARIF Standard](https://img.shields.io/badge/SARIF-v2.1.0-purple.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Architecture](https://img.shields.io/badge/architecture-Zero%20Trust%20%7C%20100%25%20Offline-orange.svg)

**Antigravity Sentinel** es un agente autónomo de ciberseguridad defensiva, análisis estático (SAST), **Bucle Agéntico de Autocorrección (`--auto-fix`)**, **Call Graph Taint Analysis**, **Servidor MCP Nativo (Model Context Protocol)** y privacidad 100% offline con IA Local (Ollama).

Diseñado y desarrollado utilizando la metodología **Spec-Kit** dentro de la plataforma Antigravity, Sentinel opera bajo arquitectura Zero Trust y se comunica directamente con IDEs y asistentes mediante MCP.

---

## 🚀 Características Principales

- **Bucle Agéntico de Autocorrección (`sentinel patch --auto-fix`):** Proceso iterativo autónomo que aplica remediaciones sugeridas, ejecuta la suite de pruebas unitarias locales (`pytest`) y, si los tests fallan, retroalimenta a la IA local (Ollama) para reintentar la corrección hasta que el código pase limpio. Revierte automáticamente en caso de fallas persistentes.
- **Análisis de Flujo Interprocedural (Global Call Graph Taint Analysis):** Mapea el grafo de llamadas entre múltiples archivos del proyecto para detectar variables de entrada que cruzan módulos antes de llegar a un Sink crítico (`TAINT002`).
- **Servidor MCP Nativo (`sentinel mcp`):** Implementación del protocolo **Model Context Protocol (MCP)** mediante JSON-RPC 2.0 sobre `stdio`, permitiendo a IDEs como Antigravity o VSCode invocar herramientas de auditoría en tiempo real (`sentinel_scan`, `sentinel_sca`, `sentinel_explain`).
- **Análisis de Componentes de Software (SCA):** Audita manifiestos de dependencias (`requirements.txt` y `package.json`) buscando versiones obsoletas o vulnerabilidades conocidas (`SCA001`, `SCA002`).
- **Soporte para Exclusiones Personalizadas (`.sentinelignore`):** Lee patrones tipo `.gitignore` para omitir rutas específicas durante las inspecciones.
- **Modo Watch en Tiempo Real (`sentinel watch`):** Monitor de archivos en segundo plano que ejecuta escaneos incrementales automáticos al guardar.
- **Exportación SARIF v2.1.0 (`--format sarif`):** Integración nativa con GitHub Code Scanning, GitLab Security Dashboard o CodeQL.
- **Verificación Completa:** Suite de 23 pruebas unitarias con `pytest` y tipado 100% verificado con `mypy` en modo estricto.

---

## 🛠️ Estructura del Proyecto

```
Antigravity_Sentinel/
├── .specify/                   # Configuración y memoria del flujo Spec-Kit
├── sentinel/                   # Paquete principal
│   ├── __init__.py
│   ├── cli.py                  # Interfaz CLI (scan, sca, watch, patch, mcp)
│   ├── config.py               # Constantes globales
│   └── core/
│       ├── analyzer.py         # Motor híbrido AST (Taint Analysis) + Regex
│       ├── callgraph.py        # Grafo de llamadas e inspección interprocedural
│       ├── agentic.py          # Bucle Agéntico de Autocorrección (--auto-fix)
│       ├── mcp_server.py       # Servidor MCP Nativo JSON-RPC 2.0 sobre stdio
│       ├── sanitizer.py        # Validación y sanitización de rutas/entradas
│       ├── reporter.py         # Formateador ANSI, JSON y SARIF v2.1.0
│       ├── patcher.py          # Generador de Artifacts e interactivo (--apply-patch)
│       ├── ollama.py           # Conector con IA Local (Ollama)
│       ├── ignore.py           # Gestor de patrones .sentinelignore
│       ├── sca.py              # Análisis de dependencias
│       └── watcher.py          # Monitor de archivos en tiempo real
├── tests/                      # Suite de 23 pruebas automáticas (pytest)
│   ├── test_agentic.py
│   ├── test_analyzer.py
│   ├── test_callgraph.py
│   ├── test_cli.py
│   ├── test_ignore.py
│   ├── test_mcp.py
│   ├── test_ollama.py
│   ├── test_patcher.py
│   ├── test_reporter.py
│   ├── test_sanitizer.py
│   ├── test_sca.py
│   └── test_watcher.py
├── pyproject.toml              # Configuración del paquete, mypy y pytest
├── LICENSE                     # Licencia MIT
└── README.md                   # Documentación principal
```

---

## ⚙️ Instalación y Configuración

```bash
# Clonar e instalar en modo ejecutable
git clone https://github.com/ODRIK22/Antigravity_Sentinel.git
cd Antigravity_Sentinel
pip install -e .
```

---

## 💻 Guía de Uso

### 1. Bucle Agéntico de Autocorrección (`--auto-fix`)

```bash
python -m sentinel.cli patch --file ./sentinel/cli.py --auto-fix
```

### 2. Servidor MCP Nativo para IDEs (`mcp`)

```bash
python -m sentinel.cli mcp
```

### 3. Escaneo Estático y Exportación SARIF (`scan`)

```bash
python -m sentinel.cli scan --path ./sentinel --format sarif > results.sarif
```

### 4. Análisis SCA y Modo Watch

```bash
# Análisis de dependencias
python -m sentinel.cli sca --path .

# Monitor en tiempo real
python -m sentinel.cli watch --path ./sentinel
```

---

## 🧪 Pruebas y Control de Calidad

```bash
# Pruebas unitarias
python -m pytest

# Verificación de tipos estricta
python -m mypy sentinel
```

---

## 📄 Licencia

Este proyecto está distribuido bajo la Licencia **MIT**. Consulta el archivo [LICENSE](file:///c:/Users/aidro/OneDrive/Documents/Antigravity%20Sentinel/LICENSE) para más información.
