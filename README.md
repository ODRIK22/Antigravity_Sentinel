# Antigravity Sentinel 🛡️

![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Type Checking](https://img.shields.io/badge/mypy-strict-brightgreen.svg)
![Tests Pass](https://img.shields.io/badge/tests-28%20passed-success.svg)
![Protocol](https://img.shields.io/badge/MCP-JSON--RPC%202.0-blue.svg)
![SARIF Standard](https://img.shields.io/badge/SARIF-v2.1.0-purple.svg)
![SCA Multi--Ecosystem](https://img.shields.io/badge/SCA-PHP%20%7C%20Go%20%7C%20Node%20%7C%20Py-blue.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Architecture](https://img.shields.io/badge/architecture-Zero%20Trust%20%7C%20100%25%20Offline-orange.svg)

**Antigravity Sentinel** es un agente universal autónomo de ciberseguridad defensiva, **Motor AST Universal (PHP, Go, JS/TS, Python)**, **SCA Multi-Ecosistema (`composer.json`, `go.mod`, `package.json`, `requirements.txt`)**, **Bucle Agéntico (`--auto-fix`)**, **Servidor MCP Nativo** y privacidad 100% offline con IA Local (Ollama).

Diseñado y desarrollado utilizando la metodología **Spec-Kit** dentro de la plataforma Antigravity, Sentinel opera bajo arquitectura Zero Trust y se comunica directamente con IDEs y asistentes mediante MCP.

---

## 🚀 Características Principales

- **Motor AST Universal Multi-Lenguaje:** Estructura sintáctica y rastreo de flujo de datos para proyectos en **PHP / Laravel**, **Go**, **TypeScript / JS / React** y **Python** (`TAINT003`).
- **Análisis SCA Multi-Ecosistema:** Audita manifiestos de dependencias en PHP (`composer.json` / `composer.lock`), Go (`go.mod`), Node.js (`package.json`) y Python (`requirements.txt`) (`SCA001`, `SCA002`).
- **Perfiles de Reglas Modulares por Lenguaje:** Definición desacoplada de fuentes (*Sources*) y vertederos (*Sinks*) específicos por lenguaje para evitar falsos positivos.
- **Bucle Agéntico de Autocorrección (`sentinel patch --auto-fix`):** Proceso iterativo autónomo que aplica remediaciones sugeridas, ejecuta la suite de pruebas unitarias locales (`pytest`) y, si los tests fallan, retroalimenta a la IA local (Ollama) para reintentar la corrección.
- **Análisis de Flujo Interprocedural (Global Call Graph Taint Analysis):** Mapea el grafo de llamadas entre múltiples archivos del proyecto (`TAINT002`).
- **Servidor MCP Nativo (`sentinel mcp`):** Implementación del protocolo **Model Context Protocol (MCP)** mediante JSON-RPC 2.0 sobre `stdio`.
- **Exportación SARIF v2.1.0 (`--format sarif`):** Integración nativa con GitHub Code Scanning, GitLab Security Dashboard o CodeQL.
- **Verificación Completa:** Suite de 28 pruebas unitarias con `pytest` y tipado 100% verificado con `mypy` en modo estricto.

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
│       ├── analyzer.py         # Motor híbrido AST + Universal AST + Regex
│       ├── universal_ast.py    # Parser sintáctico estructural multilenguaje (PHP, Go, JS/TS, Python)
│       ├── rules.py            # Perfiles de reglas modulares por lenguaje
│       ├── callgraph.py        # Grafo de llamadas e inspección interprocedural
│       ├── agentic.py          # Bucle Agéntico de Autocorrección (--auto-fix)
│       ├── mcp_server.py       # Servidor MCP Nativo JSON-RPC 2.0 sobre stdio
│       ├── sanitizer.py        # Validación y sanitización de rutas/entradas
│       ├── reporter.py         # Formateador ANSI, JSON y SARIF v2.1.0
│       ├── patcher.py          # Generador de Artifacts e interactivo (--apply-patch)
│       ├── ollama.py           # Conector con IA Local (Ollama)
│       ├── ignore.py           # Gestor de patrones .sentinelignore
│       ├── sca.py              # Análisis de dependencias (composer.json, go.mod, package.json, requirements.txt)
│       └── watcher.py          # Monitor de archivos en tiempo real
├── tests/                      # Suite de 28 pruebas automáticas (pytest)
│   ├── test_agentic.py
│   ├── test_analyzer.py
│   ├── test_callgraph.py
│   ├── test_cli.py
│   ├── test_ignore.py
│   ├── test_mcp.py
│   ├── test_ollama.py
│   ├── test_patcher.py
│   ├── test_reporter.py
│   ├── test_rules.py
│   ├── test_sanitizer.py
│   ├── test_sca.py
│   ├── test_universal_ast.py
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

### 1. Escaneo Estático y Exportación SARIF (`scan`)

```bash
# Reporte en consola con colores ANSI (Soporta Python, PHP, Go, JS, TS, HTML)
python -m sentinel.cli scan --path ./sentinel

# Exportación en formato SARIF v2.1.0
python -m sentinel.cli scan --path ./sentinel --format sarif > results.sarif
```

### 2. Análisis de Dependencias Multi-Ecosistema SCA (`sca`)

```bash
# Audita composer.json, go.mod, package.json y requirements.txt
python -m sentinel.cli sca --path .
```

### 3. Servidor MCP Nativo y Modo Watch

```bash
# Iniciar servidor MCP para IDEs
python -m sentinel.cli mcp

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
