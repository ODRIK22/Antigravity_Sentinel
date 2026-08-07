"""
Perfiles de Reglas Modulares por Lenguaje para Antigravity Sentinel.
"""

from typing import Final

# Perfil para Python
PYTHON_RULES: Final[dict[str, set[str]]] = {
    "sources": {"request.args", "request.form", "request.json", "sys.argv", "input_data", "user_input", "payload"},
    "sinks": {"eval", "exec", "subprocess.call", "subprocess.Popen", "os.system", "db.execute"},
}

# Perfil para PHP / Laravel
PHP_RULES: Final[dict[str, set[str]]] = {
    "sources": {"$_GET", "$_POST", "$_REQUEST", "$_INPUT", "Input::get", "request()->input"},
    "sinks": {"shell_exec", "passthru", "system", "exec", "eval", "DB::raw", "unserialize"},
}

# Perfil para JavaScript / TypeScript / React
JAVASCRIPT_RULES: Final[dict[str, set[str]]] = {
    "sources": {"req.body", "req.query", "req.params", "props", "params"},
    "sinks": {"eval", "innerHTML", "document.write", "dangerouslySetInnerHTML", "child_process.exec"},
}

# Perfil para Go
GO_RULES: Final[dict[str, set[str]]] = {
    "sources": {"r.URL.Query()", "r.FormValue", "c.Query", "c.Param"},
    "sinks": {"exec.Command", "db.Query", "db.Exec", "template.HTML"},
}


def get_rules_for_extension(file_extension: str) -> dict[str, set[str]]:
    """
    Retorna el perfil de reglas de fuentes (sources) y vertederos (sinks) según la extensión del archivo.
    """
    ext = file_extension.lower()
    if ext == ".py":
        return PYTHON_RULES
    elif ext in (".php", ".phtml"):
        return PHP_RULES
    elif ext in (".js", ".ts", ".jsx", ".tsx"):
        return JAVASCRIPT_RULES
    elif ext == ".go":
        return GO_RULES
    return {"sources": set(), "sinks": set()}
