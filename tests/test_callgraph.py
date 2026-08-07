"""
Pruebas unitarias para el análisis de grafo de llamadas interprocedural.
"""

from pathlib import Path
from sentinel.core.callgraph import InterproceduralCallGraph


def test_callgraph_interprocedural_taint(tmp_path: Path) -> None:
    code_content = """def ejecutor(user_input):
    eval(user_input)

ejecutor(req.body)
"""
    code_file = tmp_path / "module_a.py"
    code_file.write_text(code_content, encoding="utf-8")

    graph = InterproceduralCallGraph(tmp_path)
    issues = graph.analyze_project()

    codes = [i.code for i in issues]
    assert "TAINT002" in codes  # Propagación interprocedural detectada
