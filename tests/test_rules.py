"""
Pruebas unitarias para el módulo de perfiles de reglas por lenguaje.
"""

from sentinel.core.rules import get_rules_for_extension, PHP_RULES, GO_RULES, PYTHON_RULES


def test_rules_by_extension() -> None:
    php_res = get_rules_for_extension(".php")
    go_res = get_rules_for_extension(".go")
    py_res = get_rules_for_extension(".py")

    assert php_res == PHP_RULES
    assert go_res == GO_RULES
    assert py_res == PYTHON_RULES
    assert "$_GET" in php_res["sources"]
    assert "r.URL.Query()" in go_res["sources"]
