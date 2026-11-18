"""Détections complémentaires ciblées pour les trois CWE du projet."""
from __future__ import annotations

import re


def _line(code: str, position: int) -> int:
    return code.count("\n", 0, position) + 1


def _snippet(code: str, line: int) -> str:
    lines = code.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()
    return ""


def detect_signatures(code: str) -> list[dict]:
    """Retourne des signaux conservateurs lorsque le flux est lisible localement."""
    findings: list[dict] = []
    # Source d'entrée utilisateur réelle uniquement (HTTP, args, Scanner…)
    has_input = bool(
        re.search(r"\bgetParameter(?:Values|Map|Names)?\s*\(", code)
        or re.search(r"\bgetHeader(?:s)?\s*\(", code)
        or re.search(r"\bgetQueryString\s*\(", code)
        or re.search(r"\bgetCookies\s*\(", code)
        or re.search(r"\bgetInputStream\s*\(", code)
        or re.search(r"\bnew\s+Scanner\s*\(", code)
        or re.search(r"\bargs\s*\[", code)
    )

    sql_match = re.search(
        r"\b(?:executeQuery|executeUpdate|execute|query|queryForObject)\s*\([^;]*\+[^;]*\)",
        code,
        re.I | re.S,
    )
    sql_context = bool(re.search(r"\b(?:select|insert|update|delete)\b", code, re.I))
    statement_sink = re.search(
        r"\bStatement\b[\s\S]{0,600}\bexecute(?:Query|Update|LargeUpdate)?\s*\(",
        code,
        re.I,
    )
    concatenated_query = re.search(
        r"\bString\s+\w+\s*=[\s\S]{0,600}\+",
        code,
        re.I,
    )
    dynamic_concat = re.search(r"\+\s*[A-Za-z_][A-Za-z0-9_]*\b", code)
    prepared = re.search(
        r"\bPreparedStatement\b[\s\S]{0,600}\bset(?:String|Int|Long|Object)\s*\(",
        code,
        re.I,
    )
    if (
        sql_context
        and (sql_match or (statement_sink and concatenated_query and dynamic_concat))
        and not prepared
    ):
        match = sql_match or concatenated_query
        l = _line(code, match.start())
        findings.append(
            {
                "cwe": "CWE-89",
                "line": l,
                "line_start": l,
                "line_end": l,
                "severity": "ERROR",
                "snippet": _snippet(code, l),
                "message": "Entrée utilisateur concaténée dans une requête SQL.",
            }
        )

    html_sink = re.search(
        r"\b(?:getWriter\s*\(\s*\)|getOutputStream\s*\(\s*\)|out\b)"
        r".{0,180}\b(?:print|println|write|append)\s*\([^;]*\+[^;]*\)",
        code,
        re.I | re.S,
    )
    html_context = bool(re.search(r"<(?:html|p|li|body|h[1-6])\b", code, re.I))
    encoded = re.search(
        r"(?:encodeForHTML|escapeHtml|htmlEscape|StringEscapeUtils\.escapeHtml|encodeHtml|sanitizeHtml)",
        code,
        re.I,
    )
    if has_input and html_context and html_sink and not encoded:
        l = _line(code, html_sink.start())
        findings.append(
            {
                "cwe": "CWE-79",
                "line": l,
                "line_start": l,
                "line_end": l,
                "severity": "ERROR",
                "snippet": _snippet(code, l),
                "message": "Entrée utilisateur écrite dans du HTML sans encodage.",
            }
        )

    path_match = re.search(
        r"\b(?:new\s+(?:java\.io\.)?File|Paths?\.get|resolve)\s*\([^;]*(?:\+|,\s*[A-Za-z_][A-Za-z0-9_]*)",
        code,
        re.I | re.S,
    )
    path_context = bool(re.search(r"\b(?:filename|filepath|file|path)\b", code, re.I))
    normalized = bool(
        re.search(r"\.(?:normalize|toRealPath)\s*\(", code)
        and re.search(r"\.startsWith\s*\(", code)
    )
    if has_input and path_context and path_match and not normalized:
        l = _line(code, path_match.start())
        findings.append(
            {
                "cwe": "CWE-22",
                "line": l,
                "line_start": l,
                "line_end": l,
                "severity": "ERROR",
                "snippet": _snippet(code, l),
                "message": "Entrée utilisateur utilisée dans un chemin sans confinement au répertoire autorisé.",
            }
        )

    return findings
