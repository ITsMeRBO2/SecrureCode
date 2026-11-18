"""Tests de validation des corrections pour les Bugs 1, 2 et 3.

Critères vérifiés :
1. Bug 1 : Snippet toujours issu du code source (jamais 'requires login', jamais vide).
2. Bug 2 : Dédoublonnage strict (1 seul finding par CWE + ligne, fusion des règles qui se chevauchent).
3. Bug 3 : Boucle de réparation javac (erreur toRealPath réparée, compilation finale OK, re-scan OK).
4. Intégration complète : détection -> ML -> GenAI -> javac OK -> re-scan 0 -> ML SAFE.
5. Code SAFE : 0 finding, GenAI non appelé.
6. Stabilité : 5 exécutions successives identiques et déterministes.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from baseline.run_semgrep import deduplicate_findings, run_semgrep
from genai.validator import compile_java, validate_fix
from pipeline.analyze import analyze

needs_semgrep = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep absent")

# ── Code servlet multi-vulnérable (SQLi + XSS + Path Traversal) ─────────────
VULNERABLE_SERVLET = """\
package com.example;

import java.io.*;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class FullVulnerableServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String id = request.getParameter("id");
        String comment = request.getParameter("comment");
        String filename = request.getParameter("file");

        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "");
            Statement stmt = conn.createStatement();
            String sql = "SELECT * FROM users WHERE id=" + id;
            ResultSet rs = stmt.executeQuery(sql);
        } catch (SQLException e) {
            throw new ServletException(e);
        }

        PrintWriter out = response.getWriter();
        out.println("<h1>Results for: " + comment + "</h1>");

        File f = new File("/var/app/files/" + filename);
        FileInputStream fis = new FileInputStream(f);
        fis.read();
    }
}
"""

SAFE_SERVLET = r"""package com.example;

import java.io.*;
import java.nio.file.*;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class FullSafeServlet extends HttpServlet {
    private static final String UPLOAD_DIR = "/var/app/files";
    private static final Path BASE_DIR = Paths.get(UPLOAD_DIR).toAbsolutePath().normalize();

    private String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#x27;");
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String id = request.getParameter("id");
        String comment = request.getParameter("comment");
        String filename = request.getParameter("file");

        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "");
             PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?")) {
            ps.setString(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {}
            }
        } catch (SQLException e) {
            throw new ServletException(e);
        }

        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        out.println("<h1>Results for: " + escapeHtml(comment) + "</h1>");

        Path candidate = BASE_DIR.resolve(filename).normalize();
        if (!candidate.startsWith(BASE_DIR)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
            return;
        }
        File f = candidate.toFile();
        if (f.exists()) {
            response.setContentType("application/octet-stream");
            Files.copy(candidate, response.getOutputStream());
        }
    }
}
"""


# ── BUG 1 : EXTRAIT DE CODE ─────────────────────────────────────────────────

@needs_semgrep
def test_snippet_never_contains_requires_login(tmp_path):
    """Vérifie que pour chaque finding, snippet provient du fichier source et n'est jamais 'requires login'."""
    p = tmp_path / "FullVulnerableServlet.java"
    p.write_text(VULNERABLE_SERVLET, encoding="utf-8")
    findings = run_semgrep(p)

    assert len(findings) >= 3
    source_lines = VULNERABLE_SERVLET.splitlines()

    for f in findings:
        snippet = f.get("snippet", "")
        # Critère 1 : jamais "requires login"
        assert "requires login" not in snippet.lower(), f"Snippet invalide: {snippet}"
        # Critère 2 : jamais vide
        assert len(snippet.strip()) > 0, "Le snippet ne doit pas être vide"
        # Critère 3 : correspond exactement aux lignes du code source
        line_start = f["line_start"]
        expected_line = source_lines[line_start - 1].strip()
        assert expected_line in snippet, f"Snippet '{snippet}' ne contient pas la ligne {line_start} '{expected_line}'"
        # Critère 4 : context_snippet contient le marqueur '>'
        assert ">" in f.get("context_snippet", ""), "Le context_snippet doit marquer la ligne vulnérable avec '>'"


# ── BUG 2 : DÉDOUBLONNAGE STRICT ───────────────────────────────────────────

@needs_semgrep
def test_deduplication_single_finding_per_cwe_and_line(tmp_path):
    """Vérifie qu'aucun doublon n'apparaît pour le même CWE sur la même ligne."""
    p = tmp_path / "FullVulnerableServlet.java"
    p.write_text(VULNERABLE_SERVLET, encoding="utf-8")
    findings = run_semgrep(p)

    # Vérification d'unicité sur (cwe, line_start)
    seen_cwe_lines = set()
    for f in findings:
        pair = (f["cwe"], f["line_start"])
        assert pair not in seen_cwe_lines, f"Doublon détecté pour {pair} : {f}"
        seen_cwe_lines.add(pair)


def test_deduplication_helper_preserves_distinct_cwes():
    """Vérifie que deduplicate_findings fusionne les mêmes CWE mais conserve des CWE distincts."""
    raw = [
        {"cwe": "CWE-79", "line_start": 10, "line_end": 10, "rule_id": "xss", "severity": "ERROR", "message": "XSS 1"},
        {"cwe": "CWE-79", "line_start": 10, "line_end": 10, "rule_id": "xss-concat", "severity": "WARNING", "message": "XSS 2"},
        {"cwe": "CWE-89", "line_start": 10, "line_end": 10, "rule_id": "sqli", "severity": "ERROR", "message": "SQLi"},
    ]
    deduped = deduplicate_findings(raw)
    assert len(deduped) == 2
    cwes = {f["cwe"] for f in deduped}
    assert cwes == {"CWE-79", "CWE-89"}
    cwe79 = next(f for f in deduped if f["cwe"] == "CWE-79")
    assert cwe79["severity"] == "ERROR"
    assert "xss" in cwe79["rule_id"] and "xss-concat" in cwe79["rule_id"]


# ── BUG 3 : VALIDATION & BOUCLE DE RÉPARATION JAVAC ─────────────────────────

def test_javac_repair_loop_fixes_torealpath_in_static_field(monkeypatch):
    """Vérifie que si le LLM produit initialement un toRealPath() dans un champ statique,

    la boucle de réparation lui renvoie l'erreur javac et le code final corrigé compile.
    """
    broken_fixed_code = """\
package com.example;
import java.io.*;
import java.nio.file.*;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class SecureBlogServlet extends HttpServlet {
    private static final String UPLOAD_DIR = "/var/app/files";
    private static final Path BASE_DIR = Paths.get(UPLOAD_DIR).toRealPath();

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {}
}
"""

    # Vérification que ce code échoue bien à la compilation avec IOException
    broken_ok, broken_msg = compile_java(broken_fixed_code)
    assert not broken_ok
    assert "unreported exception" in broken_msg or "IOException" in broken_msg

    valid_fixed_code = """\
package com.example;
import java.io.*;
import java.nio.file.*;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class SecureBlogServlet extends HttpServlet {
    private static final String UPLOAD_DIR = "/var/app/files";
    private static final Path BASE_DIR = Paths.get(UPLOAD_DIR).toAbsolutePath().normalize();

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {}
}
"""
    valid_ok, _ = compile_java(valid_fixed_code)
    assert valid_ok, "Le code avec toAbsolutePath().normalize() doit compiler avec javac"

    # Simulation du générateur qui échoue au tour 1 puis réussit au tour 2 grâce au feedback
    calls = []

    class SelfRepairingGenerator:
        def generate(self, prompt: str) -> str:
            calls.append(prompt)
            if len(calls) == 1:
                return json.dumps({
                    "cwes": ["CWE-22"],
                    "findings": [{"cwe": "CWE-22", "vulnerable_line": 15, "explanation": "Path traversal"}],
                    "fixed_code": broken_fixed_code,
                })
            else:
                # Au tour 2, le prompt doit contenir l'erreur javac exacte
                assert "ERREUR DE COMPILATION JAVAC" in prompt
                assert "unreported exception" in prompt or "IOException" in prompt
                return json.dumps({
                    "cwes": ["CWE-22"],
                    "findings": [{"cwe": "CWE-22", "vulnerable_line": 15, "explanation": "Path traversal corrigé"}],
                    "fixed_code": valid_fixed_code,
                })

    result = analyze(
        "public class T { void f() { new java.io.File(args[0]); } }",
        generator=SelfRepairingGenerator(),
        baseline_runner=lambda src: [{"cwe": "CWE-22", "line_start": 1, "line_end": 1, "message": "Path"}],
    )

    assert len(calls) == 2, "La boucle de réparation aurait dû déclencher un 2ème essai"
    assert result["genai"]["validation"]["javac"]["ok"] is True
    assert result["genai"]["fixed_code"].strip() == valid_fixed_code.strip()


# ── INTÉGRATION COMPLÈTE SUR SERVLET VULNÉRABLE ─────────────────────────────

@needs_semgrep
def test_full_pipeline_vulnerable_servlet_end_to_end(monkeypatch):
    """Test complet : détection Semgrep -> ML -> GenAI -> javac OK -> re-scan 0 -> ML SAFE."""
    class MockPerfectGenerator:
        def generate(self, prompt: str) -> str:
            return json.dumps({
                "cwes": ["CWE-89", "CWE-79", "CWE-22"],
                "findings": [
                    {"cwe": "CWE-89", "vulnerable_line": 18, "explanation": "Injection SQL par concaténation."},
                    {"cwe": "CWE-79", "vulnerable_line": 23, "explanation": "XSS par écriture directe dans out.println."},
                    {"cwe": "CWE-22", "vulnerable_line": 25, "explanation": "Path Traversal sans confinement."},
                ],
                "fixed_code": SAFE_SERVLET,
            })

    result = analyze(VULNERABLE_SERVLET, generator=MockPerfectGenerator())

    # 1. Vérification baseline
    assert result["baseline"]["status"] == "ok"
    assert len(result["findings"]) >= 3
    # 2. Aucun finding concurrent 'genai'
    assert all(f["approach"] in ("baseline", "deterministic") for f in result["findings"])
    # 3. Chaque finding est enrichi par l'explication GenAI
    for f in result["findings"]:
        assert f.get("genai_explanation") is not None
        assert f.get("snippet") != "requires login"
    # 4. Validation javac et re-scan
    val = result["genai"]["validation"]
    assert val["javac"]["ok"] is True
    assert val["baseline"]["ok"] is True
    assert val["ml"]["ok"] is True
    assert val["validated"] is True
    # 5. Statut global
    assert result["overall"] == "safe"


# ── CODE SAFE : 0 FINDING & GENAI NON APPELÉ ────────────────────────────────

@needs_semgrep
def test_full_pipeline_safe_code_no_genai():
    """Un code sécurisé ne doit produire aucun finding, ne pas appeler GenAI et donner overall='safe'."""
    result = analyze(SAFE_SERVLET, generator=None)
    assert len(result["findings"]) == 0
    assert result["genai"]["status"] == "skipped"
    assert result["overall"] == "safe"


# ── TEST DE STABILITÉ (5 EXÉCUTIONS SUCCESSIFS) ─────────────────────────────

@needs_semgrep
def test_pipeline_stability_5_iterations():
    """Relance 5 fois le même scénario pour s'assurer de la stabilité des résultats."""
    for _ in range(5):
        result = analyze(SAFE_SERVLET, generator=None)
        assert len(result["findings"]) == 0
        assert result["overall"] == "safe"


# ── TEST DOCUMENT SYSTEM : LES 3 VULNÉRABILITÉS ET RÉPARATION TEXT BLOCK ──────

DOCUMENT_SYSTEM_CODE = """\
import java.io.*;
import java.sql.*;
import java.nio.file.*;
import java.util.*;

public class VulnerableDocumentSystem {
    private static final String DB_URL = "jdbc:sqlite:documents.db";
    private static final String UPLOAD_DIR = "uploads";
    private static final List<String> comments = new ArrayList<>();

    public static Connection connect() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    public static void initializeDatabase() {
        String query = \"\"\"
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                password TEXT,
                email TEXT,
                role TEXT
            )
            \"\"\";
        try (Connection conn = connect();
             Statement stmt = conn.createStatement()) {
            stmt.execute(query);
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public static void login(String username, String password) {
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        try (Connection conn = connect();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            if (rs.next()) {
                System.out.println("Login successful!");
            }
        } catch (SQLException e) {
            System.out.println("Login error: " + e.getMessage());
        }
    }

    public static void searchUser(String username) {
        String query = "SELECT * FROM users WHERE username LIKE '%" + username + "%'";
        try (Connection conn = connect();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            while (rs.next()) {
                System.out.println("User: " + rs.getString("username"));
            }
        } catch (SQLException e) {
            System.out.println("Search error: " + e.getMessage());
        }
    }

    public static void addComment(String comment) {
        comments.add(comment);
    }

    public static String displayComments() {
        StringBuilder html = new StringBuilder();
        html.append("<html>");
        html.append("<body>");
        for (String comment : comments) {
            html.append("<p>");
            html.append(comment);
            html.append("</p>");
        }
        html.append("</body></html>");
        return html.toString();
    }

    public static String searchComments(String keyword) {
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h2>Search: ");
        html.append(keyword);
        html.append("</h2>");
        return html.toString();
    }

    public static void readDocument(String filename) {
        File file = new File(UPLOAD_DIR + "/" + filename);
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line = reader.readLine();
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    public static void createDocument(String filename, String content) {
        File file = new File(UPLOAD_DIR + "/" + filename);
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(content);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    public static void deleteDocument(String filename) {
        File file = new File(UPLOAD_DIR + "/" + filename);
        if (file.exists()) {
            file.delete();
        }
    }
}
"""


@needs_semgrep
def test_document_system_detects_all_three_cwes(tmp_path):
    """Vérifie que VulnerableDocumentSystem déclenche bien CWE-89, CWE-79 et CWE-22."""
    p = tmp_path / "VulnerableDocumentSystem.java"
    p.write_text(DOCUMENT_SYSTEM_CODE, encoding="utf-8")
    findings = run_semgrep(p)

    cwes = {f["cwe"] for f in findings}
    assert "CWE-89" in cwes, f"CWE-89 manquant : {cwes}"
    assert "CWE-79" in cwes, f"CWE-79 manquant : {cwes}"
    assert "CWE-22" in cwes, f"CWE-22 manquant : {cwes}"


def test_auto_repair_unclosed_multiline_strings():
    """Vérifie la réparation automatique d'une chaîne multiligne avec guillemet simple vers un text block Java 17."""
    from genai.analyze import auto_repair_unclosed_strings
    from genai.validator import compile_java

    broken_code = (
        'public class TestQuery {\n'
        '    public static void main(String[] args) {\n'
        '        String sql = "CREATE TABLE IF NOT EXISTS users (\n'
        '            id integer PRIMARY KEY,\n'
        '            username text NOT NULL,\n'
        '            email text NOT NULL\n'
        '        )";\n'
        '        System.out.println(sql);\n'
        '    }\n'
        '}\n'
    )
    repaired = auto_repair_unclosed_strings(broken_code)
    assert '"""' in repaired
    ok, msg = compile_java(repaired)
    assert ok is True, f"Le code réparé doit compiler, erreur : {msg}"

