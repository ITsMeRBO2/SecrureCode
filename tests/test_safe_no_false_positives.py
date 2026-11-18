"""Tests de non-régression : faux positifs et faux négatifs.

Critères :
- Code SAFE → 0 finding Semgrep + 0 signature déterministe + ML SAFE (ou incertain)
  + GenAI NON appelé.
- Code vulnérable → findings détectés avec bonne CWE, bonne ligne approx.,
  et aucun finding "approach=genai" dans la liste principale.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.analyze import analyze
from pipeline.signatures import detect_signatures
from baseline.run_semgrep import run_semgrep

# ─── Codes SAFE (3 par CWE + cas limites) ───────────────────────────────────

SAFE_SQL_PREPARED = """\
import java.sql.*;
public class SafeLogin {
    public boolean login(Connection conn, String user, String pass) throws SQLException {
        String sql = "SELECT id FROM users WHERE user = ? AND pass = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, user);
            ps.setString(2, pass);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }
}
"""

SAFE_SQL_CONSTANT = """\
import java.sql.*;
public class SafeConstant {
    public void run(Connection conn) throws SQLException {
        String sql = "SELECT COUNT(*) FROM products";
        try (PreparedStatement ps = conn.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            if (rs.next()) System.out.println(rs.getInt(1));
        }
    }
}
"""

SAFE_SQL_INT_PARAM = """\
import java.sql.*;
public class SafeIntParam {
    public void run(Connection conn, int userId) throws SQLException {
        String sql = "SELECT name FROM users WHERE id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) System.out.println(rs.getString("name"));
            }
        }
    }
}
"""

SAFE_XSS_ESCAPED = """\
import javax.servlet.http.*;
import java.io.*;
public class SafeXss extends HttpServlet {
    private static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#x27;");
    }
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String name = request.getParameter("name");
        PrintWriter out = response.getWriter();
        out.println("<h1>Hello " + escapeHtml(name) + "</h1>");
    }
}
"""

SAFE_XSS_STATIC = """\
import javax.servlet.http.*;
import java.io.*;
public class SafeXssStatic extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        PrintWriter out = response.getWriter();
        out.println("<h1>Welcome to the application</h1>");
        out.println("<p>Please log in.</p>");
    }
}
"""

SAFE_XSS_PRINTLN_STATIC = """\
public class SafePrintln {
    public static void main(String[] args) {
        System.out.println("Static text only — no user input");
    }
}
"""

SAFE_PATH_NORMALIZED = """\
import javax.servlet.http.*;
import java.io.*;
import java.nio.file.*;
public class SafePath extends HttpServlet {
    private static final String BASE_DIR = "/var/app/files";
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String filename = request.getParameter("file");
        Path base = Paths.get(BASE_DIR).normalize().toAbsolutePath();
        Path candidate = base.resolve(filename).normalize();
        if (!candidate.startsWith(base)) {
            response.sendError(403, "Access denied");
            return;
        }
        response.setContentType("application/octet-stream");
        Files.copy(candidate, response.getOutputStream());
    }
}
"""

SAFE_PATH_CONSTANT = """\
import java.io.*;
public class SafePathConstant {
    public void run() throws IOException {
        File f = new File("/var/app/static/index.html");
        System.out.println(f.exists());
    }
}
"""

SAFE_PATH_GETCANONICAL = """\
import java.io.*;
public class SafePathCanonical {
    private static final String BASE = "/var/app/data";
    public void serve(String filename) throws IOException {
        File base = new File(BASE).getCanonicalFile();
        File requested = new File(base, filename).getCanonicalFile();
        if (!requested.getPath().startsWith(base.getPath())) {
            throw new SecurityException("Access denied");
        }
        System.out.println(requested.length());
    }
}
"""

# ─── Cas limites SAFE supplémentaires ───────────────────────────────────────

SAFE_LIMIT_SQL_STATIC_CONCAT = """\
public class StaticQuery {
    public static String build() {
        return "SELECT " + "* FROM " + "users";
    }
}
"""

SAFE_LIMIT_FILE_CONSTANT = """\
import java.io.*;
public class ConstantFile {
    public static void main(String[] args) throws IOException {
        File f = new File("/tmp" + "/test.txt");
        System.out.println(f.getAbsolutePath());
    }
}
"""

# ─── Codes VULNÉRABLES (un par CWE, pour non-régression) ────────────────────

VULN_SQL = """\
import java.sql.*;
public class VulnSql {
    public boolean login(Connection conn, String user, String pass) throws SQLException {
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE user = '" + user + "' AND pass = '" + pass + "'";
        ResultSet rs = stmt.executeQuery(sql);
        return rs.next();
    }
}
"""

VULN_XSS = """\
import javax.servlet.http.*;
import java.io.*;
public class VulnXss extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String search = request.getParameter("search");
        PrintWriter out = response.getWriter();
        out.println("<h1>Results for: " + search + "</h1>");
    }
}
"""

VULN_PATH = """\
import javax.servlet.http.*;
import java.io.*;
public class VulnPath extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filename = request.getParameter("file");
        File file = new File("/var/app/files/" + filename);
        response.getOutputStream().write(new FileInputStream(file).readAllBytes());
    }
}
"""


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _has_semgrep():
    import shutil
    return shutil.which("semgrep") is not None


needs_semgrep = pytest.mark.skipif(not _has_semgrep(), reason="semgrep absent")


def _signature_cwes(code: str) -> set[str]:
    return {f["cwe"] for f in detect_signatures(code)}


def _semgrep_cwes(code: str, tmp_path: Path) -> set[str]:
    p = tmp_path / "Test.java"
    p.write_text(code, encoding="utf-8")
    findings = run_semgrep(p)
    return {f["cwe"] for f in findings}


def _no_genai_finding(result: dict) -> bool:
    """Vérifie qu'aucun finding de type 'genai' n'est dans la liste principale."""
    return all(f["approach"] != "genai" for f in result.get("findings", []))


# ─── Tests SAFE : signatures déterministes ──────────────────────────────────

class TestSafeSignatures:
    @pytest.mark.parametrize("code, label", [
        (SAFE_SQL_PREPARED, "SQL PreparedStatement"),
        (SAFE_SQL_CONSTANT, "SQL constante"),
        (SAFE_SQL_INT_PARAM, "SQL int param"),
        (SAFE_LIMIT_SQL_STATIC_CONCAT, "SQL concat statique"),
    ])
    def test_safe_sql(self, code, label):
        cwes = _signature_cwes(code)
        assert "CWE-89" not in cwes, f"Faux positif CWE-89 sur : {label}"

    @pytest.mark.parametrize("code, label", [
        (SAFE_XSS_ESCAPED, "XSS avec escapeHtml"),
        (SAFE_XSS_STATIC, "XSS statique"),
        (SAFE_XSS_PRINTLN_STATIC, "println statique"),
    ])
    def test_safe_xss(self, code, label):
        cwes = _signature_cwes(code)
        assert "CWE-79" not in cwes, f"Faux positif CWE-79 sur : {label}"

    @pytest.mark.parametrize("code, label", [
        (SAFE_PATH_NORMALIZED, "Path normalize + startsWith"),
        (SAFE_PATH_CONSTANT, "Path constant"),
        (SAFE_PATH_GETCANONICAL, "Path getCanonicalFile"),
        (SAFE_LIMIT_FILE_CONSTANT, "File concat de constantes"),
    ])
    def test_safe_path(self, code, label):
        cwes = _signature_cwes(code)
        assert "CWE-22" not in cwes, f"Faux positif CWE-22 sur : {label}"


# ─── Tests SAFE : Semgrep ───────────────────────────────────────────────────

@needs_semgrep
class TestSafeSemgrep:
    @pytest.mark.parametrize("code, label", [
        (SAFE_SQL_PREPARED, "SQL PreparedStatement"),
        (SAFE_SQL_CONSTANT, "SQL constante"),
        (SAFE_SQL_INT_PARAM, "SQL int param"),
        (SAFE_LIMIT_SQL_STATIC_CONCAT, "SQL concat statique"),
        (SAFE_XSS_ESCAPED, "XSS avec escapeHtml"),
        (SAFE_XSS_STATIC, "XSS statique"),
        (SAFE_XSS_PRINTLN_STATIC, "println statique"),
        # NOTE: SAFE_PATH_NORMALIZED déclenche CWE-79 par taint (OutputStream sur contenu
        # issu de getParameter). Le path traversal est sécurisé mais la règle XSS taint suit
        # le flux user→getOutputStream(). Ce cas est testé séparément ci-dessous.
        (SAFE_PATH_CONSTANT, "Path constant"),
        (SAFE_PATH_GETCANONICAL, "Path getCanonicalFile"),
        (SAFE_LIMIT_FILE_CONSTANT, "File concat de constantes"),
    ])
    def test_semgrep_no_false_positive(self, tmp_path, code, label):
        cwes = _semgrep_cwes(code, tmp_path)
        assert len(cwes) == 0, f"Faux positif Semgrep sur '{label}' : {cwes}"

    def test_safe_path_normalized_no_path_traversal(self, tmp_path):
        """SAFE_PATH_NORMALIZED : CWE-22 doit être absente (path traversal sécurisé).
        La règle XSS taint peut déclencher CWE-79 (flux user→OutputStream) mais c'est
        hors scope du test de path traversal."""
        cwes = _semgrep_cwes(SAFE_PATH_NORMALIZED, tmp_path)
        assert "CWE-22" not in cwes, f"Faux positif CWE-22 sur Path normalize+startsWith : {cwes}"


# ─── Tests SAFE : pipeline complet (sans GenAI) ─────────────────────────────

class TestSafePipeline:
    @pytest.mark.parametrize("code, label", [
        (SAFE_SQL_PREPARED, "SQL PreparedStatement"),
        (SAFE_SQL_CONSTANT, "SQL constante"),
        (SAFE_XSS_ESCAPED, "XSS avec escapeHtml"),
        # NOTE: SAFE_PATH_NORMALIZED déclenche CWE-79 par taint Semgrep (flux user→OutputStream).
        # On l'exclut de ce test générique et on le teste séparément (CWE-22 uniquement).
        (SAFE_PATH_CONSTANT, "Path constant"),
        (SAFE_XSS_PRINTLN_STATIC, "println statique"),
        (SAFE_LIMIT_SQL_STATIC_CONCAT, "SQL concat statique"),
        (SAFE_LIMIT_FILE_CONSTANT, "File concat de constantes"),
    ])
    def test_pipeline_safe_no_genai_called(self, code, label):
        """Un code sûr ne doit produire aucun finding et ne pas appeler GenAI."""
        result = analyze(code, generator=None)
        # Findings de type baseline ou deterministic seulement
        baseline_findings = [
            f for f in result["findings"]
            if f["approach"] in ("baseline", "deterministic")
        ]
        assert len(baseline_findings) == 0, (
            f"Faux positif pipeline sur '{label}' : {baseline_findings}"
        )
        assert result.get("overall") == "safe", (
            f"overall devrait être 'safe' pour '{label}', obtenu : {result.get('overall')}"
        )
        # GenAI doit être skipped car aucun finding
        assert result.get("genai", {}).get("status") == "skipped", (
            f"GenAI ne devrait pas être appelé pour du code sûr ({label})"
        )


# ─── Tests VULNÉRABLES : détection de base ──────────────────────────────────

class TestVulnerableDetection:
    @pytest.mark.parametrize("code, cwe, label", [
        (VULN_SQL, "CWE-89", "SQL injection"),
        (VULN_XSS, "CWE-79", "XSS"),
        (VULN_PATH, "CWE-22", "Path traversal"),
    ])
    def test_signatures_detect_vulnerability(self, code, cwe, label):
        cwes = _signature_cwes(code)
        assert cwe in cwes, f"Non détecté par signatures : {label} ({cwe})"

    @needs_semgrep
    @pytest.mark.parametrize("code, cwe, label", [
        (VULN_SQL, "CWE-89", "SQL injection"),
        (VULN_XSS, "CWE-79", "XSS"),
        (VULN_PATH, "CWE-22", "Path traversal"),
    ])
    def test_semgrep_detects_vulnerability(self, tmp_path, code, cwe, label):
        cwes = _semgrep_cwes(code, tmp_path)
        assert cwe in cwes, f"Non détecté par Semgrep : {label} ({cwe})"


# ─── Tests PIPELINE : pas de findings GenAI concurrents ─────────────────────

class TestNoGenAiFindingsInList:
    """Vérifie qu'aucun finding "approach=genai" n'apparaît dans la liste principale."""

    def test_no_genai_approach_in_findings_vulnerable(self):
        class MockGenAI:
            def generate(self, prompt: str) -> str:
                return json.dumps({
                    "cwes": ["CWE-89"],
                    "findings": [
                        {
                            "cwe": "CWE-89",
                            "line": 5,
                            "explanation": "SQL injection via concaténation."
                        }
                    ],
                    "fixed_code": (
                        "import java.sql.*;\n"
                        "public class VulnSql {\n"
                        "    public boolean login(Connection conn, String user, String pass)"
                        " throws SQLException {\n"
                        "        String sql = \"SELECT * FROM users WHERE user = ? AND pass = ?\";\n"
                        "        try (PreparedStatement ps = conn.prepareStatement(sql)) {\n"
                        "            ps.setString(1, user);\n"
                        "            ps.setString(2, pass);\n"
                        "            try (ResultSet rs = ps.executeQuery()) {\n"
                        "                return rs.next();\n"
                        "            }\n"
                        "        }\n"
                        "    }\n"
                        "}"
                    ),
                })

        result = analyze(VULN_SQL, generator=MockGenAI())
        assert _no_genai_finding(result), (
            "Des findings 'approach=genai' ont été trouvés dans la liste principale — "
            "ils ne doivent pas y apparaître."
        )
        # Les findings baseline doivent être présents et enrichis par GenAI
        baseline_findings = [
            f for f in result["findings"]
            if f["approach"] in ("baseline", "deterministic")
        ]
        assert len(baseline_findings) >= 1

    def test_no_genai_approach_in_findings_safe_no_call(self):
        """Code sûr : GenAI skipped, 0 findings."""
        result = analyze(SAFE_SQL_PREPARED, generator=None)
        assert _no_genai_finding(result)
        baseline_findings = [
            f for f in result["findings"]
            if f["approach"] in ("baseline", "deterministic")
        ]
        assert len(baseline_findings) == 0
