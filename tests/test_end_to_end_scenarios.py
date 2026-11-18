import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.analyze import analyze
from pipeline.signatures import detect_signatures
from baseline.run_semgrep import run_semgrep

VULNERABLE_CWE89 = """
import java.sql.*;

public class AuthExample {
    public boolean login(String user, String pass) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "root");
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE user = '" + user + "' AND pass = '" + pass + "'";
        ResultSet rs = stmt.executeQuery(sql);
        return rs.next();
    }
}
"""

VULNERABLE_CWE79 = """
import javax.servlet.http.*;
import java.io.*;

public class CommentServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String search = request.getParameter("search");
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        out.println("<h1>Results for: " + search + "</h1>");
    }
}
"""

VULNERABLE_CWE22 = """
import javax.servlet.http.*;
import java.io.*;

public class FileServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String filename = request.getParameter("file");
        File file = new File("/var/app/files/" + filename);
        FileInputStream fis = new FileInputStream(file);
        fis.read();
    }
}
"""

SAFE_EXAMPLE = """
import java.sql.*;
import java.nio.file.*;

public class SafeClass {
    public void run(Connection conn, String id, String filename) throws Exception {
        String sql = "SELECT id, name FROM users WHERE id = ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    System.out.println("User: " + rs.getString("name"));
                }
            }
        }
        Path base = Paths.get("/var/app/files").toRealPath();
        Path candidate = base.resolve(filename).normalize();
        if (!candidate.startsWith(base)) {
            throw new SecurityException("Access denied");
        }
    }
}
"""


def test_detects_cwe89_vulnerability():
    findings = detect_signatures(VULNERABLE_CWE89)
    cwes = {f["cwe"] for f in findings}
    assert "CWE-89" in cwes
    assert all("snippet" in f and "severity" in f for f in findings)


def test_detects_cwe79_vulnerability():
    findings = detect_signatures(VULNERABLE_CWE79)
    cwes = {f["cwe"] for f in findings}
    assert "CWE-79" in cwes
    assert all("snippet" in f and "severity" in f for f in findings)


def test_detects_cwe22_vulnerability():
    findings = detect_signatures(VULNERABLE_CWE22)
    cwes = {f["cwe"] for f in findings}
    assert "CWE-22" in cwes
    assert all("snippet" in f and "severity" in f for f in findings)


def test_safe_example_produces_no_false_positives():
    findings = detect_signatures(SAFE_EXAMPLE)
    assert len(findings) == 0


def test_end_to_end_pipeline_integration(monkeypatch):
    class MockOllamaGenerator:
        def generate(self, prompt):
            return json.dumps(
                {
                    "cwes": ["CWE-89"],
                    "findings": [
                        {
                            "cwe": "CWE-89",
                            "line": 8,
                            "explication": "Injection SQL par concaténation de variables dans Statement.",
                        }
                    ],
                    "fixed_code": (
                        "import java.sql.*;\n"
                        "public class AuthExample {\n"
                        "    public boolean login(String user, String pass) throws SQLException {\n"
                        "        String sql = \"SELECT * FROM users WHERE user = ? AND pass = ?\";\n"
                        "        try (Connection conn = DriverManager.getConnection(\"jdbc:mysql://localhost/db\", \"root\", \"root\");\n"
                        "             PreparedStatement ps = conn.prepareStatement(sql)) {\n"
                        "            ps.setString(1, user);\n"
                        "            ps.setString(2, pass);\n"
                        "            try (ResultSet rs = ps.executeQuery()) {\n"
                        "                return rs.next();\n"
                        "            }\n"
                        "        }\n"
                        "    }\n"
                        "}"
                    ),
                }
            )

    result = analyze(
        VULNERABLE_CWE89,
        generator=MockOllamaGenerator(),
        model_path=ROOT / "ml/models/securecode_ml.joblib",
    )
    assert result["status"] == "ok"
    assert "CWE-89" in result["baseline"]["cwes"]
    assert result["ml"]["status"] == "ok"
    assert result["genai"]["status"] == "ok"
    assert result["genai"]["validation"]["javac"]["ok"] is True
    assert result["genai"]["validation"]["validated"] is True
    assert len(result["findings"]) >= 1
