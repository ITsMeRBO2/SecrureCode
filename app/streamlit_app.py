"""Interface Streamlit du pipeline SecureCode AI."""
from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from genai.client import OllamaClient  # noqa: E402
from pipeline.analyze import analyze  # noqa: E402


def numbered_code(code: str) -> str:
    """Ajoute les numéros de ligne pour relier un finding au code affiché."""
    return "\n".join(f"{number:4d} | {line}" for number, line in enumerate(code.splitlines(), 1))


def findings_csv(result: dict) -> str:
    output = io.StringIO()
    fields = ["approach", "status", "cwe", "line", "confidence", "explanation", "validated"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for finding in result.get("findings", []):
        validation = finding.get("validation") or {}
        writer.writerow(
            {
                "approach": finding.get("approach"),
                "status": finding.get("status"),
                "cwe": finding.get("cwe"),
                "line": finding.get("line"),
                "confidence": finding.get("confidence"),
                "explanation": finding.get("explanation"),
                "validated": validation.get("validated"),
            }
        )
    return output.getvalue()


def show_approach(name: str, details: dict) -> None:
    status = details.get("status", "unknown")
    if status == "ok":
        if name == "ML":
            label = details.get("label", "Inconnue")
            conf = details.get("confidence", "")
            st.success(f"**{name}** : OK — Classe `{label}` (confiance: {conf})")
        elif name == "Baseline":
            count = details.get("count", 0)
            det = details.get("deterministic_count", 0)
            cwes = ", ".join(details.get("cwes", [])) or "Aucune"
            st.success(f"**{name}** : OK — {count} Semgrep, {det} sign. (CWE: {cwes})")
        elif name == "GenAI":
            cwes = ", ".join(details.get("cwes", [])) or "Aucune"
            st.success(f"**{name}** : OK — {len(details.get('findings', []))} finding(s) (CWE: {cwes})")
        else:
            st.success(f"**{name}** : OK")
    elif status == "skipped":
        st.info(f"**{name}** : ignorée — {details.get('error', '')}")
    else:
        st.error(f"**{name}** : erreur — {details.get('error', 'erreur inconnue')}")


def main() -> None:
    st.set_page_config(page_title="SecureCode AI", page_icon="🔐", layout="wide")
    st.title("SecureCode AI")
    st.caption("Analyse pédagogique limitée à CWE-89, CWE-79 et CWE-22.")

    uploaded = st.file_uploader("Importer un fichier Java", type=["java"])
    default_code = st.session_state.get(
        "code",
        """public class Test {
    public static void main(String[] args) {
        String id = args[0];
        String query = "SELECT * FROM users WHERE id=" + id;
        System.out.println(query);
    }
}""",
    )
    code = st.text_area("Ou saisir le code Java", value=default_code, height=360)
    if uploaded is not None:
        code = uploaded.getvalue().decode("utf-8")
        st.text_area("Code importé", value=code, height=360, disabled=True)

    with st.sidebar:
        st.header("Configuration")
        enable_genai = st.checkbox("Activer GenAI (Ollama)", value=True)
        model = st.selectbox("Modèle Ollama", ["qwen2.5-coder:7b", "qwen2.5-coder:3b"])
        url = st.text_input("URL Ollama", "http://127.0.0.1:11434")
        timeout = st.number_input("Timeout (secondes)", min_value=1, value=120)

        if enable_genai:
            probe = OllamaClient(url, model, timeout=3.0)
            is_connected, status_message = probe.check_connection()
            if is_connected:
                st.success(f"🟢 {status_message}")
            else:
                st.warning(f"🔴 {status_message}")
                st.caption(
                    "💡 **Pour démarrer Ollama :**\n"
                    "1. Ouvre un terminal et tape : `ollama serve`\n"
                    "2. Ou lance l'application Ollama depuis Windows (icône dans la barre des tâches).\n"
                    "3. Si tu veux tester sans GenAI, décoche simplement la case ci-dessus."
                )

    if not st.button("Analyser le code", type="primary"):
        return
    if not code.strip():
        st.warning("Saisis ou importe du code Java avant de lancer l'analyse.")
        return

    # Réinitialisation propre de l'état de session avant chaque nouvelle analyse
    st.session_state["code"] = code
    for key in ("result", "findings", "fixed_code", "validation"):
        if key in st.session_state:
            del st.session_state[key]
    generator = OllamaClient(url, model, float(timeout)) if enable_genai else None
    with st.spinner("Analyse en cours..."):
        result = analyze(code, generator=generator)

    if result["status"] == "ok":
        st.success("Analyse terminée.")
    elif result["status"] == "unsupported_language":
        st.error("Langage non supporté : colle du code Java. JavaScript/Node.js n'est pas analysé.")
    else:
        st.warning("Analyse terminée avec au moins une erreur.")

    # Verdict global
    overall = result.get("overall", "unknown")
    if overall == "safe":
        st.success("✅ **Code sûr** — Aucune vulnérabilité détectée par Semgrep.")
    elif overall == "vulnerable":
        st.error("🚨 **Code vulnérable** — Des vulnérabilités ont été détectées.")
    elif overall == "uncertain":
        st.warning(
            "⚠️ **À vérifier** — Semgrep a signalé des vulnérabilités mais le classificateur ML "
            "les classe comme sûres. Revue manuelle recommandée."
        )

    left, right = st.columns(2)
    with left:
        st.subheader("Code analysé")
        st.code(numbered_code(code), language="java")
    with right:
        st.subheader("Résumé des approches")
        show_approach("Baseline", result["baseline"])
        show_approach("ML", result["ml"])
        show_approach("GenAI", result["genai"])

    # Une seule liste de findings — uniquement issus de Semgrep/signatures
    # Les numéros de ligne viennent toujours de Semgrep, jamais du LLM
    baseline_findings = [
        f for f in result["findings"]
        if f["approach"] in ("baseline", "deterministic")
    ]
    st.subheader(f"Findings ({len(baseline_findings)})")
    if not baseline_findings:
        st.info("Aucune vulnérabilité détectée par Semgrep.")
    for index, finding in enumerate(baseline_findings, 1):
        cwe = finding.get("cwe", "CWE inconnue")
        line = finding.get("line") or "non précisée"
        label = f"{cwe} (ligne {line})"
        with st.expander(label, expanded=index == 1):
            st.markdown(f"**CWE :** `{cwe}` | **Ligne :** `{line}` | **Sévérité :** `{finding.get('severity', 'ERROR')}`")
            # Affichage du contexte source avec mise en évidence de la ligne vulnérable
            ctx = finding.get("context_snippet")
            snip = finding.get("snippet")
            if ctx:
                st.caption("Extrait du code source analysé (ligne vulnérable marquée par `>`) :")
                st.code(ctx, language="java")
            elif snip and "requires login" not in snip.lower():
                st.caption(f"Ligne vulnérable ({line}) :")
                st.code(f"> {line:4d} | {snip}", language="java")

            # Explication enrichie par GenAI en priorité, sinon message Semgrep
            explanation = (
                finding.get("genai_explanation")
                or finding.get("explanation")
                or "Aucune explication."
            )
            st.markdown(f"**Explication pédagogique :**\n\n{explanation}")

    # Affichage du code corrigé unique (GenAI)
    genai_info = result.get("genai", {})
    fixed_code = genai_info.get("fixed_code")
    validation = genai_info.get("validation")
    if fixed_code:
        st.subheader("Code source complet corrigé (GenAI)")
        st.caption("Ce code réécrit intègre les remédiations de toutes les vulnérabilités détectées.")
        st.code(fixed_code, language="java")

        if validation:
            v_cols = st.columns(3)
            with v_cols[0]:
                j_ok = validation.get("javac", {}).get("ok")
                j_msg = validation.get("javac", {}).get("message", "")
                if j_ok:
                    st.success("Compilation javac : **SUCCÈS**")
                else:
                    st.error(f"Compilation javac : **ÉCHEC**\n\n`{j_msg}`")
            with v_cols[1]:
                b_ok = validation.get("baseline", {}).get("ok")
                b_msg = validation.get("baseline", {}).get("message", "")
                if b_ok:
                    st.success("Re-scan Semgrep : **0 vulnérabilité**")
                else:
                    st.error(f"Re-scan Semgrep : **Non sécurisé**\n\n`{b_msg}`")
            with v_cols[2]:
                m_ok = validation.get("ml", {}).get("ok")
                m_msg = validation.get("ml", {}).get("message", "")
                if m_ok:
                    st.success(f"Classification ML : **SAFE**\n\n`{m_msg}`")
                else:
                    st.warning(f"Classification ML : **Avertissement**\n\n`{m_msg}`")

            if j_ok and b_ok and m_ok:
                st.success("✨ **Correctif entièrement validé par javac, Semgrep et le classificateur ML.**")
            elif not j_ok:
                st.error("❌ **Échec de compilation javac** : ce code ne compile pas et ne peut pas être considéré comme un correctif valide.")
            elif not b_ok:
                st.warning("⚠️ **Correctif partiel** : des vulnérabilités résiduelles subsistent après re-scan Semgrep.")
            elif not m_ok:
                st.warning("⚠️ **À vérifier** : re-scan Semgrep = 0 mais le classificateur ML émet un avertissement.")

            if validation.get("validated"):
                st.success("✨ **Correctif entièrement validé par javac, Semgrep et le classificateur ML.**")
            else:
                st.error("⚠️ **Correctif non totalement validé : des erreurs ou failles résiduelles subsistent.**")

    st.download_button(
        "Télécharger le résultat JSON",
        data=json.dumps(result, indent=2, ensure_ascii=False),
        file_name="securecode_result.json",
        mime="application/json",
    )
    st.download_button(
        "Télécharger les findings CSV",
        data=findings_csv(result),
        file_name="securecode_findings.csv",
        mime="text/csv",
    )


if __name__ == "__main__":
    main()
