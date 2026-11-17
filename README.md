# SecureCode AI

Assistant d'analyse de code Java qui détecte des vulnérabilités de laboratoire, les catégorise par CWE et explique comment les corriger.

> Projet de contrôle continu, module IA pour la Cybersécurité (EMSI). Usage strictement pédagogique : données publiques (NIST SARD / Juliet, OWASP Benchmark) et scénarios de laboratoire. Aucun scan d'une cible tierce. Ce n'est pas un audit de sécurité exhaustif.

## Périmètre

- **Langage** : Java
- **CWE ciblés** : CWE-89 (SQL Injection), CWE-79 (XSS), CWE-22 (Path Traversal, optionnel)
- **Entrée** : extrait de code Java
- **Sortie** : findings (CWE, ligne, explication, correctif proposé, tests)

## Trois approches comparées

| Approche | Rôle | Dossier |
|---|---|---|
| Baseline SAST | Règles Semgrep CE / motifs | `baseline/` |
| ML | TF-IDF + classificateur CWE (scikit-learn) | `ml/` |
| GenAI | LLM local (Ollama) : explication + correctif validé | `genai/` |

## Structure

```
data/        scripts de téléchargement/préparation (données brutes non versionnées)
baseline/    règles SAST
ml/          features TF-IDF, entraînement, modèle
genai/       prompts, client Ollama, validation des correctifs
pipeline/    analyse de bout en bout
app/         interface Streamlit
tests/       tests pytest
eval/        métriques, comparaison, analyse des erreurs
report/      rapport final et supports de soutenance
```

## Installation

```bash
python -m venv .venv
source .venv/bin/activate        # Windows : .venv\Scripts\activate
pip install -r requirements.txt
```

Prérequis externes : Java (JDK 17+), Git, [Ollama](https://ollama.com) (pour l'étape GenAI).

## Données

| Source | Usage | Lien |
|---|---|---|
| NIST SARD / Juliet Java | exemples vulnérables et corrigés | https://samate.nist.gov/SARD/ |
| OWASP Benchmark | cas Java annotés | https://owasp.org/www-project-benchmark/ |

Licences/conditions d'usage, schéma et méthode de partition : à compléter en Étape 2.

## Feuille de route (9 semaines)

- [x] S1 Choix CWE + langage, squelette du dépôt
- [x] S2 Préparation des données, split train/test
- [x] S3 Baseline SAST
- [x] S4 Classificateur ML
- [ ] S5 Aide à la correction GenAI
- [ ] S6 Pipeline d'analyse + tests
- [ ] S7 Tableau des findings (interface)
- [ ] S8 Comparaison + analyse des faux positifs
- [ ] S9 Démonstration DevSecOps, rapport

## Évaluation

Precision / recall par CWE, taux de faux positifs, taux de correctifs validés. Le jeu de test est séparé de l'entraînement dès le départ (pas de data leakage).

## Équipe

- Étudiant 1 : _à compléter_
- Étudiant 2 : _à compléter_
