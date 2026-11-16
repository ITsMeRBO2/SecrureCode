# Données

## Source principale : OWASP Benchmark v1.2 (Java)

- Dépôt : https://github.com/OWASP-Benchmark/BenchmarkJava
- Licence : GNU GPL v2 (usage pédagogique, données de laboratoire). Les données brutes ne sont pas versionnées : `prepare_data.py` les télécharge.
- Contenu : 2 740 servlets Java, chacun annoté dans `expectedresults-1.2.csv` (catégorie, vulnérable oui/non, CWE).

### CWE retenus

| Catégorie Benchmark | CWE | Cas vulnérables | Cas sûrs |
|---|---|---|---|
| sqli | CWE-89 | 272 | 232 |
| xss | CWE-79 | 246 | 209 |
| pathtraver | CWE-22 | 133 | 135 |

Total : 1 227 fichiers.

## Schéma de `data/processed/dataset.csv`

| Colonne | Description |
|---|---|
| test_name | identifiant du cas (ex. BenchmarkTest00008) |
| category / cwe | catégorie Benchmark et CWE associé |
| vulnerable | True = vulnérable, False = version sûre |
| code_raw | code Java original (baseline SAST, affichage, LLM) |
| code_clean | code nettoyé (ML) |
| split | train ou test |

## Méthode de partition

- Split **par fichier** (un fichier = un cas, jamais coupé), 80 % train / 20 % test, `random_state=42`.
- Stratifié par (CWE, vulnérable) : chaque CWE garde ses proportions dans les deux jeux.
- Le jeu de test n'est utilisé que pour l'évaluation finale. Réglages et validation croisée : sur le train uniquement.

## Prévention du data leakage

`code_clean` retire : commentaires, annotation `@WebServlet("/sqli-00/...")` (elle contient la catégorie), numéros de test (`BenchmarkTest00008` devient `TestCase`).

## Limites connues

- Les cas du Benchmark sont générés à partir de gabarits, donc beaucoup se ressemblent. Une bonne performance ici ne prouve pas la généralisation à du code réel. À mentionner dans le rapport.
- Optionnel : valider sur NIST SARD / Juliet Java (https://samate.nist.gov/SARD/) comme jeu externe.

## Reproduire

```bash
python data/prepare_data.py
pytest tests/test_data.py
```
