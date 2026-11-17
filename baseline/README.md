# Baseline SAST (Semgrep CE)

Règles **taint** (source non fiable vers fonction dangereuse) pour Java, une par CWE :

| Fichier | CWE | Sources | Sinks |
|---|---|---|---|
| `rules/cwe89_sqli.yml` | CWE-89 | `getParameter`, `getHeader`, `getCookies`, `getQueryString`… | `executeQuery`, `execute`, `prepareStatement`, `JdbcTemplate.query*`… |
| `rules/cwe79_xss.yml` | CWE-79 | idem | `response.getWriter().print/println/write/printf/format…` |
| `rules/cwe22_path_traversal.yml` | CWE-22 | idem | `new File(...)`, `FileInputStream`, `FileOutputStream`, `Paths.get` |

Assainisseurs : `ESAPI encodeFor*`, `escapeHtml*`, `encodeForSQL`. Propagation à travers `add`, `put`, `append`.

## Exécuter

```bash
python baseline/run_semgrep.py                 # écrit eval/results/baseline_predictions.csv + findings.json
python eval/evaluate.py --pred eval/results/baseline_predictions.csv --split test
```

## Méthode (rigueur)

- Les règles ont été écrites et ajustées en regardant **uniquement le jeu d'entraînement**. Le jeu de test n'a été évalué qu'une fois, à la fin.
- Seuls des changements généraux ont été faits (suivi dans les collections, sinks à toute position d'argument). Aucun réglage propre à un fichier.

## Résultats (jeu de test, 246 fichiers)

| CWE | TP | FP | FN | précision | rappel | F1 | taux FP |
|---|---|---|---|---|---|---|---|
| CWE-89 | 55 | 45 | 0 | 0.55 | 1.00 | 0.71 | 0.24 |
| CWE-79 | 46 | 75 | 3 | 0.38 | 0.94 | 0.54 | 0.38 |
| CWE-22 | 24 | 25 | 3 | 0.49 | 0.89 | 0.63 | 0.11 |

## Analyse des erreurs

- **Rappel élevé, précision faible** : la baseline trouve presque toutes les failles mais signale aussi beaucoup de versions sûres.
- **Faux positifs CWE-89 / CWE-22** : tous sur des versions sûres où la donnée est écartée de façon subtile (ex. `valuesList.get(1)` renvoie une constante). Semgrep ne suit pas les indices de liste ni les branches mortes (ex. `(7*42)-num > 200`).
- **Faux positifs CWE-79** : une grande part vient de fichiers CWE-22 qui affichent le nom du fichier dans la réponse. Le XSS y est réel, mais le Benchmark ne les étiquette que CWE-22 (limite d'étiquetage, fichiers multi-vulnérabilités).
- **Limite** : analyse intra-procédurale, sans exécution du code. Ce n'est pas un audit exhaustif.
