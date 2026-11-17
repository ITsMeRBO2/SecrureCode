# Classificateur ML (TF-IDF + scikit-learn)

## Principe

- **Entrée** : code Java (version nettoyée, voir `data/README.md`), chaînes de caractères masquées (`"STR"`).
- **Features** : TF-IDF sur les tokens du code (identifiants, nombres, symboles), n-grammes 1 à 3.
- **Classes** : `CWE-89`, `CWE-79`, `CWE-22` (fichier vulnérable) ou `SAFE`.
- **Modèle retenu** : régression logistique (C=100, n-grammes jusqu'à 3), choisi par validation croisée 5 plis stratifiée **sur le train uniquement**.
- **Explication** : `ml_model.explain(pipe, code)` renvoie la classe, un score de confiance (softmax, non calibré) et les tokens qui ont le plus poussé vers cette classe.

## Exécuter

```bash
python ml/train.py        # CV, entraînement, prédictions, modèle dans ml/models/
python eval/evaluate.py --pred eval/results/ml_predictions.csv --split test
```

## Méthode (rigueur)

- Le TF-IDF est réajusté dans chaque pli (Pipeline) : pas de fuite d'IDF.
- Les prédictions « train » sont **out-of-fold** ; le jeu de test n'est évalué qu'une fois, avec le modèle final.
- Même fichier `evaluate.py` et mêmes métriques que la baseline : comparaison équitable.

## Résultats (jeu de test, 246 fichiers)

| CWE | Baseline précision / rappel | ML précision / rappel |
|---|---|---|
| CWE-89 | 0.55 / 1.00 | 1.00 / 1.00 |
| CWE-79 | 0.38 / 0.94 | 0.98 / 0.96 |
| CWE-22 | 0.49 / 0.89 | 1.00 / 1.00 |

Validation croisée (train, F1 macro) : 0.983 ± 0.009.

## ⚠️ Fuite de signature : ce que ces scores veulent dire

Premier essai sur le code brut : F1 macro de **1.000** en validation croisée. Trop beau : en regardant les features les plus importantes, le modèle lisait des constantes absurdes générées par le Benchmark (`"alsosafe"`, `"barbarians_at_the_gate"`, `"This_should_always_happen"` pour la classe SAFE, `"bobs_your_uncle"` pour CWE-22). Ces mots n'existent pas dans du vrai code.

Correction : masquage du contenu des chaînes. Le score baisse (0.983 en CV) et les features deviennent sensées : `get ( 0` pousse vers « vulnérable » et `get ( 1` vers « sûr » (accès à un élément de liste contenant la donnée utilisateur ou une constante), exactement le cas que Semgrep ne sait pas suivre.

L'ablation (`ml_raw_predictions.csv`, code brut) est conservée pour documenter l'écart.

**Limite importante** : même masqué, le modèle apprend les **gabarits du générateur** du Benchmark (indices de liste, branches mortes, constantes numériques). Un score proche de 1 mesure donc la régularité du jeu de données, **pas** la capacité à détecter des failles dans du code réel. Un jeu externe (NIST Juliet) est nécessaire pour mesurer la généralisation. À écrire dans la section « Limites » du rapport.

## Fichiers

| Fichier | Rôle |
|---|---|
| `ml_model.py` | pipeline, masquage des chaînes, explication, sauvegarde/chargement |
| `train.py` | CV, entraînement, prédictions, ablation |
| `models/securecode_ml.joblib` | modèle entraîné (~150 Ko) |
| `../eval/results/ml_*.{csv,json,txt}` | prédictions, scores CV, features, métriques |
