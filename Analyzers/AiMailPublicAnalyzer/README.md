# AiMailPublicAnalyzer

Analyzer Cortex indépendant, cascade à 2 modèles (Safe-vs-Suspicious puis
Suspicious-vs-Dangerous) entraînés sur un dataset public. Dispatché en
parallèle d'`AI_Mail_Analyzer` par `launch_cortex_ai_jobs`
(`Suspicious/Suspicious/cortex_job/cortex_utils/cortex_and_job_management.py`)
comme analyzer "ai_public" — purement informatif, ne modifie jamais
`case.results_ai`.

## 1. Déposer les poids et le vectoriseur

- Copier tes 2 fichiers `.pth` dans `models/` (voir `models/README.md` pour
  les noms exacts attendus).
- Copier le vectoriseur (même modèle que AIMailAnalyzer, réutilisable tel
  quel) :
  ```bash
  cp -r ../AIMailAnalyzer/vectorizers ./vectorizers
  ```

## 2. Builder les 2 images

Même pattern que AIMailAnalyzer : aucun service compose ne les build (ni
pour AIMailAnalyzer ni pour son propre serveur d'inférence, qui sont
également construits/lancés à la main sur cette codebase) — build manuel :

```bash
# Image client, référencée par Cortex (dockerImage dans analyzers.json)
docker build -t aimailpublicanalyzer:v1 .

# Image serveur d'inférence persistant
docker build -t aimailpublicanalyzer-inference:v1 -f inference_server/Dockerfile .
```

## 3. Lancer le serveur d'inférence (persistant)

```bash
docker run -d --name aimailpublic_inference --restart unless-stopped \
  -p 8091:8091 \
  aimailpublicanalyzer-inference:v1
```

Le port doit être publié sur toutes les interfaces (pas `127.0.0.1:...`) car
Cortex spawn `aimailpublicanalyzer:v1` dans un conteneur éphémère sur le
bridge Docker par défaut, qui joint ce serveur via la gateway du bridge
(`172.17.0.1:8091` par défaut — voir le docstring de
`inference_server/server.py` et `ai_mail_public_classifier.py` pour le
détail). Vérifier : `curl http://localhost:8091/health`.

## 4. Enregistrer l'analyzer dans Cortex

L'entrée catalogue a déjà été ajoutée dans le fichier réellement monté par
Cortex (`Analyzers/AIMailAnalyzer/analyzers.json` — un seul fichier monté
pour tous les analyzers custom AI, voir `deployment/compose_apps.yaml:184`),
pas besoin d'y retoucher. Il reste à :
1. Redémarrer/recréer le conteneur `cortex` pour qu'il relise le catalogue
   (`docker compose up -d --force-recreate --no-deps cortex`).
2. Activer l'analyzer `AiMailPublicAnalyzer` dans l'UI Cortex (comme pour
   n'importe quel nouvel analyzer du catalogue).
3. Vérifier qu'il apparaît dans `Analyzer.objects.all()` côté Suspicious
   après le prochain `sync_cortex`.

`Suspicious/settings.json` pointe déjà `integrations.cortex.analyzers.ai_public`
vers `AiMailPublicAnalyzer_1_0` (nom Cortex = `name` + `_` + `version` avec
points remplacés par `_`, soit `AiMailPublicAnalyzer` + `1.0` →
`AiMailPublicAnalyzer_1_0`).

## 5. Test bout-en-bout

Soumettre un mail de test, vérifier dans les logs `suspicious_celery` que
`launch_cortex_ai_jobs` dispatche bien les 2 jobs (personal + public), et
que le rapport public apparaît dans l'UI (`InvestigationAnalyzerReportCard.tsx`)
à côté du rapport personal, sans changer le verdict du cas.
