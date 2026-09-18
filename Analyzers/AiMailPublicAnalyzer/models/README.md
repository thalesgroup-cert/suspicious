# models/

Dépose ici tes 2 modèles entraînés sur le dataset public, avec exactement
ces noms de fichiers (attendus par `inference_server/server.py`) :

- `safe_suspicious_model.pth` — classifieur binaire Safe vs Suspicious
- `suspicious_dangerous_model.pth` — classifieur binaire Suspicious vs Dangerous

Même architecture que `AIMailAnalyzer/models/` : `ResNetMLP(input_dim=768,
output_dim=2)` sur des embeddings `paraphrase-multilingual-mpnet-base-v2`
(768 dimensions). Si tes poids ont été entraînés avec une autre dimension
d'entrée/sortie, il faut adapter `inference_server/server.py::_load_model`
en conséquence avant de démarrer le serveur.
