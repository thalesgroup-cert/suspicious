# AI / ML Analyzers

`Analyzers/AIMailAnalyzer/` is the machine-learning email classifier exposed to
the platform as a Cortex analyzer.

## How it works

- **Embeddings:** a Sentence Transformers model
  (`paraphrase-multilingual-mpnet-base-v2`) turns email text into vectors.
- **Classifier:** an ensemble of custom `ResNetMLP` networks (several 2-class
  models plus a 4-class danger model) predicts the verdict from the embeddings.
- **Similarity:** ChromaDB stores vectors so finalised cases can be matched
  against prior cases for semantic similarity.

## Source

| Module | Role |
|---|---|
| `mail_analysis.py` | Entry point for analysing an email |
| `ai_mail_classifier.py` | Classifier wrapper |
| `ResNetMLP.py` | The neural network definition |
| `health.py` | Health check |

These modules are auto-documented in the
[Python Code Reference](../reference/index.md).
