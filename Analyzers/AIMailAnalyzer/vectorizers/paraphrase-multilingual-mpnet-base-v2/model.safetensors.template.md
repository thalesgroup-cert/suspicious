# Download the official Model

Download to the folder this file: [Safetensors Model](https://huggingface.co/sentence-transformers/paraphrase-multilingual-mpnet-base-v2/blob/4328cf26390c98c5e3c738b4460a05b95f4911f5/model.safetensors)

Use this commit (`4328cf26390c98c5e3c738b4460a05b95f4911f5`, the `ENCODER_REVISION` of `inference_server/Dockerfile`): another revision changes the server's `encoder_hash`, and registered bundles will then not load.
