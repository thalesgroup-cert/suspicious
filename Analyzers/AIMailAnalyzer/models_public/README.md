# models_public/

Weights for the "public" comparison model, served by the inference server's
`variant=public` slot (see `inference_server/server.py`).

**No weights are committed here.** Drop `.pth` files trained on a public mail
dataset with exactly these names in this folder (same architecture and taxonomy
as `../models/`, so no code change is needed):

- `safe_suspicious_30_epochs_model.pth`
- `spam_dangerous_30_epochs_model.pth`
- `safe_30_epochs_model.pth`
- `unwanted_30_epochs_model.pth` (optional)
- `dangerous_30_epochs_model.pth`

The folder is bind-mounted into the `ai_inference` container, and the server
re-checks it periodically (or immediately on `POST /reload`), so no restart is
needed.

Until real public weights are here the `public` variant is simply **unavailable**:
`GET /health` lists it as not ready and a `variant=public` request fails with a
503 naming the missing files. (An earlier placeholder copied `../models/` here;
a truncated copy of those files looked loadable but was not, which is why the
server now reports per-file load errors instead.)
