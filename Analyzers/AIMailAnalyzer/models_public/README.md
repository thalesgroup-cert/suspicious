# models_public/

Weights for the "public" comparison model exposed by the inference server's
`variant=public` slot (see `inference_server/server.py`).

**These 5 `.pth` files are currently a plain copy of `../models/`** — a
placeholder so the two-model dispatch/UI path is provably wired end to end
before real public weights exist. Same architecture, same taxonomy, so no
code change is needed to swap them: drop in `.pth` files trained on a public
mail dataset with the exact same filenames as `../models/`
(`safe_suspicious_30_epochs_model.pth`, `spam_dangerous_30_epochs_model.pth`,
`safe_30_epochs_model.pth`, `unwanted_30_epochs_model.pth`,
`dangerous_30_epochs_model.pth`) and restart the inference server — that's
the whole swap.

Until real public weights land here, the "public" card in the UI will always
agree with the "personal" card (same weights) — that's expected, not a bug.
