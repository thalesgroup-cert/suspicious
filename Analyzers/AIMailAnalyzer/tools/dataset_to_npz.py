"""Convert the test bed's dataset.pkl into a pickle-free .npz for the evaluation regression.

    python tools/dataset_to_npz.py <dataset.pkl> <out.npz> [--encoder <sentence-transformers dir>]

The pickle is our own trusted export (the test bed made it); it is read with pandas, which this
tool alone needs. The .npz holds `embeddings` (float32 (n, 768), the stored `mpnet_vect`: one
encoder pass over the body, so the first 128 tokens), `folders` (fixed-width unicode) and, when
the pickle has a `hash` column, `mail_ids`. With --encoder it also re-embeds each body in the two
chunk forms of Ruling E11, `embeddings_words90` and `embeddings_tokens`, and prints how close a
plain encoder pass gets to the stored vectors. Only counts and statistics are printed; no mail
text is written or printed. Keep the output outside the repository (Ruling E2). Nothing in
training/ or inference_server/ imports this file.
"""
import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _cosine(a, b):
    return (a * b).sum(1) / (np.linalg.norm(a, axis=1) * np.linalg.norm(b, axis=1))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dataset")
    ap.add_argument("out")
    ap.add_argument("--encoder", help="sentence-transformers model directory")
    args = ap.parse_args(argv)

    import pandas as pd

    df = pd.read_pickle(args.dataset)
    out = {"embeddings": np.vstack(df["mpnet_vect"].to_numpy()).astype(np.float32),
           "folders": df["folder"].to_numpy().astype(str)}
    if "hash" in df:
        out["mail_ids"] = df["hash"].to_numpy().astype(str)
    print(f"rows {len(df)} dim {out['embeddings'].shape[1]}")
    for folder, n in sorted(df["folder"].value_counts().items()):
        print(f"  {folder} {n}")

    if args.encoder:
        import torch
        from sentence_transformers import SentenceTransformer

        from training.recipe import chunk_mean_embedding

        torch.set_num_threads(8)
        enc = SentenceTransformer(args.encoder, device="cpu")
        bodies = df["body"].tolist()
        plain = np.asarray(enc.encode(bodies, batch_size=32), dtype=np.float32)
        cos = _cosine(plain, out["embeddings"])
        print(f"plain encoder pass vs stored vectors: cosine min {cos.min():.5f} "
              f"mean {cos.mean():.5f}")
        for key, by_tokens in (("embeddings_words90", False), ("embeddings_tokens", True)):
            out[key] = np.vstack([chunk_mean_embedding(enc, b, by_tokens=by_tokens)
                                  for b in bodies]).astype(np.float32)
            print(f"{key}: cosine to stored vectors mean "
                  f"{_cosine(out[key], out['embeddings']).mean():.5f}")

    np.savez(args.out, **out)
    print(f"wrote {', '.join(out)}")


if __name__ == "__main__":
    main()
