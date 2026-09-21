#!/usr/bin/env python3
"""Assemble a labeled body,label CSV for train_models.ipynb from PUBLIC
datasets, for environments with no real labeled mailbox to run
mailbox_to_csv.ipynb against (a fresh test/dev deployment).

Sources (all public, no auth):
  - SetFit/enron_spam       -- real internal-company email (ham) + injected spam
  - talby/spamassassin      -- the classic SpamAssassin public corpus (ham/spam)
  - zefang-liu/phishing-email-dataset -- an aggregate phishing corpus
                                (Nazario + Enron + CEAS + Nigerian-fraud + more)

Mapping to Suspicious's 8-class taxonomy (mail_analysis.SubClassificationName):
  LEGIT_INTERNAL_COMMUNICATION <- enron_spam ham         (literally internal
                                   company-to-company mail, by construction)
  LEGIT_EXTERNAL_COMMUNICATION <- spamassassin ham        (external senders to
                                   a personal inbox), minus anything that looks
                                   like a mailing list (see NEWSLETTER)
  SPAM                         <- enron_spam spam + spamassassin spam/spam_2
  NEWSLETTER                   <- spamassassin ham containing "unsubscribe"
                                   (real signal: a genuine ham/newsletter split
                                   is not something these corpora label
                                   directly, so this is the closest honest proxy)
  CLASSIC_PHISHING /
  WHALING_PHISHING /
  BLACKMAILING_PHISHING /
  CLONE_PHISHING                <- zefang-liu phishing pool, keyword-heuristic
                                    sub-split (see _classify_phishing below)

IMPORTANT — read before trusting this for anything but exercising the
pipeline: no public, untargeted phishing dump distinguishes whaling / clone /
blackmail from generic phishing (those require send-target and pairing
metadata these corpora don't carry). The 4-way phishing split below is a
keyword heuristic, not ground truth. It's good enough to give the
dangerous_model 4 non-empty, plausible classes to learn shape from for a test
deployment — it is NOT a substitute for real human-labeled examples if you
need that split to be accurate. LEGIT/SPAM/NEWSLETTER rest on firmer footing
(each source's own real label, or a real header/keyword signal).

Usage:
    python build_test_dataset.py [--out mailbox_dataset.csv] [--per-class 300]
"""
import argparse
import re
import sys
import urllib.request

import pandas as pd

_UA = {"User-Agent": "curl/8"}


def _fetch_parquet(url: str) -> pd.DataFrame:
    print(f"Fetching {url} ...", file=sys.stderr)
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read()
    import io
    return pd.read_parquet(io.BytesIO(data))


ENRON_URL = "https://huggingface.co/datasets/SetFit/enron_spam/resolve/refs%2Fconvert%2Fparquet/default/train/0000.parquet"
SPAMASSASSIN_URL = "https://huggingface.co/datasets/talby/spamassassin/resolve/refs%2Fconvert%2Fparquet/text/train/0000.parquet"
PHISHING_URL = "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/resolve/refs%2Fconvert%2Fparquet/default/train/0000.parquet"

_WS_RE = re.compile(r"[ \t]+")
_BLANKLINES_RE = re.compile(r"\n{3,}")


def _clean(text: str) -> str:
    text = str(text).replace("\r", "")
    text = _WS_RE.sub(" ", text)
    text = _BLANKLINES_RE.sub("\n\n", text)
    return text.strip()


_KW_BLACKMAIL = re.compile(
    r"bitcoin|btc wallet|webcam|compromising|embarrass|hacked your|sextort|"
    r"48 hours|pay within",
    re.I,
)
_KW_WHALING = re.compile(
    r"wire transfer|urgent.{0,15}(payment|transfer)|\bceo\b|\bcfo\b|gift card|"
    r"confidential.{0,15}transaction|invoice.{0,15}(payment|attached)",
    re.I,
)
_KW_CLONE = re.compile(
    r"verify your account|suspend|unusual activity|"
    r"update your (information|account|payment)|click here to (confirm|verify)|"
    r"your account (has been|will be)",
    re.I,
)


def _classify_phishing(text: str) -> str:
    """Keyword heuristic, checked in most-specific-first order. See module
    docstring for why this is a heuristic, not ground truth."""
    text = str(text)
    if _KW_BLACKMAIL.search(text):
        return "BLACKMAILING_PHISHING"
    if _KW_WHALING.search(text):
        return "WHALING_PHISHING"
    if _KW_CLONE.search(text):
        return "CLONE_PHISHING"
    return "CLASSIC_PHISHING"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="mailbox_dataset.csv")
    ap.add_argument("--per-class", type=int, default=300, help="cap for the well-populated classes")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rows = []  # (body, label)

    # ---- Enron-Spam: internal ham + a spam pool ----
    enron = _fetch_parquet(ENRON_URL)
    enron_body = (enron["subject"].fillna("") + "\n\n" + enron["message"].fillna(""))
    enron_ham = enron_body[enron["label_text"] == "ham"].sample(
        n=min(args.per_class, (enron["label_text"] == "ham").sum()), random_state=args.seed
    )
    enron_spam = enron_body[enron["label_text"] == "spam"].sample(
        n=min(args.per_class, (enron["label_text"] == "spam").sum()), random_state=args.seed
    )
    rows += [(_clean(b), "LEGIT_INTERNAL_COMMUNICATION") for b in enron_ham]
    rows += [(_clean(b), "SPAM") for b in enron_spam]
    print(f"enron_spam: {len(enron_ham)} internal, {len(enron_spam)} spam", file=sys.stderr)

    # ---- SpamAssassin: external ham (+newsletter split) and more spam ----
    sa = _fetch_parquet(SPAMASSASSIN_URL)
    ham_mask = sa["group"].isin(["easy_ham", "hard_ham"])
    spam_mask = sa["group"].isin(["spam", "spam_2"])
    ham_text = sa.loc[ham_mask, "text"].astype(str)
    newsletter_mask = ham_text.str.contains("unsubscribe", case=False, na=False)

    newsletter_pool = ham_text[newsletter_mask]
    external_pool = ham_text[~newsletter_mask]
    spam_pool = sa.loc[spam_mask, "text"].astype(str)

    n_ext = min(args.per_class, len(external_pool))
    n_spam2 = min(args.per_class, len(spam_pool))
    rows += [(_clean(b), "LEGIT_EXTERNAL_COMMUNICATION") for b in external_pool.sample(n=n_ext, random_state=args.seed)]
    rows += [(_clean(b), "NEWSLETTER") for b in newsletter_pool]  # small pool, take all
    rows += [(_clean(b), "SPAM") for b in spam_pool.sample(n=n_spam2, random_state=args.seed)]
    print(
        f"spamassassin: {n_ext} external, {len(newsletter_pool)} newsletter, {n_spam2} spam",
        file=sys.stderr,
    )

    # ---- Phishing pool, heuristic 4-way sub-split ----
    ph = _fetch_parquet(PHISHING_URL)
    phishing_texts = ph.loc[ph["Email Type"] == "Phishing Email", "Email Text"].dropna().astype(str)
    buckets: dict[str, list[str]] = {
        "CLASSIC_PHISHING": [], "WHALING_PHISHING": [], "BLACKMAILING_PHISHING": [], "CLONE_PHISHING": [],
    }
    for t in phishing_texts:
        buckets[_classify_phishing(t)].append(t)

    for label, texts in buckets.items():
        cap = args.per_class if label == "CLASSIC_PHISHING" else len(texts)
        cap = min(cap, len(texts))
        sample = pd.Series(texts).sample(n=cap, random_state=args.seed) if cap < len(texts) else pd.Series(texts)
        rows += [(_clean(b), label) for b in sample]
        print(f"phishing/{label}: {cap} (of {len(texts)} matched)", file=sys.stderr)

    df = pd.DataFrame(rows, columns=["body", "label"])
    df = df[df["body"].str.len() > 20]  # drop near-empty bodies
    df.to_csv(args.out, index=False)

    print(f"\nWrote {len(df)} rows to {args.out}", file=sys.stderr)
    print(df["label"].value_counts(), file=sys.stderr)


if __name__ == "__main__":
    main()
