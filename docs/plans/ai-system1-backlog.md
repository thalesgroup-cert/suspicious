# System 1 second opinion and challenge triage (backlog)

Status: backlog. Start after Plans E, F and G of the `ai_model` connector are merged.
Origin: two ideas raised on 2026-11-07, read against a research summary on TypeSafe's Jev
model (an AI-generated French report, not in the repository).

## What the source says, and what holds up

- **Jev is real.** TypeSafe's Jev is a non-generative decision model. It takes a state and a
  set of typed questions and returns, per question:
  - Choice: the chosen option, per-option probabilities and a confidence value.
  - Noul (yes/no): a probability.
  - Score: an ordinal level with probabilities.
- **Jev itself is not usable here.** The weights are closed and the model is served only
  through a cloud API, while mail content must stay local.
- **Not verified, or contradicted.**
  - The cited survey ("The Hitchhiker's Guide to System 1 Models", arXiv:2610.33775) was not
    found.
  - OpenJev is described elsewhere as a wrapper around an ordinary chat model, with no RLCD
    calibration and no stated license. The report calls it an open RLCD implementation.
  - "Tachyone" was not found.
  - The latency and cost figures are the vendor's own.
  - The report carries text-generator artefacts (`[span_163](start_span)`).
- **What we keep, whatever the source's accuracy.**
  1. Typed questions asked about one state, each answer a probability.
  2. The confidence formulas.
     - Choice: `(p_max - 1/n) / (1 - 1/n)`.
     - Score: `max(0, 1 - MAD / MAD_unif)`, where MAD is the probability-weighted distance to
       the most likely level.
  3. The model reads literally and cannot count or compare dates, so Python code computes
     those facts first.
  4. Adversarial text moves the probabilities. A phishing mail is adversarial by definition,
     so the model is never the only authority.
  5. Evaluation happens in shadow, against analyst verdicts.

## A home-made "Jev" for this platform

- **Model.** A local multilingual NLI cross-encoder; the candidate is an mDeBERTa-v3-base XNLI
  checkpoint, to be chosen by measurement.
  - The structured state is the premise and each question is a hypothesis.
  - Noul is the entailment probability.
  - Choice asks one hypothesis per option, with a softmax across the options.
  - Score is a Choice over ordered levels, plus the confidence formula above.
- **Determinism.** The weights are fixed and nothing is sampled, so the same input and version
  always give the same answer.
- **Calibration.** Each question gets its own temperature, fitted on ledger labels with the
  Plan E machinery (`training/gate.py`: ECE and Wilson intervals).
- **Fine-tuning.** Only when labels allow (SetFit or a cross-encoder fine-tune, item 10 of the
  analyzer backlog).
- **Hardware.** CPU only, on the existing host. No vLLM, Triton or GPU.

## H1: two-way analysis, a second opinion on the mail verdict

- **State.** Subject, sender display name and address, Reply-To, URL domains, attachment types
  and body chunks.
  - Python computes the deterministic facts and passes them as text: SPF/DKIM/DMARC result,
    display name against sender domain, link text against target domain, and the link count.
- **Draft questions.**
  - Noul:
    - asks for credentials, payment or gift cards
    - urgency or threat
    - impersonates a brand or an internal service
    - newsletter with an unsubscribe path
    - ordinary internal business exchange
  - Choice: the phishing type, using the 4-way head's taxonomy.
  - Score: risk from 1 to 5.
- **Combination rule.** It is deterministic and asymmetric, because Dangerous called Safe is
  the costly error.
  - Model 2 agrees with model 1: keep the verdict and record the agreement.
  - Model 2 says more dangerous, with confidence at or above `t_up`: raise the case to
    Suspicious for an analyst, never straight to Dangerous.
  - Model 2 says safer: flag only, never downgrade.
  - Either model has low confidence: no change.
- **First step, offline.**
  - Run the questions zero-shot on the 505-mail dataset.
  - Measure how often both models are wrong on the same mails.
  - Measure the change in Dangerous called Safe inside Plan E's grouped cross-validation.
  - Stop if the errors overlap: a second model only helps when it fails on different mails.
- **Cheaper alternative to compare first.** Add the subject, sender, URL and header features
  to model 1 (analyzer backlog item 9).
- **Rollout.** Through Plan F's shadow path (dual classify, would-be verdict through the
  scoring engine), not a new mechanism.
- **Latency.** The work runs in Celery and the budget is the current classify, 844 ms on a
  chunk-mean bundle. Questions multiplied by chunks multiply the number of forward passes, so
  cap the chunks.

## H2: deterministic challenge triage, deciding the TheHive alert

Today a challenge stores the reporter's proposal and reason, and the challenge flow raises the
TheHive alert. Plan D records challenge proposals in the label ledger. Read the current alert
trigger in the code before designing.

- **Decision table.**
  - Ordered rules, first match wins, each emitting a reason code (the pattern of
    `score_process/scoring/explanation/`).
  - Outputs: `ALERT` (send to TheHive now) or `ANALYST` (queue, no alert).
  - No auto-close in the first version.
- **Fact inputs.**
  - Case verdict and model 1's calibrated probability.
  - Campaign size and the folder labels of its members.
  - Sender on an allowlist or a blocklist.
  - MISP and analyzer hits.
  - Earlier challenges on the same campaign.
- **Typed questions on the reporter's reason text.**
  - Choice, the challenge type: says false positive, says missed threat, says
    clicked/opened/entered credentials, other.
  - Noul: "the reporter states they clicked a link, opened an attachment or entered
    credentials".
- **Rules no model output can override.**
  - Any non-trivial probability of a compromise claim: `ALERT`.
  - Case Dangerous, or a campaign with Dangerous members: `ALERT`.
  - Reporter says false positive: never `ALERT`, always `ANALYST`, because changing the verdict
    is the analyst's decision.
  - Reporter says missed threat and a fact signal agrees: `ALERT`; otherwise `ANALYST`.
  - Low confidence anywhere: `ANALYST`.
- **Untrusted text.** The reason text is untrusted and can be crafted, so the model can only
  escalate. It never suppresses an alert that a fact rule demands.
- **Audit.** Store, per decision, the rule-set version, the question version, the
  probabilities and the reason code.
- **Rollout.**
  1. A rules-only version first, with no model.
  2. Then the questions, in shadow, beside the analysts' actual actions.
  - The exit criterion is numeric and agreed before shadow starts, for example no missed
    `ALERT` where an analyst alerted, over a fixed number of weeks.

## Order and prerequisites

1. Plans E, F and G merged.
2. H2 rules-only. It is the smallest piece and is useful without any model.
3. Spike: measure the NLI model on CPU (latency, French and English) and its zero-shot answers
   to the H1 questions on the 505 mails.
4. H2 questions in shadow.
5. H1 offline overlap study, then H1 in shadow through Plan F.

## Open points for the owner

- Who owns the thresholds (`t_up`, the confidence floors) and who reviews shadow disagreements.
- Whether replying to the reporter automatically is wanted at all.

## Sources

- TypeSafe Jev, community summaries:
  - https://openrouter.ai/docs/guides/community/jev.md
  - https://nexos.ai/blog/what-is-jev/
- OpenJev, described as a chat-model wrapper:
  - https://aisuccesslabjuliangoldie.com/blog/jev-vs-openjev/
  - https://pub.towardsai.net/jev-and-rlcd-architecture-open-source-models-and-practical-agent-use-cases-bd8ab990fc44
