# LLM Council Transcript: Verdict Narration Model

**Date:** 2026-09-11
**Subject:** Pressure-testing a proposed generative "verdict narration" model for Suspicious (Thales CERT phishing/threat-analysis platform).

## Original question (as brought by the user)

> How can we come up with a training of a model like the AIMailAnalyzer one but for the verdict explanation? Could we brainstorm this and have council? Look at Hugging Face and other official documentation for what's best for our case.

Scoping answers gathered before framing: on-prem deployment required; teacher-distillation training strategy; a detailed doc on training it for open-source publication is the end deliverable; teacher model may be a hosted API (Claude/GPT) even though the resulting dataset won't be redistributable; the model must never independently form or alter a verdict — it ingests full analyzer reports plus the case's already-computed score/confidence/verdict as fixed facts and produces a narrative report + conclusion for non-technical readers.

## Framed question (given to all advisors verbatim)

> Pressure-test the design for a new "verdict narration" model for the Suspicious phishing-analysis platform (Thales CERT). Context: a rule-based structured verdict-explanation system already ships (deterministic, no LLM) and must stay authoritative for the actual band/score/confidence. This new project is a generative add-on for the SOC roadmap's P4 item: a rich, plain-language report + conclusion for non-technical stakeholders, synthesizing ALL analyzer reports (VT, GTI, MISP, etc. full report_full/enrichment data) plus the AI_Mail_Analyzer's detailed output for mail cases, grounded by the case's already-computed score/confidence/verdict (given as fixed input, never re-derived by the model).
>
> Proposed design:
> - Training strategy: teacher distillation — a hosted LLM (Claude or GPT via API) generates target "report + conclusion" text from structured case facts (historical/synthetic cases), used to fine-tune a small open-weight model.
> - Student model candidate: Qwen2.5-7B-Instruct (Apache-2.0 license), via LoRA/QLoRA, chosen for permissive licensing since the training pipeline/code should be publishable for open-source purposes (the resulting distilled dataset itself will NOT be freely redistributable due to the hosted teacher's ToS — student model + code will be).
> - Deployment: fully on-prem inference (no case data leaves the network at inference time); the one-time training run may use rented/external GPU compute since only historical/synthetic case shapes (not necessarily live sensitive data) go to the teacher.
> - Safety constraint: the verdict/band/score are fixed facts in the prompt the model must narrate, never contradict or re-derive — explicitly to avoid recreating a "second black-box verdict" that could disagree with the deterministic engine (a bug class the team just found and fixed in the rule-based system's whole-branch review).
>
> Questions for the council: Is this the right overall architecture? Is teacher distillation + LoRA fine-tuning on a 7B open model the right call versus alternatives (e.g., skip training and just prompt a locally-hosted general instruct model at inference; use a smaller/larger student; use a different training strategy like RAG instead of fine-tuning)? Is the "fixed verdict, never re-derived" safety property enforceable in practice for a generative model, and what would break it? What's underspecified or risky that we haven't considered? Is the open-source-redistribution framing (open model + open code, teacher-generated data not redistributable) coherent, or does it create hidden problems? What data volume/quality would actually be needed to make this fine-tune worthwhile versus not bothering with training at all?
>
> Team/resource context: effectively a solo technical lead driving this via an AI coding agent, small CERT team, no dedicated ML infra, prior experience only with training a small classifier (not a generative model) once, on CPU, in ~9 minutes.

---

## Step 2: Advisor Responses

### The Contrarian

The fatal flaw is right in your own setup, and you already named it: you just finished fixing a bug where generated text contradicted an updated verdict. You are now proposing to build a system whose entire job is generating text from case facts, via a fine-tuned model, and asserting "fixed verdict, never re-derived" as if that's a property you can specify into existence. It isn't. LoRA fine-tuning on teacher outputs does not teach a model to treat the verdict field as immutable — it teaches statistical association between case facts and narrative style, including the teacher's phrasing of confidence. A 7B model under distribution shift (a MISP report shape it never saw in training, a classifier score near a decision boundary, an analyzer that errored out) will happily hedge, soften, or flatly restate a different band in prose, because nothing in LoRA training enforces hard constraints — it's gradient descent on token likelihood, not a grammar. Your only real enforcement mechanism is post-hoc: template-lock the verdict/score/confidence as literal injected strings never generated by the model, and regex/parse the output to reject or regenerate anything that emits a competing number or band word. That's not a training-time solution, it's an output-filter solution — which means the fine-tune is buying you narrative fluency, not safety, and the safety has to be built anyway, in the same deterministic style as the system you're augmenting.

Second flaw: "solo lead + AI coding agent + one prior CPU classifier" is not a team that safely ships a hallucination-prone generative layer into a CERT tool. Nobody here has bandwidth to build and maintain that output-validation harness rigorously. Skip the fine-tune; that harness is the actual project.

### The First Principles Thinker

First, define the actual job: a translator from structured facts to prose, with a hard non-negotiable — it must never alter, hedge against, or contradict the verdict it's handed. That's not a modeling problem. That's a templating problem wearing a modeling costume.

You already have the deterministic system. The generative add-on's only real job is fluency: turning terse rule outputs and analyzer JSON into readable narrative for non-technical stakeholders. Fluency is exactly what a general-purpose instruct model already does at the 99th percentile out of the box, zero training. The entire distillation pipeline — teacher generation, LoRA, rented GPUs, on-prem deployment, open-source packaging — is being built to solve a problem ("does the model sound natural and cover our report sections") that a good system prompt plus a few hand-written examples already solves.

Ask what the fine-tune is actually buying you. It's not knowledge (analyzer data goes in the prompt either way). It's not verdict-fidelity (a fine-tuned 7B is more likely to drift than a well-constrained prompted model, because fine-tuning teaches it patterns from training data that can generalize past your guardrails — the exact opposite of what "sole authority on verdict" needs). The only thing distillation reliably buys is house style, and you don't need gradient descent for house style — you need a template and a linter.

So the load-bearing question isn't "LoRA vs RAG vs bigger model." It's: have you tried prompting Qwen2.5-7B (or Llama, or Mistral) with structured input and a strict output contract, validated the output with a deterministic checker (does every number/verdict/entity in the generated text match the source facts?), and only reached for training after that demonstrably fails? Nobody described that experiment. Skipping straight to teacher-distillation is solving an assumed problem, not an observed one — a solo lead should not spend rented GPU hours and weeks of pipeline engineering before running the free version first.

### The Expansionist

The upside case here is being drastically undersold by framing this as "add-on report generator." Let me push on where this actually goes.

First: the fixed-verdict architecture isn't just a safety constraint, it's a moat. Most vendors bolt LLM narration directly onto their scoring, which is why they can't touch it without breaking trust — this team has decoupled verdict-authority from narration-authority. That decoupling is the reusable asset. Once it exists, the same pipeline narrates ANY structured decision the platform makes, not just phishing verdicts: malware triage, incident timelines, threat-intel enrichment summaries, even cross-case pattern reports for a CERT lead who wants "what happened this week" in prose. Scope the fine-tune's input schema generically now (verdict + evidence graph + confidence, not "phishing-specific fields") and this becomes the narration layer for the whole platform, not a single feature.

Second, undervalued asset: the teacher-generated dataset. Yes it's ToS-encumbered for redistribution, but nothing stops the team from using it internally to spin off adjacent fine-tunes — analyst-facing terse summaries, exec one-pagers, ticket-close notes — all from the same distillation run, marginal cost near zero once the harness exists.

Third: publishing the training pipeline isn't just goodwill — a Thales CERT open-sourcing "how we built a compliant, verdict-locked explanation model" is a recruiting and credibility signal in a market where every vendor claims "AI-powered" with zero transparency. That's disproportionate PR/hiring return for a solo-lead side build.

Bigger swing: don't stop at Qwen2.5-7B for on-prem inference — if this works, the harness (structured facts in, narrated report out) is the template for a small internal "report-writing model family" across every deterministic system Thales runs, not just Suspicious. Build the schema layer generic from day one; that's the only expansion tax worth paying now.

### The Outsider

Stepping back from all the acronyms: what is being built is "take some data, write a paragraph about it." A person who does this well with a template and a checklist doesn't need to go rent a GPU and grow a whole custom brain to do it. That's the part that reads as confusing to an outsider — the solution is enormously bigger than the problem.

Concretely: the stated goal is a plain-language narrative for people who are explicitly *not* technical. That's a formatting/tone problem, not a reasoning problem. Any competent instruct model, prompted with the structured facts and a fixed verdict, already does this. Training a new model doesn't make prose "more plain-language" — it mostly changes style consistency, which a good prompt + template also buys you, cheaper and reversible.

On "verdict never re-derived" — nothing about fine-tuning vs. prompting changes whether that's enforceable. A generative model of any kind can restate a stale number or contradict a fact if you don't check its output. The only thing that actually enforces "never re-decide" is a deterministic post-generation validator that scans the output for the score/band/confidence and fails closed if it doesn't match. That's a small rule-based component you'd need regardless of which LLM route is chosen — and it's suspiciously similar to the exact bug the team just fixed, so it needs to exist as code, not as a hope about model behavior.

Also: one person is now the data pipeline, the training infra operator, the quality evaluator, AND the deployer, for a security document that goes to outside stakeholders. If this person is out sick for two weeks, who checks the next batch of AI-written verdicts isn't hallucinating? Nobody currently in the described team can.

### The Executor

Monday morning, what do you actually do:

**Step 1 isn't training — it's a prompted baseline, this afternoon.** Take Qwen2.5-7B-Instruct (or whatever's already runnable on-prem), zero-shot/few-shot prompt it with the fixed verdict + raw analyzer JSON, ask for the narrative. Cost: an afternoon. If that output is 80% of the way to "good enough for a non-technical stakeholder," you have your answer on whether distillation is even worth the next six weeks. Nobody should touch LoRA before this exists and has been read by an actual analyst.

**The "fixed verdict, never re-derived" constraint is not an ML property, it's a plumbing property, and that's good news.** A generative model can't be trusted to hold a fact in its weights — it has to be re-fed the fact every time and the output has to be checked, not trusted. Concretely: template-lock the verdict/score/band as a literal string injected post-generation or via constrained decoding, not left for the model to transcribe from context. Then a cheap regex/JSON-schema validator on every generation checks the stated verdict in the output matches the input fact — reject and regenerate (or fall back to the deterministic template) if not. That's a Monday-morning afternoon of work too, and it's needed whether you fine-tune or just prompt. This is the actual fix for the bug that scared the team — not "train it better," but "never let it assert the verdict unchecked."

**Skip the teacher-distillation pipeline until the prompted baseline fails.** It's a multi-week detour (dataset generation, ToS-constrained data, rented GPU, LoRA hyperparameter search) undertaken by one person with zero prior generative-model training experience, justified only by a hunch. If the baseline is bad specifically because it's verbose/inconsistent in tone, that's a prompt-engineering and few-shot-example problem, not a fine-tuning problem — try that next before touching a GPU.

**If you do get to fine-tuning:** don't rent GPU compute until you've counted your data. If you can't produce 200+ genuinely distinct historical/synthetic cases with teacher outputs, you don't have a training set, you have a demo, and QLoRA on <200 examples on a 7B model is a well-known way to burn a rented A100 overfitting to phrasing. That's your go/no-go gate, and you can count your cases before spending a dollar.

**Open-source framing: solvable but not this week's problem.** Publishing code+weights while withholding the dataset is normal and fine (Alpaca did exactly this). Don't let it block anything now — flag it, revisit after there's something to publish.

---

## Step 3: Peer Review (anonymization revealed)

**Mapping:** A = Outsider, B = Contrarian, C = Executor, D = Expansionist, E = First Principles Thinker.

### Reviewer 1
Strongest: C — converts shared skepticism into an actual decision procedure with a concrete go/no-go gate (200+ distinct cases) and resolves the open-source question with the Alpaca precedent instead of just flagging it. Biggest blind spot: D — doesn't answer the question asked; never addresses enforceability, team-bandwidth, or whether training is justified at all; its own proposal (spinning off adjacent fine-tunes) multiplies the exact solo-maintainer risk A and B raised. All five missed: data exfiltration/classification risk — every response discussed ToS *redistribution* rights on the resulting dataset, but none flagged that sending Thales CERT case data to an external LLM vendor in the first place is a separate, likely more serious, data-handling/compliance question.

### Reviewer 2
Strongest: C — only response that converts every abstract point into an action with a concrete gate: prompt-first this afternoon, then a numeric go/no-go before renting GPU, plus the Alpaca precedent that neutralizes the open-source worry instead of just flagging it. B's failure-mode explanation is sharper mechanistically, but C is more useful to act on. Biggest blind spot: D — doesn't answer the question asked, never addresses whether fine-tuning is enforceable or justified, inverts the risk: a solo lead with no ML experience is told to generalize the schema for "the whole platform" and spin off more fine-tunes from a ToS-encumbered dataset. Ignores team-capacity reality entirely. All five missed: routing raw analyzer data — VT/GTI/MISP intel and mail content, potentially client/incident-sensitive — through a third-party hosted API at all, independent of the redistribution-ToS issue everyone caught, is a data-handling/legal question distinct from "can we redistribute the resulting dataset."

### Reviewer 3
Strongest: C — the only response that converts the debate into a sequence with go/no-go gates: ship a prompted baseline this afternoon, gate fine-tuning on a countable threshold, and treats the verdict-lock as a "Monday-afternoon" plumbing task rather than a research problem. It also settles the open-source question with a concrete precedent instead of hand-waving. Biggest blind spot: D — never answers the questions asked, assumes yes and pivots to empire-building, treats the solo-lead constraint as absent rather than the binding constraint every other response identifies. All five missed: how to evaluate factual faithfulness beyond a verdict-string regex (numbers, entity names, analyzer findings can still be misstated even with the verdict locked); what happens when the deterministic system's rules change and the teacher-generated training set silently goes stale; any human sign-off gate before an AI-narrated report reaches an external stakeholder.

### Reviewer 4
Strongest: C — turns every question into a concrete, sequenced decision procedure: prompt-first this afternoon, template-lock + validator regardless of path, a numeric go/no-go gate before renting GPUs, and it resolves the open-source question with a real precedent instead of hand-waving. It answers all five sub-questions without dropping any. Biggest blind spot: D — doesn't answer the question asked, reframes "is this the right architecture for a solo lead" into "how big can this platform become," ignoring the enforceability question entirely. Proposing a "generic report-writing model family across Thales" for someone with one CPU-classifier's experience is the opposite of what was asked. All five missed: the fine-tune's own staleness lifecycle — when the deterministic rules/thresholds change, the distilled model's learned phrasing goes stale exactly like the bug that started this, except now baked into weights instead of cached text, requiring re-distillation on every rule change. None addressed human sign-off/audit trail before an AI-narrated report reaches external stakeholders.

### Reviewer 5
Strongest: C — the only response that turns the debate into a sequenced, falsifiable plan: ship a prompted baseline this afternoon, gate any LoRA spend on a concrete data threshold, and treats verdict-locking as plumbing needed either way. It directly channels the team's fresh bug scar into a concrete fix rather than a warning. Biggest blind spot: D — never engages the actual question — enforceability of "fixed verdict" — and instead reframes the safety constraint as a "moat" to expand. For a solo lead with no ML infra, urging a generic schema so the harness can spawn a "report-writing model family across Thales" is the opposite of what a resource-constrained, safety-critical build needs. It also waves off the ToS-encumbered dataset as a non-issue to "spin off adjacent fine-tunes" from — expanding exposure, not limiting it. All five missed: none flagged that feeding raw case data to a hosted teacher LLM is a confidentiality/data-governance problem for a CERT, separate from the redistribution-ToS issue everyone discussed; regression-testing the narration layer against future changes to the deterministic verdict engine itself.

---

## Step 4: Chairman Synthesis

### Where the Council Agrees

Every advisor converges on the same core diagnosis, reached independently:

- **"Fixed verdict, never re-derived" is not a training-time property.** No advisor believes LoRA, distillation, or model choice affects this. The Contrarian, First Principles Thinker, Outsider, and Executor all land on the same mechanism: template-lock the verdict/score/band as literal injected strings, then run a deterministic post-generation validator that checks the output and rejects/regenerates on mismatch. This is code, not model behavior, and it's needed under *every* architecture on the table — fine-tuned, prompted, RAG, doesn't matter.
- **The distillation pipeline is solving an unproven problem.** Four of five advisors (all but the Expansionist) independently say: try prompting the base model first. Nobody described running that experiment before committing to teacher distillation, LoRA, and rented GPUs. That's the load-bearing gap in the proposal as written.
- **Solo-lead bandwidth is a real constraint, not a footnote.** The Contrarian, Outsider, and Executor all flag that one person with one prior CPU-classifier's worth of ML experience cannot also be the data pipeline, training infra operator, quality evaluator, and deployer for a document that reaches external stakeholders.
- **The open-source framing (open model/code, closed dataset) is fine and not a live problem.** The Executor's Alpaca precedent settled this for the peer reviewers — it's a "flag and revisit later," not a blocker.

### Where the Council Clashes

**The Expansionist vs. everyone else.** This is the one real fight, and it's lopsided. The Expansionist argues the fixed-verdict architecture is a reusable "moat," urges generalizing the schema now, and proposes spinning off additional fine-tunes (analyst summaries, exec one-pagers) from the same ToS-encumbered teacher data. Every single peer reviewer — independently, 5 for 5 — named the Expansionist as the weakest response and gave the same reason: it never engages the enforceability question or the solo-lead constraint the brief explicitly set, and its proposal *increases* the maintenance surface for someone already stretched thin. This isn't "reasonable people disagree" — it's a response that answered a different, more comfortable question than the one asked. Its one useful idea (design the input schema generically rather than phishing-specific) is worth keeping; the rest of the expansion agenda should be shelved.

**Train now vs. prompt first** is a softer disagreement, mostly of degree. Nobody actually argues for jumping straight to LoRA — even the proposal's implicit defenders (none, really) don't show up. The real spectrum runs from "prompting probably suffices, don't build the pipeline" (Outsider, First Principles) to "prompt first, but keep a numeric go/no-go gate for later fine-tuning if the baseline falls short" (Executor). The Executor's framing is the one that survived peer review intact, because it doesn't foreclose fine-tuning — it just sequences it behind evidence.

### Blind Spots the Council Caught

Peer review surfaced two issues that no advisor raised in their own initial response — that's the actual value-add of the second pass here:

1. **Data governance/exfiltration, not just redistribution ToS.** Four of five reviewers flagged this independently: sending raw case data — phishing emails, VT/GTI/MISP intelligence, mail analyzer output — to a hosted third-party API to generate teacher training text is a confidentiality and compliance question for a CERT that is *separate from and arguably more serious than* the "can we redistribute the dataset" question every advisor spent time on. "Historical/synthetic case shapes" was asserted in the proposal as low-risk without examination; if "historical" cases carry real indicators, real targeted-org names, or real victim data, this needs a data-classification pass before any teacher-call happens, not after.
2. **Staleness lifecycle of the fine-tune itself.** Two reviewers independently caught that a distilled model bakes in phrasing tied to the deterministic engine's rules *at training time*. When those rules or thresholds change (as they clearly do — the team just did a whole-branch review), the model's learned narrative patterns go stale in weights, not in a cache — a slower-motion, harder-to-detect version of the exact bug that motivated this whole safety constraint. No re-distillation trigger tied to rule changes was proposed anywhere.
3. Also worth carrying forward even though weighted lower: no human sign-off gate before an AI-narrated report reaches an external stakeholder, and no plan for validating factual faithfulness of entities/numbers in the body text beyond the verdict string itself (a report can hold the verdict fixed and still misstate a domain, a hash, or a date pulled from analyzer JSON).

### The Recommendation

Do not start the teacher-distillation pipeline. The proposal as written skips the cheap experiment that would tell you whether you need it, and builds the expensive one first. The council's consensus, reinforced unanimously by peer review, is:

- Build the deterministic verdict-lock + output validator now, regardless of which generation approach you use. This is the actual fix for the bug class you're worried about, and it's a day of work, not a training run.
- Prompt an on-prem instruct model (Qwen2.5-7B or whatever's already available) against real case data with the locked verdict injected, and get an analyst to read the output. This answers "is fine-tuning even necessary" empirically instead of by hunch.
- Treat fine-tuning as contingent, gated on two things: the prompted baseline demonstrably failing in a way prompting/few-shot can't fix, and having 200+ genuinely distinct cases with teacher outputs in hand before renting any GPU.
- Before any teacher API call happens with real case content, resolve the data-classification question the council's peer review surfaced — that's a harder blocker than anything in the original five questions.
- Shelve the Expansionist's platform-wide ambitions entirely. Generalizing the input schema slightly (verdict + evidence + confidence, not phishing-only field names) is fine and cheap to do now; spinning off a family of fine-tunes from ToS-encumbered data is not something a solo lead should be doing before the first version ships and survives contact with a real stakeholder.
- The open-source framing (open model + open code, closed dataset) is fine as-is — don't spend more cycles on it now.

### The One Thing to Do First

This afternoon, before touching LoRA or a rented GPU: build the deterministic verdict/score/band injector-and-validator (inject as literal strings, regex/schema-check the generated output, fail closed to a template on mismatch), then run it in front of a zero-shot prompt to the on-prem instruct model on a handful of real cases and have an analyst read the results — that single artifact answers the safety-enforceability question, the "is fine-tuning necessary" question, and gives you your first real data point, all before you've spent a dollar on training infrastructure.
