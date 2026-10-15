# Scope

This document defines what ScamSentinel does, what it doesn't do yet, what it won't do at all, and the rules it follows when it touches the outside world.

ScamSentinel is a portfolio cybersecurity project: an explainable scam and phishing analyzer that runs locally, plus a threat model and tests for the analyzer itself. Detection is organized into **scam categories**. Tax-season impersonation is the baseline category; package-delivery smishing is the second.

## MVP definition

The MVP is done when someone can run ScamSentinel on their own computer, send it a text message, email, URL or screenshot from the command line, and get back an explainable verdict, with the security defenses tested and accuracy measured.

| Milestone | What | Status |
|---|---|---|
| M0 | Docs, repo skeleton, API skeleton, test harness | ✅ Done |
| M1 | Lookalike-domain engine | ✅ Done |
| M2 | Message analyzer (rules first, then Groq LLM) + verification layer | ✅ Done |
| M3 | Risk aggregator + `POST /v1/analyze` (text, URL, email) | ✅ Done |
| M4 | Security hardening: upload guard, prompt-injection suite, no-fetch test, log redaction | ✅ Done |
| M5 | Screenshot analysis (Groq vision transcription) | ✅ Done |
| M6 | Evaluation dataset + precision/recall/F1/FPR report | ✅ Done |

## In scope

### Scam categories and protected brands

| Category | Brand | Official domains (allowlist) |
|---|---|---|
| Tax-season impersonation | IRS | `irs.gov` (and subdomains) |
| | TurboTax | `turbotax.com`, `intuit.com` (incl. `turbotax.intuit.com`) |
| | QuickBooks | `quickbooks.com`, `intuit.com` (incl. `quickbooks.intuit.com`) |
| | Credit Karma | `creditkarma.com` |
| Package-delivery smishing | USPS | `usps.com`, `uspis.gov` |

Categories and brands live in `data/brands.yaml`, versioned, with a source for each entry. The code names no organization; see [`architecture.md` §16](architecture.md#16-scam-categories-and-the-brand-agnostic-core).

**Rule for growth:** add one category at a time, each with sourced trusted facts, its own signals, synthetic samples with hard negatives, and its own reported metrics. Check that existing categories' numbers don't change before describing the tool as covering the new one. Don't add brands without facts and tests.

### Inputs
- Plain text (SMS, chat, social DMs)
- Raw email (`.eml`): headers + text/HTML bodies, parsed but never rendered
- A URL (http/https), **analyzed as a string only, never visited**
- Screenshots (PNG, JPEG, WebP)

### Scam patterns
Shared across categories:
- Lookalike domains (homoglyphs, typos, keyword stuffing, subdomain tricks, TLD swaps)
- Impersonation of a protected organization, and claims that contradict its published policies
- Urgency and threats; payment demands (gift cards, crypto, wire, Zelle, Cash App)
- Credential and PII harvesting (SSN, bank, password, MFA codes, card details, ID photos)
- Instructions aimed at AI classifiers (prompt injection), scored as evidence

Tax: refund holds, identity verification, account suspension, fake balance due, fake tax-prep or "IRS agent" offers.
Delivery: "package on hold", incomplete address, redelivery or customs fees, "returned to sender".

### Outputs
- Verdict (`likely_scam` / `suspicious` / `likely_legitimate`), a 0–100 score, per-module scores, and an itemized list of evidence-backed reasons
- Domain-only scoring (`GET /v1/domain/score`)
- Evaluation report: precision, recall, F1, FPR, confusion matrix, ablations, per category
- Lookalike domains found in Certificate Transparency logs (`GET /v1/ct/candidates`)

## After the MVP

Details in [`architecture.md` §14](architecture.md#14-post-mvp-roadmap).

| Phase | What | Status |
|---|---|---|
| P1 | Certificate Transparency watcher (crt.sh) to find newly registered lookalikes | ✅ Done |
| G1 | Brand-agnostic core and scam categories; package delivery (USPS) as the second category | ✅ Done |
| G2+ | One new category at a time: bank impersonation, account takeover, tech support, job scams | Planned |
| E1 | "What should I do next?": short, cautious next steps chosen by the evidence found (never repeating links or numbers from the message) | Planned |
| E2 | Richer domain explanations: which characters were swapped, the misspelling, the misleading extra words | Planned |
| E3 | Fact-check summary: which claims match, conflict with, or can't be checked against the trusted facts | Planned |
| E4 | Named scenarios per category (refund delay, payment demand, package on hold, …), added over time | Planned |
| P2 | Lightweight page fetch (no browser) to inspect forms and brand content, together with the SSRF URL guard | Planned |
| P3 | Playwright headless-browser sandbox (screenshots, JavaScript-rendered pages, redirect chains) | Planned |
| P4 | Docker packaging | Planned |

## Out of scope

| Not doing | Why |
|---|---|
| Brands or categories without sourced facts and tests | A brand list without facts and labeled data would claim coverage that isn't measured |
| A hosted web app | The browser UI is a single local page served by the same loopback-only process. Keeps the attack surface small |
| Remote/hosted deployment | The API binds to `127.0.0.1` only; exposing it to a network isn't supported |
| Real-time inbox/SMS integration or blocking | ScamSentinel is an analyzer, not a filter or gateway |
| Takedown requests, abuse reports, registrar contact | Out of scope for an educational tool |
| Malware / executable analysis | No downloads, no execution of anything submitted |
| PDF, Office, or archive uploads | Large parser attack surface. Images only |
| Voice-call (vishing) analysis | No audio pipeline |
| Training a custom ML classifier | LLM feature extraction + rules; a trained model could become a later ablation |
| Non-English messages | Rules and eval set are English-only; would bias metrics |
| Guarantees of safety | A "likely legitimate" verdict is not a warranty |

## Responsible-use rules

### Attacker infrastructure
- The MVP never connects to submitted URLs. Don't add code that does until the post-MVP SSRF guard (P2) exists.
- The CT watcher (P1) only queries crt.sh: one request at a time, spaced out, with backoff and an identifying `User-Agent`. It never visits the domains it finds, and its candidates are unverified leads, not accusations.
- Don't publish live, working phishing URLs in the repository. Store eval URLs defanged (`hxxps://example[.]com`).

### Data handling
- Inputs may contain victims' personal data. Analyses are retained for 7 days by default, SSN- and card-like numbers are redacted in logs, and user submissions never go into the public eval set without consent.
- Groq's free tier sends input text to a third party. Only analyze synthetic or public samples with the LLM enabled. Never send real victims' personal data. Rules-only mode (no API key) keeps everything local.

### Guidance (E1)
- Next-step advice comes from fixed, reviewed templates, never from the LLM.
- It never repeats, links to or recommends a URL or phone number from the analyzed message. Official contacts come only from `data/facts.yaml`, with sources.
- It's worded cautiously and never promises that something is safe.

### Evaluation data
- Use public datasets under their licenses and cite them in `data/eval/SOURCES.md`.
- Mark every synthetic sample `synthetic: true`. Report metrics on real and synthetic samples separately, and per category.

## Assumptions
- English-language, US context (US tax agencies and carriers).
- One person running ScamSentinel on their own computer in a Python virtual environment, using the API from the command line at `http://127.0.0.1:8000`.
- Screenshot analysis needs a `GROQ_API_KEY`: a Groq vision model reads the text, and the sanitized image (metadata removed) is sent to Groq. Without a key, screenshot requests return 503. Only use synthetic or public screenshots, never ones showing real people's personal data.
- An LLM API key is available for the selected provider (Groq by default, free tier). Without one, the system runs rules-only.
