# Scope

This document defines the **MVP**: what ScamSentinel does, what it doesn't do yet, what it won't do at all, and the rules it follows when it touches the outside world.

## MVP definition

The MVP is done when someone can run ScamSentinel on their own computer, send it a text message, email, URL or screenshot from the command line, and get back an explainable verdict, with the security defenses tested and accuracy measured.

| Milestone | What | Status |
|---|---|---|
| M0 | Docs, repo skeleton, API skeleton, test harness | ✅ Done |
| M1 | Lookalike-domain engine | ✅ Done |
| M2 | Message analyzer (rules first, then Groq LLM) + verification layer | ✅ Done |
| M3 | Risk aggregator + `POST /v1/analyze` (text, URL, email) | ✅ Done |
| M4 | Security hardening: upload guard, prompt-injection suite, no-fetch test, log redaction | ✅ Done |
| M5 | Screenshot OCR (Tesseract) | |
| M6 | Evaluation dataset + precision/recall/F1/FPR report | |

## In scope (MVP)

### Targets
Scams that impersonate these protected brands:

| Brand | Official domains (initial allowlist) |
|---|---|
| IRS | `irs.gov` (and subdomains) |
| TurboTax | `turbotax.com`, `intuit.com` (incl. `turbotax.intuit.com`) |
| QuickBooks | `quickbooks.com`, `intuit.com` (incl. `quickbooks.intuit.com`) |
| Credit Karma | `creditkarma.com` |

The allowlist lives in `data/brands.yaml`. It is versioned, and each entry records its source.

### Inputs
- Plain text (SMS, chat, social DMs)
- Raw email (`.eml`): headers + text/HTML bodies, parsed but never rendered
- A URL (http/https), **analyzed as a string only, never visited**
- Screenshots (PNG, JPEG, WebP)

### Scam patterns
- Refund / "refund on hold" / identity-verification lures
- Account suspension or lockout
- Fake balance due and payment demands (gift cards, crypto, wire, Zelle, Cash App)
- Credential and PII harvesting (SSN, bank, password, MFA codes, ID photos)
- Fake tax-prep or "IRS agent" offers
- Lookalike domains (homoglyphs, typos, keyword stuffing, subdomain tricks)

### Outputs
- Verdict (`likely_scam` / `suspicious` / `likely_legitimate`), a 0–100 score, per-module scores, and an itemized list of evidence-backed reasons
- Domain-only scoring (`GET /v1/domain/score`)
- Evaluation report: precision, recall, F1, FPR, confusion matrix, ablations

## Post-MVP (planned, not in the MVP)

Built in this order, only after the MVP works end to end. Details in [`architecture.md` §14](architecture.md#14-post-mvp-roadmap).

| Phase | What |
|---|---|
| P1 | Certificate Transparency watcher (crt.sh) to find newly registered lookalikes |
| P2 | Lightweight page fetch (no browser) to inspect forms and brand content, together with the SSRF URL guard |
| P3 | Playwright headless-browser sandbox (screenshots, JavaScript-rendered pages, redirect chains) |
| P4 | Docker packaging |

## Out of scope

| Not doing | Why |
|---|---|
| Brands other than the four above | Keeps the allowlist, eval set, and rules focused; adding a brand is a config change later |
| Web UI or browser front end | API-only: run locally and use it from the command line. Keeps the attack surface small |
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
- Don't publish live, working phishing URLs in the repository. Store eval URLs defanged (`hxxps://example[.]com`).

### Data handling
- Inputs may contain victims' personal data. Analyses are retained for 7 days by default, SSN- and card-like numbers are redacted in logs, and user submissions never go into the public eval set without consent.
- Groq's free tier sends input text to a third party. Only analyze synthetic or public samples with the LLM enabled. Never send real victims' personal data. Rules-only mode (no API key) keeps everything local.

### Evaluation data
- Use public datasets under their licenses and cite them in `data/eval/SOURCES.md`.
- Mark every synthetic sample `synthetic: true`. Report metrics on real and synthetic samples separately.

## Assumptions
- English-language US taxpayer context.
- One person running ScamSentinel on their own computer in a Python virtual environment, using the API from the command line at `http://127.0.0.1:8000`.
- Tesseract is installed for screenshot OCR (M5). Without it, screenshot analysis reports `degraded: ocr_unavailable`.
- An LLM API key is available for the selected provider (Groq by default, free tier). Without one, the system runs rules-only.
