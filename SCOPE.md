# Scope

This document says what ScamSentinel does, what it doesn't do, and the rules it follows when it touches the outside world.

## In scope (MVP)

### Targets
Scams that impersonate these protected brands:

| Brand | Official domains (initial allowlist) |
|---|---|
| IRS | `irs.gov` (and subdomains) |
| TurboTax | `turbotax.com`, `turbotax.intuit.com`, `intuit.com` |
| QuickBooks | `quickbooks.com`, `quickbooks.intuit.com`, `intuit.com` |
| Credit Karma | `creditkarma.com` |

The allowlist lives in `data/brands.yaml`. It is versioned, and each entry records its source.

### Inputs
- Plain text (SMS, chat, social DMs)
- Raw email (`.eml`): headers + text/HTML bodies, parsed but never rendered
- A single URL (http/https)
- Screenshots (PNG, JPEG, WebP)

### Scam patterns
- Refund / "refund on hold" / identity-verification lures
- Account suspension or lockout
- Fake balance due and payment demands (gift cards, crypto, wire, Zelle, Cash App)
- Credential and PII harvesting (SSN, bank, password, MFA codes, ID photos)
- Fake tax-prep or "IRS agent" offers
- Lookalike and newly registered domains (via CT logs)

### Outputs
- Verdict (`likely_scam` / `suspicious` / `likely_legitimate`), a 0–100 score, per-module scores, and an itemized list of evidence-backed reasons
- Sandbox artifacts: screenshot, redirect chain, form inventory
- CT candidate feed
- Evaluation report: precision, recall, F1, FPR, confusion matrix, ablations

## Out of scope (MVP)

| Not doing | Why |
|---|---|
| Brands other than the four above | Keeps the allowlist, eval set, and rules focused; adding a brand is a config change later |
| Real-time inbox/SMS integration or blocking | ScamSentinel is an analyzer, not a filter or gateway |
| Takedown requests, abuse reports, registrar contact | Out of scope for an educational tool; may be considered later with manual review |
| Malware / executable analysis | The detonator observes phishing pages; it does not run downloads. Downloads are blocked |
| PDF, Office, or archive uploads | Large attack surface. Images only for MVP |
| Voice-call (vishing) analysis | No audio pipeline |
| Training a custom ML classifier | MVP uses LLM feature extraction + rules; a trained model could become a later ablation |
| Multi-tenant auth, billing, production SLA | Portfolio/demo deployment |
| Non-English messages | Rules and eval set are English-only; would bias metrics |
| Guarantees of safety | A "likely legitimate" verdict is not a warranty |

## Responsible-use rules

ScamSentinel touches live attacker infrastructure and public services. These rules apply to the code and to anyone operating it.

### URL detonator
1. **Observe only.** Never submit forms, type credentials, click buttons, or trigger downloads. The sandbox loads the page and records what it sees.
2. **Never send real data.** No cookies, stored credentials, or real user-agent fingerprint tied to an operator identity.
3. **Bounded traffic.** One page load per submission. Hard caps on time, redirects, and bytes. Rate limits stop the tool from being used to flood a site.
4. **No internal targets.** The SSRF guard (see [`SECURITY.md`](SECURITY.md)) enforces this, and it can't be turned off with a config flag in production builds.
5. **Isolated execution.** Detonation runs only inside the sandbox container, never on a developer's host browser.

### CT watcher
1. Query crt.sh politely: low frequency (default every 6 h), sequential requests, exponential backoff, and a descriptive User-Agent.
2. CT candidates are **unverified leads**, not accusations. A certificate containing "irs" is not evidence of fraud. The UI and API label these "candidate lookalikes."
3. CT candidates are not auto-detonated in the MVP. Detonation stays on-demand.

### Data handling
- Inputs may contain victims' personal data. Retain them for 7 days by default, redact SSN- and card-like numbers in logs, and never use user submissions in the public eval set without consent.
- Do not publish live, working phishing URLs in the repository. Store eval URLs defanged (`hxxps://example[.]com`).

### Evaluation data
- Use public datasets under their licenses and cite them in `data/eval/SOURCES.md`.
- Mark every synthetic sample `source: synthetic`. Report metrics on real and synthetic samples separately.

## Assumptions
- English-language US taxpayer context.
- One operator running the stack locally or on a single VM via Docker Compose.
- An Anthropic API key is available. Without one, the system runs rules-only.
