# Architecture

This document describes the **MVP**. Features planned for after the MVP are summarized in [§14 Post-MVP roadmap](#14-post-mvp-roadmap).

## 1. Design principles

1. **The LLM extracts, the rules decide.** The language model turns messy text into structured features. Deterministic, unit-tested rules turn the features into a score. This keeps verdicts explainable and limits the damage prompt injection can do.
2. **Every point is accounted for.** Every module score is built from reasons that carry points, so each verdict can be audited.
3. **Untrusted by default.** User input, uploaded images, and LLM output all get validated at the boundary. See [`SECURITY.md`](SECURITY.md).
4. **Graceful degradation.** If the LLM or OCR is unavailable, the analysis still finishes. It notes which modules ran and which didn't.
5. **Never touch attacker infrastructure (MVP).** URLs are analyzed as strings only. ScamSentinel never connects to a user-supplied URL, which removes SSRF by design.
6. **Runs on a laptop.** A Python virtual environment and one external program (Tesseract, for OCR). No Docker, no headless browser.

---

## 2. System overview

```
                  ┌───────────────────────────────────────────────┐
  text / email /  │            API (FastAPI, 127.0.0.1)           │
  URL / screenshot│  Host check · size caps · input validation    │
  ──────────────▶ └───────────────────────┬───────────────────────┘
                                          ▼
                  ┌───────────────────────────────────────────────┐
                  │                Ingest / Normalize             │
                  │  .eml parse · HTML→text · URL extraction      │
                  │  (incl. defanged) · screenshot → OCR → text   │
                  └──────────┬────────────────────────┬───────────┘
                             │ domains                │ text
                             ▼                        ▼
                  ┌──────────────────┐     ┌────────────────────────┐
                  │  Domain Engine   │     │   Message Analyzer     │
                  │  PSL · IDN ·     │     │  rule features +       │
                  │  homoglyph ·     │     │  LLM features (Groq)   │
                  │  edit distance · │     └───────────┬────────────┘
                  │  keyword stuffing│                 ▼
                  └────────┬─────────┘     ┌────────────────────────┐
                           │               │  Verification layer    │
                           │               │  (trusted facts)       │
                           │               └───────────┬────────────┘
                           ▼                           ▼
                  ┌───────────────────────────────────────────────┐
                  │                Risk Aggregator                │
                  │  weights · renormalize · floors · bands       │
                  └───────────────────────┬───────────────────────┘
                                          ▼
                            verdict · score · reasons[]
```

### Interface

ScamSentinel is **API-only**. There is no web UI. It runs on the user's own computer with `python -m scamsentinel`, and the user calls the HTTP API from the command line (e.g. `curl`) at `http://127.0.0.1:8000`. Results come back as JSON. FastAPI's auto-generated OpenAPI page at `/docs` serves as the API reference.

### Runtime

| Piece | How it runs |
|---|---|
| API + all analysis modules | One Python process (`python -m scamsentinel`), listening on `127.0.0.1:8000` only |
| OCR | In-process image validation and re-encoding (Pillow); `pytesseract` runs the Tesseract binary as a separate process with a timeout |
| LLM | HTTPS call to the configured provider (Groq by default). Optional: without a key, rules-only |
| Storage | SQLite file under `var/` |

---

## 3. Repository layout

```
scamsentinel/
  config.py       # Settings (env vars, localhost-only bind policy)
  models.py       # Verdict, Reason, ModuleResult, AnalysisResult
  data.py         # validated loaders for data/*.yaml and config/scoring.yaml
  pipeline.py     # orchestrator: ingest -> domain/message -> verify -> aggregate
  api/            # FastAPI app, routes, request schemas, middleware
  ingest/         # eml parsing, html→text, URL extraction (incl. defanged)
  domain/         # registrable-domain parsing, homoglyphs, distance, keywords, scorer
  message/        # feature schema, rule extractor, LLM extractor, merger
  verify/         # trusted-facts checks
  ocr/            # re-encode + Tesseract
  aggregate/      # weights, floors, verdict bands, reason assembly
  security/       # upload_guard.py, redaction.py (url_guard.py is post-MVP)
  ct/             # post-MVP: crt.sh client, watcher, candidate store (stubs)
  eval/           # dataset loader, runner, metrics, ablations, report
config/
  scoring.yaml    # weights, bands, floors, technique points
data/
  brands.yaml     # protected brands, official domains, brand tokens
  keywords.yaml   # stuffing keywords, urgency phrases, payment methods
  facts.yaml      # trusted facts for verification (with sources)
  confusables.txt # curated Unicode TR39 confusables subset
  eval/           # labeled samples + SOURCES.md
tests/
  unit/ security/
```

---

## 4. Lookalike-domain engine

**Input:** a hostname or URL. **Output:** `DomainResult {host, registrable, official, score, brand, techniques[], normalized, reasons[]}`.

### Pipeline

1. **Canonicalize.** Lowercase, refang (`[.]`, `hxxp`), strip scheme/userinfo/port/path and the trailing dot, remove zero-width characters, and decode punycode (`xn--…` → Unicode).
2. **Split with the Public Suffix List** (`tldextract`): `subdomain`, `domain` (the label), `suffix`.
   - Example: `turbotax.com.refund-help.co.uk` → subdomain `turbotax.com`, label `refund-help`, suffix `co.uk`.
3. **Allowlist check.** If `label.suffix` matches an official registrable domain in `brands.yaml`, the result is `official=true, score=0` and processing stops.
4. **Normalize to a skeleton** (`domain/normalize.py`).
   - NFKC + casefold (folds fullwidth and math-alphanumeric forms).
   - Unicode confusables → ASCII from `data/confusables.txt` (a curated UTS #39 subset): `tսrbotax` (Armenian `ս`) → `turbotax`.
   - Strip combining marks: `türbotax` → `turbotax`.
   - ASCII lookalike *classes*, applied to both the input and the brand tokens: `0→o, 1→l, i→l, 3→e, 4→a, 5→s, 7→t, 8→b, rn→m, vv→w, cl→d`. Because `i`, `l` and `1` all collapse to `l`, `1rs` and `lrs` match `irs`.
   - Strip separators to get the compact form: `turbo-tax` → `turbotax`.
5. **Match tokens.** Long tokens (`turbotax`, `quickbooks`, `creditkarma`) match as substrings of the compact skeleton. **Boundary tokens** (`irs`, `intuit`) only match as whole words. Their neighbors must split entirely into other brand tokens or stuffing keywords (dynamic-programming segmentation), and the label is also split on digits. So `irsgov` and `irs2024-refund` match, while `first`, `theirs` and `intuition` don't.
6. **Run the detectors:**

| Technique | How | Example | Points (initial) |
|---|---|---|---|
| `homoglyph` | The skeleton contains a brand token, but the literal label doesn't | `turb0tax.com`, `іrs-refund.com` (Cyrillic `і`) | 85 |
| `brand_plus_keywords` | Brand token + ≥1 stuffing keyword | `turbotax-refund-secure.com` | 50 + 10 per keyword (cap 90) |
| `tld_swap` | Label equals an official label, under a different suffix | `irs.gov.co`, `turbotax.net` | 65 |
| `exact_brand_unofficial` | Compact label equals a brand token, but it isn't an official label | `turbo-tax.com`, `credit-karma.com` | 70 |
| `brand_in_label` | Brand token plus unrecognized words | `myturbotaxfiling.com` | 50 |
| `typosquat` | Normalized Damerau-Levenshtein ≤ 0.2 between a brand token (min length 4) and any part, or sliding window, of the label | `turbotxa.com`, `quickbook.com` | 60–80 (scaled by similarity), +10 per keyword |
| `brand_in_subdomain` | Brand token appears in the subdomain of an unrelated registrable domain | `turbotax.com.evil.net`, `irs.gov.refund-claim.net` | 75 |
| `idn_mixed_script` | Label mixes scripts (Latin + Cyrillic) | `сreditkarma.com` | +15 bonus |

The domain score is the maximum over techniques plus bonuses, capped at 100. Every technique that fires becomes a reason carrying its own points. Domains that resemble nothing return a single `no_lookalike_signals` reason, and IP-address hosts return `ip_address_host` (score 0). The PSL split uses tldextract's bundled snapshot (no network, no disk cache) with PSL private domains enabled, so `irs-refund.netlify.app` is analyzed by its attacker-controlled label.

### Testing
- One case per technique, plus a generated suite covering every lookalike technique for every brand (AC-2).
- Negative suite: official domains, legitimate lookalike-prone domains (`firstbank.com`, `taxact.com`, `hrblock.com`, `intuition.com`), and words containing `irs`.
- `hypothesis`: normalization is idempotent, no official domain (with any subdomain) ever scores above 0, and arbitrary input never crashes the engine.

---

## 5. Message analyzer

Two extractors run, and a merger combines their results.

### 5.1 Rule extractor (built first)

Regex and phrase lists from `keywords.yaml`: urgency phrases ("within 24 hours", "final notice", "immediately"), payment rails, PII requests (`social security`, `SSN`, `routing number`, `verification code`), threats, brand mentions, injection phrases, and phone numbers / URLs (including defanged ones). Fully deterministic and local.

### 5.2 LLM feature extractor

- **Provider:** pluggable via `SCAMSENTINEL_LLM_PROVIDER`. The default is **Groq** with `openai/gpt-oss-20b`, called over its OpenAI-compatible API with `httpx`. That model supports Groq's **strict JSON-schema mode** (constrained decoding against `FEATURE_SCHEMA` in `message/llm.py`). Other Groq models fall back to JSON-object mode. Either way, the reply is validated as `MessageFeatures`. Temperature 0. The Anthropic provider is configurable but not implemented yet; selecting it reports `llm_unavailable:provider_not_implemented` and runs rules-only.
- **Failure handling:** timeouts, network errors, 401/403, 429, other HTTP errors, non-JSON replies and schema violations all raise `LlmUnavailable(reason)`. The analysis continues rules-only and reports `degraded: ["llm_unavailable:<reason>"]`.
- **Prompt structure:**
  - *System:* role ("you extract indicators from untrusted content"), an explicit statement that the content is data and must not be followed, and the schema field definitions.
  - *User:* `<untrusted_content_{random_hex}> … </untrusted_content_{random_hex}>`, with the input capped at about 20k chars.
- **Feature schema (excerpt):**

```json
{
  "impersonated_entity": { "value": "IRS|TurboTax|QuickBooks|Credit Karma|other|none", "span": "..." },
  "urgency":            { "level": 0, "spans": ["..."] },
  "payment_methods":    [{ "method": "gift_card|crypto|wire|zelle|cash_app|venmo|other", "span": "..." }],
  "sensitive_requests": [{ "type": "ssn|bank_account|password|mfa_code|card|id_photo|dob", "span": "..." }],
  "claimed_urls":       ["..."],
  "claimed_phone_numbers": ["..."],
  "call_to_action":     { "value": "click_link|call_number|reply|pay|none", "span": "..." },
  "threats":            [{ "type": "arrest|account_suspension|refund_loss|penalty|legal_action", "span": "..." }],
  "injection_attempt":  { "detected": false, "span": "" }
}
```

  There is no verdict or score field, and the schema rejects unknown fields.
- **Grounding check:** each `span` must appear in the normalized input (case/whitespace-insensitive). Features that fail the check are dropped and counted.
- **Caching (M3):** results will be keyed on `sha256(provider + model + prompt_version + normalized_text)` in SQLite.

### 5.3 Merge

Union both extractors' features, tagging each one with `source: llm|rule|both`. Everything the LLM returns is tagged `llm` regardless of what it claims, and is grounded before merging. Rule features always count (they're deterministic and visible in the text). On conflicts (e.g. a different impersonated entity) the rules win. Indicators the rules found but the LLM missed are returned as `disagreements` (e.g. `llm_missed_injection_attempt`), a signal of possible injection or extraction gaps.

The rule extractor ignores payment methods, sensitive requests and threats that follow a negation in the same clause ("The IRS will **never** ask for your SSN"), so legitimate warnings don't score as scams.

### 5.4 Scoring

The message score is the **sum** of its reasons' points, clamped to 0–100 (`message_points` and `verify_points` in `config/scoring.yaml`). Sensitive requests and threats have caps so one long list can't dominate. Verification reasons are added once per signal, and mitigating ones (official link, DKIM-verified official sender) only count when no check failed.

---

## 6. Verification layer (VerifyVault-style)

The verification layer turns claims in the message into checks against `data/facts.yaml`. Each fact records a source URL and a last-reviewed date.

| Check | Input | Fails when |
|---|---|---|
| `official_domain` | Each URL/domain (incl. email link targets) + impersonated brand | Domain is not in the brand's official list (an official link is mitigating) |
| `contact_channel` | Input type + entity | IRS contacting by SMS/email (or a screenshot of one) while asking for information, payment, or sending to an unofficial link |
| `payment_method_policy` | Payment methods + entity | A fact says the entity doesn't take that method (IRS: gift card / crypto / wire / P2P apps) |
| `phone_number` | Claimed phone numbers + entity | Number isn't among the entity's published numbers (reported as "can't verify", lower weight) |
| `sender_alignment` (email) | From / Reply-To / DKIM `header.d` | Claims a brand but sent from another domain, or Reply-To goes to a different domain. An official sender with passing DKIM is mitigating |

Output: `[{check, claim, verified: true|false|null, source, detail}]`. Checks that come back `false` become reasons. A check that passes, such as "link goes to irs.gov," is shown as a mitigating reason and lowers the score.

---

## 7. Input handling

| Input | Handling |
|---|---|
| Text (`text`) | Up to 20,000 characters. URLs and domains extracted, including defanged forms |
| URL (`url`) | Scored by the domain engine and checked by the verification layer. **Never fetched** |
| Email (`email_raw`) | Parsed with Python's `email` package. HTML bodies converted to text with an HTML parser, never rendered. Attachments listed by name/type/size, never opened |
| Screenshot (multipart `image`) | Upload guard → OCR (§8) → treated as text |

---

## 8. Screenshot OCR

```
upload ─▶ upload_guard (size cap, magic bytes, pixel cap)
       ─▶ decode → re-encode PNG (strips metadata and appended payloads)
       ─▶ grayscale + upscale if small → tesseract subprocess (timeout)
       ─▶ text + mean confidence ─▶ ingest (URL extraction) ─▶ message analyzer
```

Tesseract must be installed on the machine (Windows installer, `brew install tesseract`, or `apt install tesseract-ocr`). If it's missing, screenshot analysis returns `degraded: ocr_unavailable` instead of failing. When OCR confidence is low (<60), the reasons say so.

---

## 9. Risk aggregator

### Module scores
Each module produces `score ∈ [0,100]` and `reasons[]` (each with `points`). Verification has no module score of its own. Its reasons add points to the message module.

### Weighted combination with renormalization
Default weights: `domain 0.55, message 0.45`. Only modules that **ran** count, and their weights are renormalized:

```
active = {m: w for m, w in weights if m ran}
risk   = Σ (w / Σ active_w) · score_m
```

So a text message with no URL isn't dragged toward zero by a missing domain score.

### Overrides (floors)
High-confidence combinations set a minimum score, regardless of averaging:

| Condition | Floor |
|---|---|
| Requests SSN / bank / password / MFA code **and** links to a lookalike domain (score ≥ 60) | 90 |
| Impersonates IRS **and** demands gift card / crypto / wire | 85 |
| Homoglyph domain of a protected brand | 80 |
| Injection attempt detected **and** any other scam signal | 70 |

A mitigating cap also applies: if every URL is official, no sensitive data is requested, and there's no payment demand, the score is capped at 40. This keeps real IRS and Intuit notices out of `likely_scam`.

### Verdict bands
`0–29 likely_legitimate · 30–59 suspicious · 60–100 likely_scam`

### Response

```json
{
  "analysis_id": "an_01J…",
  "verdict": "likely_scam",
  "risk_score": 90,
  "module_scores": { "domain": 70, "message": 82 },
  "modules_run": ["domain", "message", "verify"],
  "degraded": [],
  "reasons": [
    {
      "module": "domain",
      "signal": "brand_plus_keywords",
      "detail": "'irs-refund-secure' combines the IRS name with trust keywords: refund, secure",
      "evidence": "irs-refund-secure.com",
      "points": 70
    }
  ],
  "overrides_applied": ["sensitive_request_with_lookalike"]
}
```

Weights, points, and floors live in `config/scoring.yaml`. They're tuned on the **dev** split only.

---

## 10. Evaluation harness

### Dataset (`data/eval/`)

| Slice | Source | Label |
|---|---|---|
| Phishing URLs / domains | OpenPhish community feed, PhishTank archives (filtered to tax/financial brands where possible), stored defanged | scam |
| Phishing email bodies | Public phishing corpora (e.g. Nazario corpus), filtered + relabeled | scam |
| Synthetic tax scams | Hand-written + LLM-generated, then manually reviewed: SMS, email, refund, suspension, payment demands, all 4 brands, with injection variants | scam |
| Synthetic screenshots | Rendered images of synthetic scam and legitimate messages | scam / legitimate |
| Legitimate tax comms | Official IRS public pages/notices text, Intuit public help/marketing emails, real legitimate domains | legitimate |
| Hard negatives | Legit messages that are *urgent* or mention refunds (real deadline reminders, H&R Block/TaxAct domains, banks) | legitimate |

Every record: `{id, input_type, content (URLs defanged), label, brand, source, synthetic: bool, split}`. Splits are 60/20/20 with a fixed seed, stratified by `input_type × label × synthetic`. Near-duplicates are clustered **before** splitting so templates can't leak across splits.

### Metrics
- Precision, recall, F1, FPR, and confusion matrix, treating `likely_scam` as positive. `suspicious` is reported as a separate "triage" rate.
- Broken down by input type, brand, and real vs. synthetic.
- **Ablations:** rules-only · LLM+rules · ±verification · Groq vs. Claude (optional).
- **Robustness:** the injection-paired set (verdict-band stability).

### Running
`python -m scamsentinel.eval --split test --report reports/eval-YYYYMMDD.md` writes a markdown report and JSON metrics. The README table is copied from the latest test-split report.

---

## 11. Data model (SQLite)

```
analyses(id, created_at, input_type, input_hash, verdict, risk_score, result_json, expires_at)
llm_cache(key PK, provider, model, prompt_version, features_json, created_at)
ct_candidates(...)   -- post-MVP (P1)
```

Uploaded images are processed in memory and never written to disk. Analyses older than `expires_at` (7 days by default) are purged on startup and daily.

---

## 12. Observability
- Structured logs with PII redaction (`security/redaction.py`).
- Per-module latency, LLM token usage, cache hit rate, grounding-drop rate, and LLM/rule disagreement rate.
- `/healthz` reports the LLM provider/model and whether a key is configured (later: OCR availability).

---

## 13. Key trade-offs

| Decision | Alternative | Why |
|---|---|---|
| LLM → features, rules → verdict | End-to-end LLM classification | Explainability and injection resistance; testable scoring |
| Max-over-techniques domain score | Learned domain classifier | Transparent and needs no training data; a classifier can be an ablation later |
| Renormalized weights + floors | Plain weighted average | Missing modules don't dilute scores; strong combos aren't averaged away |
| Never fetch URLs (MVP) | Fetch pages to inspect them | Removes SSRF and contact with attacker servers entirely; page analysis is post-MVP |
| Plain venv, no Docker | Containers per component | Fast to set up and iterate; isolation comes back with page fetching post-MVP |
| SQLite | Postgres | Single-user local tool; schema is portable |
| Images only for uploads | PDF/Office support | Much smaller parser attack surface |

---

## 14. Post-MVP roadmap

Built only after the MVP works end to end and has evaluation numbers.

| Phase | What | Notes |
|---|---|---|
| **P1** | **Certificate Transparency watcher** | Poll crt.sh politely (every 6 h, sequential, backoff) for certificates containing brand tokens. Score each new name with the existing domain engine and store candidates ≥ 50. Expose `GET /v1/ct/candidates`. Cheap, because the domain engine already exists. Stubs live in `scamsentinel/ct/`. |
| **P2** | **Lightweight page fetch** | `httpx` + an HTML parser (no browser). Look for credential/SSN forms, forms posting to other domains, and brand mentions on unofficial domains. **Requires the SSRF URL guard first** (strict parsing, resolve-then-pin, reject non-global IPs, re-check every redirect hop). Guard stub and payload tests already exist. |
| **P3** | **Headless-browser sandbox** | Playwright for JavaScript-rendered pages, screenshots and redirect chains, run in an isolated container with an egress proxy that blocks internal addresses. |
| **P4** | **Docker packaging** | Containerize the API, OCR and (with P3) the sandbox with locked-down settings. |
