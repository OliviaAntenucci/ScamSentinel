# Architecture

This document describes the **MVP**, plus what has been built since: the Certificate Transparency watcher ([§15](#15-certificate-transparency-watcher-p1)), the brand-agnostic core with scam categories ([§16](#16-scam-categories-and-the-brand-agnostic-core)), and the LLM fact check for organizations without curated facts ([§17](#17-fact-check-for-organizations-without-curated-facts)). Planned work is in [§14 Post-MVP roadmap](#14-post-mvp-roadmap). Examples throughout use the tax category (the baseline); the same machinery serves every category.

## 1. Design principles

1. **The LLM extracts, the rules decide.** The language model turns messy text into structured features. Deterministic, unit-tested rules turn the features into a score. This keeps verdicts explainable and limits the damage prompt injection can do.
2. **Every point is accounted for.** Every module score is built from reasons that carry points, so each verdict can be audited.
3. **Untrusted by default.** User input, uploaded images, and LLM output all get validated at the boundary. See [`SECURITY.md`](SECURITY.md).
4. **Graceful degradation, honest failure.** If the text LLM is unavailable, the analysis still finishes rules-only and says so. A screenshot that can't be read is an error (503), never a silent "likely legitimate".
5. **Never touch attacker infrastructure (MVP).** URLs are analyzed as strings only. ScamSentinel never connects to a user-supplied URL, which removes SSRF by design.
6. **Runs on a laptop.** A Python virtual environment and nothing else: no Docker, no headless browser, no OCR engine to install. Screenshots are read by a Groq vision model.

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
                  │  (incl. defanged) · screenshot → vision → text│
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
                                          ▼
                  Next-steps guide (E1, §18): fixed templates ─▶ next_steps[]
```

### Interface

ScamSentinel serves a lightweight browser UI and its HTTP API from the same local FastAPI process. Run `python -m scamsentinel` and open `http://127.0.0.1:8000`; the UI submits to the same-origin API, so CORS is not needed. The API remains available to command-line clients, and FastAPI's auto-generated OpenAPI page at `/docs` serves as the API reference. The server binds to loopback only. If an LLM provider is configured, message text may be sent to that provider; otherwise analysis uses local rules.

### Runtime

| Piece | How it runs |
|---|---|
| API + all analysis modules | One Python process (`python -m scamsentinel`), listening on `127.0.0.1:8000` only |
| Screenshots | In-process header validation and byte-level sanitizing (no image decoder runs locally), then an HTTPS call to a Groq vision model to transcribe the text. Requires `GROQ_API_KEY` |
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
  domain/         # registrable-domain parsing, homoglyphs, distance, keywords, scorer;
                  #   explain.py (E2): how a lookalike imitates its brand
  message/        # feature schema, rule extractor, LLM extractor, merger
  verify/         # trusted-facts checks
  ocr/            # vision.py: Groq vision transcriber + cache
  web/            # browser UI (index.html, app.js, app.css), served at / and /static
  aggregate/      # weights, floors, verdict bands, reason assembly
  guidance/       # E1: next_steps.py, "what should I do next?" chosen from the evidence;
                  #   E4: scenarios.py, named scam scenarios from data/scenarios.yaml
  security/       # upload_guard.py, image_sanitize.py, redaction.py (url_guard.py is post-MVP)
  ct/             # P1: crt.sh client, CT watcher (python -m scamsentinel.ct), candidate store
  eval/           # dataset loader, runner, metrics, ablations, report
config/
  scoring.yaml    # weights, bands, floors, technique points
data/
  brands.yaml     # scam categories; protected brands, their category, official domains, tokens
  keywords.yaml   # stuffing keywords, urgency phrases, payment methods
  facts.yaml      # trusted facts for verification (with sources)
  guidance.yaml   # E1 next-step templates and their references
  scenarios.yaml  # E4 named scenarios: rules, descriptions, sources, own next step
  resources.yaml  # "Learn more" links: scam-type articles, organizations' help pages
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
| `typosquat` | Normalized Damerau-Levenshtein ≤ 0.2 between a brand token (min length 4) and any part, or sliding window, of the label; also the brand plus a stray character or two | `turbotxa.com`, `quickbook.com`, `turbotaxx.com` | 60–80 (scaled by similarity), +10 per keyword |
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
  "impersonated_entity": { "value": "<a brand name from brands.yaml>|other|none", "span": "..." },
  "urgency":            { "level": 0, "spans": ["..."] },
  "payment_methods":    [{ "method": "gift_card|crypto|wire|zelle|cash_app|venmo|other", "span": "..." }],
  "sensitive_requests": [{ "type": "ssn|bank_account|password|mfa_code|card|id_photo|dob", "span": "..." }],
  "claimed_urls":       ["..."],
  "claimed_phone_numbers": ["..."],
  "call_to_action":     { "value": "click_link|call_number|reply|pay|none", "span": "..." },
  "threats":            [{ "type": "arrest|account_suspension|refund_loss|delivery_hold|suspicious_activity|access_loss|device_infected|job_offer_loss|penalty|legal_action", "span": "..." }],
  "injection_attempt":  { "detected": false, "span": "" }
}
```

  There is no verdict or score field, and the schema rejects unknown fields.
- **Grounding check:** each `span` must appear in the normalized input (case/whitespace-insensitive). Features that fail the check are dropped and counted.
- **Caching:** successful extractions are cached in SQLite (`CachedExtractor`), keyed on `sha256(provider + model + prompt_version + whitespace-normalized text)`. Failures aren't cached. Cached features are re-grounded against each input like fresh ones.

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
| `contact_channel` | Input type + entity | IRS contacting by SMS/email (or a screenshot of one) while asking for sensitive information, demanding an *unusual* payment method (gift card, crypto, wire, P2P app), or sending to an unofficial link. Pointing to an official payment channel ("pay through IRS Direct Pay") doesn't count |
| `payment_method_policy` | Payment methods + entity | A fact says the entity doesn't take that method (IRS: gift card / crypto / wire / P2P apps) |
| `phone_number` | Claimed phone numbers + entity | Number isn't among the entity's published numbers (reported as "can't verify", lower weight) |
| `sender_alignment` (email) | From / Reply-To / DKIM `header.d` | Claims a brand but sent from another domain, or Reply-To goes to a different domain. An official sender with passing DKIM is mitigating |
| `sender_alignment`: `link_sender_mismatch` (email, any brand) | From domain + links + threats and requests | An account-security email (a suspicious-activity, suspension or lockout threat, or a request for a password, code or other sensitive data) links to a domain other than the sender's. Subdomains of the sender and any protected brand's official sites don't count (GovDelivery linking to irs.gov is fine). Needs no protected brand, so it covers "Northstar"-style senders the brand list doesn't know. 25 points |

Output: `[{check, claim, verified: true|false|null, source, detail}]`. Checks that come back `false` become reasons. A check that passes, such as "link goes to irs.gov," is shown as a mitigating reason and lowers the score.

---

## 7. Input handling

| Input | Handling |
|---|---|
| Text (`text`) | Up to 20,000 characters. URLs and domains extracted, including defanged forms |
| URL (`url`) | Scored by the domain engine only (running the message analyzer on the URL string would count the same evidence twice). **Never fetched** |
| Email (`email_raw`) | Parsed with Python's `email` package. HTML bodies converted to text with an HTML parser, never rendered; link `href` targets are collected separately. Attachments listed by name/type/size, never opened. The domain module scores body links, link targets, and the From / Reply-To domains |
| Screenshot (`POST /v1/analyze/image`, raw body) | Upload guard → sanitize → vision transcription (§8) → treated as text, with `input_type: "image"`. If the transcribed text shows email headers (`From: Name <a@b.example>`, `Reply-To:`), they're read by `headers_from_text` and get the email sender checks, and the sender domains are scored. A screenshot never verifies a sender: there's no trusted `Authentication-Results`, so a pictured "dkim=pass" is ignored |

---

## 8. Screenshot analysis

```
raw image body (image/png | image/jpeg | image/webp | application/octet-stream)
  ─▶ body-size cap (6 MB) ─▶ upload_guard: magic bytes, 5 MB, 25 MP read from the header
  ─▶ image_sanitize: rebuild the file from display-critical chunks only
       PNG  keep IHDR PLTE tRNS IDAT IEND gAMA cHRM sRGB (CRC-checked); stop at IEND
       JPEG drop APP1–13, APP15, COM; keep APP0/APP14; stop at the first EOI after SOS
       WebP keep VP8/VP8L/VP8X/ALPH/ANIM/ANMF; drop EXIF/XMP/ICCP; clear VP8X metadata flags
  ─▶ Groq vision model (qwen/qwen3.8-27b): "transcribe all visible text", JSON {"text": …}
  ─▶ transcription ─▶ same path as a pasted message (rules + text LLM + verify + domains)
```

- **No local image decoding.** Header parsing and chunk copying are plain byte operations, so image-library parser bugs and decompression bombs can't hit our process. The only decoder is Groq's.
- **Why sanitize at all:** EXIF/GPS and other metadata would otherwise go to a third party, and bytes appended after the end-of-image marker (polyglots) are dropped.
- **The vision model only transcribes.** Its text is scored by the same rules and grounded LLM features as any message. An `ocr` reason records the image size, type and model.
- **Endpoint:** `POST /v1/analyze/image` with the raw image as the body. Image content types aren't CORS "simple" types, so other websites can't send them without a preflight (unlike `multipart/form-data`), and no multipart parser is needed.
- **Failures are errors, not verdicts:** no Groq key or vision failure (timeout, rate limit, retired model) → 503; no text in the image → 422; rejected file → 422 / 413.
- **Caching:** transcriptions are cached by the SHA-256 of the sanitized image (7-day retention, like other LLM results).
- **Preview model:** Groq lists its only vision model as *preview* ("may be discontinued at short notice"). The model is configurable (`SCAMSENTINEL_VISION_MODEL`), and a retired model surfaces as `503 … model_not_found`.
- Each screenshot costs up to two LLM calls (transcription + feature extraction).

---

## 9. Risk aggregator

### Module scores
Each module produces `score ∈ [0,100]` and `reasons[]` (each with `points`). Verification has no module score of its own. Its reasons add points to the message module. When an input has several links, the domain module's score is the worst (highest) domain's score, and reasons are listed for up to 5 flagged domains. At most 20 domains are scored per input.

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
| Impersonates a brand **and** demands a payment method that brand's facts say it never uses (e.g. the IRS and gift cards, crypto, wire, P2P apps) | 85 |
| Homoglyph domain of a protected brand | 80 |
| Injection attempt detected **and** any other scam signal | 70 |

A mitigating cap also applies: if the input has at least one link, every link is official, and nothing sensitive, no payment and no AI instructions are requested, the score is capped at 40. This keeps real IRS and Intuit notices out of `likely_scam`. The cap is applied first, then the floors.

The aggregator explains itself: it appends `aggregate` reasons (0 points) showing the weighting math (`Weighted score: domain 70 × 0.55 + message 100 × 0.45 = 84`) and every cap or floor that changed the result.

### Verdict bands
`0–29 likely_legitimate · 30–59 suspicious · 60–100 likely_scam`

### Response

```json
{
  "analysis_id": "an_3f1c…",
  "created_at": "2026-10-14T21:05:11Z",
  "input_type": "text",
  "verdict": "likely_scam",
  "risk_score": 90,
  "module_scores": { "domain": 70, "message": 100 },
  "modules_run": ["domain", "message"],
  "llm_used": true,
  "degraded": [],
  "reasons": [
    {
      "module": "domain",
      "signal": "brand_plus_keywords",
      "detail": "'irs-refund-secure' combines the IRS name with trust keywords: refund, secure",
      "evidence": "irs-refund-secure.com",
      "points": 70
    },
    { "module": "message", "signal": "sensitive_request", "detail": "Asks for a Social Security number: \"SSN\"", "points": 25 },
    { "module": "verify", "signal": "contact_channel", "detail": "The IRS does not initiate contact … [source: https://www.irs.gov/…]", "points": 25 },
    { "module": "aggregate", "signal": "weighted_score", "detail": "Weighted score: domain 70 × 0.55 + message 100 × 0.45 = 84", "points": 0 },
    { "module": "aggregate", "signal": "floor:sensitive_request_with_lookalike", "detail": "Raised to at least 90: asks for sensitive information and links to a lookalike domain", "points": 0 }
  ],
  "overrides_applied": ["sensitive_request_with_lookalike"],
  "disagreements": []
}
```

Weights, points, and floors live in `config/scoring.yaml`. They're tuned on the **dev** split only.

---

## 10. Evaluation harness

### Dataset (`data/eval/samples.jsonl`)

332 hand-written samples in six categories (tax 152, delivery 39, bank 39, and 34 each for account takeover, tech support and job scams; see §16 for the later ones). **Tax** (the MVP set, 152): 40/35 scam/legitimate texts, 12/10 emails, 30/25 URLs, across all four tax brands plus brandless scams. **Delivery** (39): 10/8 texts, 5/5 emails, 6/5 URLs. All categories have deliberate hard negatives and off-vocabulary scams. Composition, rules and limitations are in [`data/eval/SOURCES.md`](data/eval/SOURCES.md). Real-world corpora (OpenPhish / PhishTank URLs, public phishing-email corpora) are the planned next addition, marked `synthetic: false` and reported separately. Screenshots aren't in the set yet.

Every record: `{id, group?, input_type, label, brand, content (scam URLs defanged), source, synthetic, notes?}`. Validated by `eval/dataset.py` (unique ids, known fields), and tests enforce that scam links are defanged.

### Splits (`eval/dataset.py`)
60/20/20 train/dev/test, **stratified** by `category × input_type × label` and **grouped**: variants of one template share a `group`, and whole groups are ordered by a seeded SHA-256 hash and cut by position, so a template never straddles two splits and the assignment is deterministic. Because category is part of the stratum, adding a category never moves another category's samples between splits; a test checks that the tax splits are identical with or without the other categories.

**Protocol:** rules, weights and floors are tuned on **dev** only. **Test** is run once per release for the reported numbers, and its errors are reported, not fixed. (M6 example: the dev run exposed a dilution bug and two missing floors, which were fixed. The test run was then made once, and its misses, brandless scams, are documented as limitations.)

### Metrics (`eval/metrics.py`, `eval/report.py`)
- Precision, recall, F1, FPR and confusion counts with scam as the positive class: **strict** counts `likely_scam` only; **triage** also counts `suspicious`.
- Broken down by category, input type, brand, and synthetic vs. real (`--category` restricts a run to one category); a verdicts-by-label table; and every misclassified sample with its score and signals.
- **Ablations** (`--ablation`): `rules_only` (default, no API calls), `full` (rules + LLM when `GROQ_API_KEY` is set; results cached in `var/eval.db`), `no_verify` (verification contributes 0 points).
- **Robustness** is tested separately: the 30-variant prompt-injection paired corpus (`tests/security/test_prompt_injection.py`).

### Running
`python -m scamsentinel.eval --split test --report reports/eval-test.md --json reports/eval-test.json` writes a markdown report and JSON metrics plus predictions (`reports/` is gitignored). The README table is copied from the latest test-split report.

---

## 11. Data model (SQLite)

```
analyses(id PK, created_at, expires_at, input_type, input_hash, verdict, risk_score, result_json)   -- expires_at unused ('')
input_images(analysis_id PK, mime, data)   -- the cleaned screenshot behind an image analysis
llm_cache(key PK, provider, model, features_json, created_at)   -- key = sha256(provider, model, prompt version, normalized text)
accounts(id PK, email UNIQUE, password_hash, created_at)
account_sessions(token_hash PK, account_id, expires_at)
saved_analyses(account_id, analysis_id, created_at, result_json)   -- PK (account_id, analysis_id)
ct_candidates(domain PK, registrable, score, brand, techniques, cert_id, issuer, not_before, first_seen, last_seen)   -- P1
ct_polls(id PK, started_at, finished_at, queries, failed_queries, names_seen, candidates, new_candidates)             -- P1
```

`scamsentinel/store.py` opens a fresh connection per call (safe under FastAPI's thread pool). Each result carries what was submitted (`submitted.content`: the message, URL or raw email as entered, or the text read from a screenshot), with SSN- and card-like numbers masked by the same redaction as the rest of the result. For a screenshot, the cleaned image is stored in `input_images`. That's the re-encoded image with its metadata stripped and anything appended removed, never the upload as sent. `GET /v1/analysis/{id}/image` and, for a saved analysis, the account-scoped `GET /v1/saved/{id}/image` serve it with its exact image type, `nosniff`, and a `default-src 'none'; sandbox` CSP. Analyses and their inputs are kept until deleted: nothing expires them. Saving copies the result, input included, into the account's `saved_analyses`. Only cached LLM features expire after 7 days, because they hold unredacted quotes. Results from before inputs were kept have no `submitted` field and still load.

The CT tables (`ct/store.py`) live in the same file. They hold public certificate data, not user input, so they aren't purged. The watcher process writes them and the API only reads them.

---

## 12. Observability
- Structured logs with PII redaction (`security/redaction.py`).
- Per-module latency, LLM token usage, cache hit rate, grounding-drop rate, and LLM/rule disagreement rate.
- `/healthz` reports the LLM provider/model, whether a key is configured, the vision model, and whether screenshots are available.
- The browser UI (`/`, `/static/*`) is served with a strict Content-Security-Policy (same-origin scripts, styles and requests only; `blob:` images for the screenshot preview; no framing).

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
| Vision LLM for screenshots, byte-level sanitizing | Local OCR (Tesseract, RapidOCR) with Pillow re-encoding | Nothing to install and no image decoder in our process; costs: screenshots need a Groq key, leave the machine, and depend on a preview model |

---

## 14. Post-MVP roadmap

Built only after the MVP works end to end and has evaluation numbers. Done: P1 (CT watcher), G1 (brand-agnostic core + delivery category), G2 (bank impersonation), E1 (next steps), E2 (domain explanations), E3 (fact-check summary), G3 (account takeover, tech support, job scams), E4 (named scenarios), P2a (page fetch, off by default) and P2b (scoring with page evidence, measured on saved page snapshots). Also built alongside them: the brand-agnostic `link_sender_mismatch` email check (§6) and sender checks for screenshots of emails (§7). Next: P3 → P4.

### Scam categories (G1 ✅, G2 ✅, G3 ✅)

See [§16](#16-scam-categories-and-the-brand-agnostic-core). G3 added **account takeover** (Google, Apple: password-expiry, deletion and MFA-code lures), **tech support** (Microsoft: virus pop-ups and callback numbers) and **job scams** (Indeed: upfront fees, equipment payments, ID and SSN requests), each with sourced facts, its own phrases, hard negatives and its own reported metrics. Open work for them is listed in §16's known limitations.

### Explain and guide (E1–E4)

ScamSentinel's angle is being an explainable checker that runs locally and shows its evidence, not a black-box score. This phase builds on that. All four items follow design principle 1: the output comes from deterministic templates and data files keyed on signals the rules already produce. The LLM doesn't write advice or explanations.

| Phase | What | Notes |
|---|---|---|
| **E1** ✅ | **"What should I do next?"** (built: see [§18](#18-what-should-i-do-next-e1)) | Each result gets a short, cautious `next_steps[]` list, chosen from fixed templates by the evidence that fired. Examples: a sensitive-data request → "Don't reply with personal information"; an IRS or brand impersonation → "Contact the agency using a number from its official website or your paperwork, not the one in the message"; a gift-card or crypto demand → "The IRS doesn't take payment this way. Don't pay." Official contact details come only from `data/facts.yaml`, with sources. **Links and phone numbers found in the analyzed message are never repeated, opened or recommended.** Advice is worded cautiously and never promises safety; a `likely_legitimate` verdict still says to verify through a channel you already trust. Shown in the UI below the verdict. |
| **E2** ✅ | **Richer domain explanations** (built: see [§19](#19-richer-domain-explanations-e2)) | Before E2, each domain technique carried only a one-line `detail`. Add a structured explanation of *what* differs from the real brand: the swapped characters (`0` for `o`, Cyrillic `і` for `i`), the misspelling (`turbotxa` vs. `turbotax`), the misleading extra words (`-refund-secure`), or the real owner of a brand-in-subdomain URL. Built from data the engine already computes (skeleton, edit operations, keywords, PSL split). |
| **E3** ✅ | **Fact-check summary** (built: see [§20](#20-fact-check-summary-e3)) | The verification layer already evaluates every check as matched / conflicts / can't verify (`CheckResult.verified`), but only failures and mitigations reach the response, as reasons. Expose the full list as `fact_checks[]`: each claim in the message, the trusted fact it was compared with, the outcome, and the fact's source and last-reviewed date. Shown in the UI as a matches / conflicts table. |
| **E4** ✅ | **Named scenarios per category** (built: see [§21](#21-named-scenarios-e4)) | Recognize named scenarios, such as (tax) refund delay or "refund on hold", balance due or payment demand, identity verification, fake tax-prep or "IRS agent" offers, and (delivery) "package on hold", incomplete address, redelivery fee. Each scenario is a rule over existing signals in a new `data/scenarios.yaml` with a plain-language description and its own E1 next steps. Reported as `scenario` on the result (0 points: it explains the score and doesn't change it). New scenarios are added over time as data, each with eval samples. |

E1–E4 change no scores, so evaluation numbers stay comparable. Each needs tests that the advice and explanations never quote a URL or phone number from the input, and that every result still has at least one reason (AC-6).

### Infrastructure phases

| Phase | What | Notes |
|---|---|---|
| **P1** ✅ | **Certificate Transparency watcher** | Poll crt.sh politely (every 6 h, sequential, backoff) for certificates containing brand tokens. Score each new name with the existing domain engine and store candidates ≥ 50. Expose `GET /v1/ct/candidates`. Cheap, because the domain engine already exists. See [§15](#15-certificate-transparency-watcher-p1). |
| **P2** ✅ (P2a + P2b) | **Lightweight page fetch** (built: see [§23](#23-lightweight-page-fetch-p2); off by default; page evidence is scored but can only raise a score) | `httpx` + an HTML parser (no browser). Look for credential/SSN forms, forms posting to other domains, and brand mentions on unofficial domains. **Requires the SSRF URL guard first** (strict parsing, resolve-then-pin, reject non-global IPs, re-check every redirect hop). Guard stub and payload tests already exist. |
| **P3** | **Headless-browser sandbox** | Playwright for JavaScript-rendered pages, screenshots and redirect chains, run in an isolated container with an egress proxy that blocks internal addresses. |
| **P4** | **Docker packaging** | Containerize the API and (with P3) the sandbox with locked-down settings. |

---

## 15. Certificate Transparency watcher (P1)

Phishing sites almost always get a TLS certificate, and every publicly trusted certificate lands in a Certificate Transparency log. Watching those logs finds lookalike domains *before* anyone reports them.

```
python -m scamsentinel.ct  (separate process; --once for a single pass)
  every 6 h:  for each brand pattern ─▶ crt.sh JSON search (sequential, spaced, backoff)
              ─▶ split SANs, validate hostnames, dedupe ─▶ domain engine (§4)
              ─▶ keep non-official names scoring ≥ 50 ─▶ ct_candidates (SQLite)
API:  GET /v1/ct/candidates?since=&min_score=&limit=  ─▶ reads ct_candidates
```

- **Search patterns** come from `data/brands.yaml`. Long tokens match anywhere (`%turbotax%`, `%quickbooks%`, `%creditkarma%`). Whole-word tokens (`irs`, `intuit`) are anchored to the start of a name or a `.`/`-` separator (`irs%`, `%.irs%`, `%-irs%`), because a bare `%irs%` matches every certificate for "first" or "shirts" and times out. Expired certificates are excluded.
- **Politeness** (`ct/client.py`): one request at a time, at least 10 s apart, a descriptive `User-Agent`, up to 4 attempts with exponential backoff (30 s, 60 s, 120 s, capped at 10 min) on timeouts, network errors, 429 and 5xx, honoring `Retry-After`. Redirects aren't followed. Responses over 64 MB are refused. Polling more often than hourly is refused by the settings.
- **Untrusted data.** Certificate names are chosen by whoever requested the certificate. Each one must be a plain lowercase ASCII hostname (wildcards reduced to their domain; IPs, emails and anything else dropped), and other fields are length-capped. Names are only scored as strings. Nothing ever resolves or connects to them.
- **Dedupe.** A name found by several patterns is scored once per pass (at most 50,000 names per pass). A domain already stored keeps its `first_seen` and first certificate; later passes refresh its score, techniques and `last_seen`. A failed query is logged and skipped, and every pass is recorded in `ct_polls`, which the API returns as `last_poll` so an empty list can be told apart from a watcher that never ran.
- **Settings:** `SCAMSENTINEL_CT_POLL_INTERVAL_HOURS` (default 6, minimum 1), `SCAMSENTINEL_CT_MIN_SCORE` (50), `SCAMSENTINEL_CT_TIMEOUT_SECONDS` (120).
- **Limitations.** crt.sh search is substring-based, so lookalikes that never contain a brand token literally (`turb0tax`, Cyrillic homoglyphs, `quickbook`) aren't found, even though the engine would score them. crt.sh is a free community service and is often slow or unavailable, so passes can partially fail. Candidates are unverified leads: a certificate is not proof of a live phishing site.

---

## 16. Scam categories and the brand-agnostic core

Scams differ by lure (a held refund, a held package, a locked bank account) but share the same evidence: impersonation, lookalike links, urgency, payment and data demands, and claims that contradict the impersonated organization's own published policies. ScamSentinel's code detects that shared evidence. Everything specific to an organization or a kind of scam is **data**, grouped into categories.

### What a category is

| Piece | Where | Example (delivery) |
|---|---|---|
| Category | `data/brands.yaml` → `categories` | `delivery`: package-delivery smishing |
| Brands | `data/brands.yaml` → `brands` (each with `category`, tokens, official domains, sources) | USPS: token `usps`, official `usps.com`, `uspis.gov` |
| Trusted facts | `data/facts.yaml` (statement, source URL, last-reviewed date) | USPS doesn't text or email unless you asked for tracking, and those messages contain no link ([uspis.gov](https://www.uspis.gov/news/scam-article/smishing)); published phone numbers |
| Signals | `data/keywords.yaml` | Brand mentions (`usps`, `u.s. postal service`), the `delivery_hold` threat ("package is on hold", "incomplete address", "returned to sender"), trust keywords for domains (`redelivery`, `parcel`, `tracking`) |
| Labeled data | `data/eval/samples.jsonl` with `"category"` | 21 scams and 18 legitimate, including hard negatives |

The bank category (G2) adds Chase, Bank of America and Wells Fargo. Banks do text and email their customers, so they have no first-contact-channel fact. What they publish instead is what they never *ask for*. A new fact kind captures that: `disallowed_requests` (sensitive-request types, optionally limited to `channels`), checked as `request_policy`. It also adds a `suspicious_activity` threat ("unusual activity", "unauthorized charge"; LLM prompt v3), and PINs and access/authorization codes as sensitive-request phrases.

### What's generic (no organization named in code)

- **Domain engine** (§4): tokens and official domains come from `brands.yaml`, so every technique (homoglyph, typosquat, keyword stuffing, TLD swap, subdomain abuse) works for any brand. A token that is an ordinary word can be marked `boundary_tokens` (whole word only: "purchase" isn't Chase) and `no_typo_tokens` (never matched by edit distance: "phase" and "chose" are one letter from "chase").
- **Message features** (§5): `impersonated_entity` accepts any brand from `brands.yaml`, plus `other` / `none`. The LLM's JSON schema enum and prompt are built from the same list. In JSON-object mode (no enforced enum), a name outside the list becomes `other`, and the analyzer re-checks merged features, so neither the LLM nor a stale cache entry can introduce a "protected" brand the rules don't know. The entity list is part of the LLM cache key.
- **Verification** (§6): checks are driven by each entity's facts (`official_domains`, `disallowed_first_contact_channels`, `disallowed_payment_methods`, `disallowed_requests`, `phone_numbers`). A brand without a given kind of fact simply doesn't get that check.
- **Floors** (§9): `disallowed_payment_demand` (formerly `irs_unusual_payment_demand`) fires when a brand's own payment-policy fact fails, so it applies to any brand that publishes one. For the IRS it behaves exactly as before.
- **CT watcher** (§15): search patterns come from `brands.yaml`.
- **Load-time validation:** brand names are unique and not `other` / `none`; every brand's category is defined; `entity_mentions` names only known brands; every fact's entity is a known brand; every category has facts and at least 15 scam and 15 legitimate eval samples (tests).

### Adding a category

1. Define it in `brands.yaml` and add its brands with sources.
2. Add trusted facts with sources and review dates. Only add facts the organization itself publishes.
3. Add its phrases to `keywords.yaml`. A new threat type also needs the `ThreatType` literal and a label in `message/scoring.py` (and bumps the LLM prompt version).
4. Write labeled samples with `"category"`: scams, hard negatives that resemble them, and off-vocabulary scams so recall isn't flattered. At least 5 per category × input type × label, so every stratum reaches dev and test.
5. Check the existing categories' test numbers are unchanged, tune on the new category's dev split only, run its test split once, and report its metrics separately.

New trust keywords are shared by every brand's domain scoring. Adding the delivery keywords left the tax category's numbers unchanged (re-run 2026-10-15), and so did adding the G3 keywords and rule changes for tax, delivery and bank (re-run 2026-10-15). That check is part of every new category.

**One category per brand.** A brand belongs to exactly one category, so Microsoft account phishing is counted under `tech_support`, Microsoft's category.

**Ordinary words as brand names.** `apple`, `outlook` and `indeed` are whole-word, no-typo tokens (like `chase`). Their text mentions are limited to forms that name the company ("Apple ID", "Indeed Recruiter"). Bare "google" and "gmail" aren't mentions either: "Google Play cards" is a payment demand, and a `gmail.com` sender is just a personal address.

### Known limitations

- **Brandless scams** are the weak spot in every category: the strongest evidence (lookalike domains, fact checks, floors) depends on knowing which organization is being impersonated.
- **Facts are uneven across brands.** The IRS has a published payment policy, so a gift-card demand hits the 85 floor; USPS has no equivalent sourced fact, so the same demand scores on message signals only.
- **What isn't a request.** Real bank messages mention codes, cards and payment apps all the time. The rule extractor skips a code being delivered ("your code is 482913"), a card or account named by its last four digits ("card ending in 4421"), and money coming in ("You received $40 via Zelle"). Since G3 it also skips a code shown before the phrase ("G-482913 is your Google verification code", but not digits after a hyphen, as in a phone number), and a password that's only mentioned: one that changed or expires, or what someone did or should do with it ("someone knows your password", "reset your password"). A reset lure still scores through its link and threat. Any other mention still counts. A merchant receipt that names a Chase card is still read as a claim to be Chase.
- **Tech support and job scams (G3)** are the weakest categories (strict recall 50% and 61% on all samples). Microsoft publishes that its error messages never include phone numbers, but nothing checks that yet, so "virus detected, call this number" stops at *suspicious*. "windows" isn't a Microsoft token, and refund lures name brands that aren't protected (Norton, Geek Squad). Most job scams name no protected company, so a gift-card or crypto "training fee" scores on message signals only.
- **Unofficial Google hosts.** `googleapis.com` and `googleusercontent.com` aren't marked official, because anyone can host a page there, and Google's country sites (`google.co.uk`) aren't either, because they'd need a sourced list. Links to them score as unofficial.
- **Short tokens** (`usps`, 4 letters) only get typosquat detection for an added character (`uspss`); a substituted letter (`uspz`) is below the edit-distance threshold.

---

## 17. Fact check for organizations without curated facts

Curated categories cover a handful of organizations. When a message claims to come from **any other organization**, an LLM fact check fills part of the gap: it checks the message's links against the official domains the model knows for that organization.

```
LLM features: impersonated_entity = "other", span "Acme Bank"  (grounded: verbatim in the message)
  and the message has links
    ─▶ second LLM call (verify/org_facts.py): "Acme Bank" inside <untrusted_name_{nonce}>
       ─▶ {known, canonical_name, official_domains[]}  (strict schema, strict validation)
       ─▶ sanitize: plain registrable domains only; give up if the name contains one of them
    ─▶ each link's registrable domain vs. those domains
       conflict ─▶ reason org_domain_mismatch_unverified (+10), labeled "model knowledge"
       match    ─▶ recorded (verified: null), 0 points
```

**Why it's fenced in.** Curated facts come from the organization's own published pages; this comes from a model's memory, and the organization name was written by the possible scammer. So:

| Guard | What it prevents |
|---|---|
| Runs only for a grounded `other` entity, never for curated brands | The LLM overriding sourced facts, or inventing an organization that isn't in the message |
| Name capped at 64 chars, sent in an unguessable delimiter as data | Instructions smuggled in through the name |
| Strict schema + strict Pydantic validation; domains must be plain registrable domains | Malformed or coerced replies |
| No answer used if the name contains any returned domain | "Acme Bank (acme-secure-login.com)" talking the model into echoing the attacker's domain |
| **Risk-only:** a match earns nothing, only a conflict adds points | A wrong or manipulated answer can at most suppress one 10-point reason; it can never make a scam look legitimate |
| Fewer points than sourced checks (10 vs. 20), no floor depends on it, detail says "according to the model's knowledge, not a published source" | Overweighting unverified evidence |
| Cached 7 days in the LLM cache table (keyed by provider, model, prompt version, name); failures aren't cached and show as `degraded: ["org_fact_check_unavailable:<reason>"]` | Repeat cost; silent failure |

**Cost and switches.** One extra Groq call, only for messages that name an uncurated organization *and* contain links. Off without a Groq key, or with `SCAMSENTINEL_ORG_FACT_CHECK=false`. `/healthz` reports its state. Rules-only mode never runs it. In the eval harness it runs only with `--ablation full`.

**Limitations.** The model's knowledge can be outdated or wrong, and it doesn't know small or local organizations (`known: false` → no check). Legitimate organizations often link to third-party domains (email services, payment processors, link trackers), so a conflict is "suspicious", not proof; that's why it's worth only 10 points. Email sender domains aren't checked against the model's answer, for the same reason. It isn't included in the published metrics yet, because those are rules-only.

---

## 18. "What should I do next?" (E1)

A verdict tells you how worried to be; it doesn't tell you what to do. Every result also carries `next_steps[]`: up to seven short, cautious steps, most important first, chosen by the evidence that fired. It changes no scores. The report step is always kept: when there are too many steps, `already_acted` is dropped first, then the list is cut before the report step.

```
verdict + input type + merged features + domain results + verification checks
  ─▶ NextStepsGuide.build()   (guidance/next_steps.py)
       choose step ids by rule      ─▶ fill {placeholders} from data files only
       (no LLM involvement)            brands.yaml · facts.yaml · guidance.yaml
  ─▶ next_steps: [{id, text, source}]
```

### Which organization the advice names

The curated brand the message claims to be (`protected_entity`). If there isn't one, it's the brand of the highest-scoring link that is official or a lookalike (score ≥ 60). An `other` organization (named, but not curated) is never named in the advice, because its name was written by the possible scammer.

### Which steps, in order

A `likely_legitimate` result gets one step: `verify_brand` ("go to irs.gov by typing it in yourself") when a brand is known, otherwise `verify`. It never says "safe". Otherwise:

| Step | When | Filled from |
|---|---|---|
| `dont_open_link_brand` / `dont_open_link` | The brand's link check failed or a link is a lookalike of that brand / any lookalike, unverified-link conflict or unofficial link | Brand name |
| `dont_share` | Sensitive data was requested ("your Social Security number and your date of birth") | Fixed labels per request type |
| `dont_pay_policy` / `dont_pay` | An unusual payment method was demanded. The policy version is used when the brand's own payment fact failed ("IRS says it doesn't take payment by gift card") | Brand name, source of its payment fact |
| `dont_call` | A phone number in the message isn't a published one, or the message says to call without giving a known number | — |
| `scenario_<id>` (E4) | The message matches a named scenario (§21). It may stand in for the generic "don't" steps it covers (`replaces`) | `scenarios.yaml`, with a source |
| `contact_brand_with_phone` / `contact_brand` / `contact_unknown_org` / `contact_sender` | Always one of these: the brand's official site and first published number (or "a number from your own paperwork"), a generic "the organization it claims to be from", or "check with the sender through a channel you already trust" | `brands.yaml` official domain, `facts.yaml` phone numbers |
| `already_acted` | `likely_scam` and data or payment was requested | — |
| `report_brand_text` / `report_brand` / `report_text` / `report` | Always last: the brand's published report address (plus 7726 for texts), or 7726 / ReportFraud.ftc.gov | `facts.yaml` `report_to`, `guidance.yaml` references |

Each step has a stable `id` (for the UI and tests), its `text`, and the `source` URL of any official contact or policy it gives.

### Why it can't be turned against the user

The obvious attack is a scam that says "call 1-888-… to confirm" and hopes the tool repeats it as advice. So:
- **Templates, not generation.** Wording lives in `data/guidance.yaml`, reviewed like any other data file. The guide refuses to start if a required template is missing.
- **Placeholders come from data files only.** Brand names and official sites come from `brands.yaml`. Phone numbers and report addresses come from `facts.yaml`, each with a source and review date. Nothing from the analyzed message is ever inserted.
- **The LLM has no say.** It can't write or choose a step, and an entity it names counts only if it's a curated brand.
- **Plain text in the UI.** The "What to do next" list is rendered with `textContent` and never turned into links.

Tests (`tests/unit/test_next_steps.py`) check the advice for every eval sample, so any URL or phone number in it must be a curated official contact. A property-based test plants random scam domains and numbers and checks they never come back. See [`SECURITY.md`](SECURITY.md#next-step-advice-e1).

### Adding or changing advice

Edit `data/guidance.yaml`. To add a step, add a template and the rule that picks it in `guidance/next_steps.py`, and add it to `REQUIRED_STEPS`. Official contacts are added as sourced facts in `facts.yaml`, never in the template text. A new category gets its brand-specific contact and report steps automatically from its facts.

### Limitations

- Advice follows the evidence, so it's only as good as the signals: a scam that the rules miss gets the mild "verify" step.
- Brands without a published phone number or report address get the generic contact and FTC reporting steps (TurboTax, QuickBooks and Credit Karma have none yet).
- English and US-only: 7726 and ReportFraud.ftc.gov are US channels.

---

## 19. Richer domain explanations (E2)

A technique name like `homoglyph` or `typosquat` says *that* a domain imitates a brand. It doesn't say *how*, and "how" is what lets someone spot the next one themselves. Every non-official domain that scores against a brand now carries an `explanation`, built from data the engine already computes. It changes no score.

```
DomainEngine.score("turb0tax-refund.com")
  techniques that fired for the winning brand ─▶ _explain()   (domain/explain.py)
    homoglyph          ─▶ align label and brand token through their skeletons ─▶ swapped_characters
    typosquat          ─▶ closest part of the label, as written ─▶ misspelled + spelling_edits
    brand or misspelling present ─▶ trust keywords left over   ─▶ extra_words
    brand_in_subdomain ─▶ the registrable domain               ─▶ real_owner
    tld_swap           ─▶ the suffix                           ─▶ wrong_ending
  ─▶ summary[]: plain-language lines built only from the fields above
```

| Field | Example | How it's found |
|---|---|---|
| `swapped_characters` | `turb0tax` → `0` instead of `o`; `bankofarnerica` → `rn` instead of `m`; `turbоtax` → Cyrillic `о` instead of `o` (with its Unicode name) | `Normalizer.segments()` splits the label and the brand token into (characters, skeleton) pairs, including multi-character classes like `rn` → `m`. The two are aligned where their skeletons meet, and each aligned chunk that reads differently is a swap. If the segments don't reproduce the engine's skeleton exactly, no swaps are reported rather than wrong ones |
| `misspelled`, `spelling_edits` | `turbotxa`: `a` and `x` swapped; `quickbook`: a missing `s`; `turbotaxx`: an extra `x`; `turbotzx`: `z` instead of `a` | The hyphen-separated part (or window) of the label closest to the brand token, compared as written rather than skeletonized. A Damerau-Levenshtein backtrace gives `swapped`, `replaced`, `extra` and `missing` edits |
| `extra_words` | `turbotax-refund-secure` → refund, secure | Stuffing keywords left after removing the brand (or its misspelling), with hyphens kept as word breaks |
| `real_owner` | `turbotax.com.evil.net` → evil.net | The registrable domain from the Public Suffix List split |
| `wrong_ending` | `turbotax.net` → .net (real: turbotax.com) | The suffix of a tld_swap |

`summary` always ends with the brand's official sites. A domain that only uses the brand name ("myturbotaxfiling.com") gets "Uses the TurboTax name, but … is not a TurboTax domain."

**Where it appears.** On every `DomainResult` (so `GET /v1/domain/score` returns it), and on analysis results as `domain_explanations[]`: one per lookalike registrable domain, highest score first, at most five. The UI shows them in the "Link and claim checks" card, whose heading states the strongest checked fact ("This link isn't IRS"). Official and unrelated domains get no explanation, but the card still lists them with what was checked ("doesn't imitate a protected brand, so there's no official site list to compare it with"), so no link is silently left out.

**Safety.** The domain is attacker-chosen. Explanations quote it as plain text: the UI renders them with `textContent` and never as a link, and they go through the same SSN/card redaction as reasons (a hostname can carry digits). Only data the engine computed is used; nothing is fetched or resolved.

**Tests:** `tests/unit/test_domain_explain.py` covers each field, punycode input, the summary wording (including the README example), official and clean domains getting none, results and redaction, and fuzzes the character alignment.

**Limitations.**
- The explanation describes the winning brand only. A domain that imitates two brands is explained for the higher-scoring one.
- A label that is both misspelled *and* uses lookalike characters may get only one of the two explanations: the misspelling is found on the label as written, the swaps on the skeleton.
- The engine's own reason text still finds keywords with hyphens removed, so `turbotax-refund-secure` is reported there as "refunds, secure" ("refund" plus the "s" of "secure"). The explanation keeps hyphens and gets it right. Fixing the reason text is left alone because it could change scores.

---

## 20. Fact-check summary (E3)

The verification layer (§6) compares each claim in a message with what's known about the organization it claims to be. Before E3, only failures and mitigations reached the response, as scored reasons. Now every check is also listed as a row of `fact_checks[]`: the claim, what it was compared with, and the outcome. It changes no score.

```json
{ "check": "payment_method_policy", "claim": "IRS asking for payment by gift card",
  "outcome": "conflicts", "basis": "published_fact",
  "fact": "The IRS does not demand immediate payment by gift card, prepaid debit card, cryptocurrency, or wire transfer.",
  "fact_id": "irs_no_unusual_payment_methods",
  "source": "https://www.irs.gov/newsroom/tax-scams-consumer-alerts", "last_reviewed": "2026-10-14",
  "detail": "IRS does not demand payment by gift card" }
```

### Outcomes and what a claim is compared with

`outcome` maps `CheckResult.verified`: `True` → **matches**, `False` → **conflicts**, `None` → **can't verify**. Rows are sorted conflicts first, then can't verify, then matches, at most 30.

| `basis` | Compared with | Example |
|---|---|---|
| `published_fact` | A fact in `facts.yaml`, with its statement, id, source and last-reviewed date | IRS payment policy, Wells Fargo's "never asks for codes by text", a published phone number |
| `brand_list` | The official domains in `brands.yaml` (source, no review date), used when a brand has no domains fact | TurboTax links (Intuit facts aren't curated yet) |
| `email_headers` | The email's own headers: the sender's domain and DKIM | Reply-To pointing to another domain |
| `model_knowledge` | The LLM's answer for an uncurated organization (§17), labeled as unverified | "Acme Bank" links |
| `no_fact` | Nothing: no published fact covers this claim | A gift-card demand "from USPS"; a phone number for a brand with no published numbers |

### Gaps are shown, not hidden

Three new checks record claims that *couldn't* be checked, all with `verified: None`:
- `payment_method_unverified`: an unusual payment method was demanded, but the brand has no payment-policy fact.
- `request_unverified`: sensitive data was requested, but no fact of the brand covers that request (or its channel).
- `phone_number_unverified`: a phone number was given, but the brand has no published numbers.

They have no entry in `verify_points`, so they earn 0 points and never become reasons. A test runs every text eval sample and checks that removing them leaves the message score and reasons identical. They make the "facts are uneven across brands" limitation (§16) visible on each result, instead of only in this document.

### Safety

Claims quote the message (URLs, phone numbers, sender addresses), so rows go through the same SSN/card redaction as reasons, and the UI renders them as plain text. Sources come from the data files, but they're also shown as text rather than links. Model-knowledge rows say so in both `basis` and `fact`, and never carry a source.

**Shown in the UI** as the "Fact check" table: claim, what it was checked against (with source and review date), and a matches / conflicts / can't-verify badge, with a count of conflicting claims.

**Tests:** `tests/unit/test_fact_checks.py` covers outcomes, citations and review dates, ordering, each basis, the three gap checks, the zero-points guarantee over the eval set, and redaction.

**Limitations.**
- A check only runs when its trigger fires. "IRS contacting you by text" appears only when the message also asks for something, because the fact is about unsolicited requests.
- The same claim can appear twice with different outcomes. For example, "IRS asking for SSN" is *can't verify* against request policies (the IRS has none in `facts.yaml`) while "IRS contacting you by text and asking you to act" *conflicts*. Each row answers a different question.
- A phone number that isn't published is *can't verify*, not *conflicts*: only a short list of numbers is known.

---

## 21. Named scenarios (E4)

Reasons say *what* was found ("asks for a Social Security number", "threatens arrest"). A scenario says which **story** the message tells: *Refund lure*, *Back taxes, audit or arrest threat*, *Fake bank fraud alert*. It explains it in plain language, with a source, and adds one next step written for that story. It changes no score.

```json
"scenario": {
  "id": "back_taxes_threat", "name": "Back taxes, audit or arrest threat", "category": "tax",
  "description": "Claims you owe taxes or are under audit and pushes you to pay right away, ... The IRS mails a bill first, lets you question what you owe, and doesn't threaten arrest or demand a specific payment method.",
  "source": "https://www.irs.gov/newsroom/how-to-know-its-really-the-irs-calling-or-knocking-on-your-door",
  "matched_on": ["phrase: \"you owe\"", "threat: arrest"]
}
```

```
pipeline: aggregate() ─▶ verdict
  verdict != likely_legitimate and there's a message?
    ─▶ NextStepsGuide.scenario()   (guidance/scenarios.py)
         brand + category (as for next steps), merged features, links, message text
         ─▶ data/scenarios.yaml, top to bottom: first rule whose conditions hold
    ─▶ result.scenario (0 points) + the scenario's step in next_steps
```

### The catalog

21 scenarios in `data/scenarios.yaml`, tried in file order; the first match is reported. More specific stories come first, so a job offer that sends a check is *Fake check job* rather than *Pay-to-work*, and a sign-in alert that asks for a code is *Verification-code request*.

| Category | Scenarios |
|---|---|
| Tax | Tax debt relief offer · Back taxes, audit or arrest threat · Stimulus or relief payment · Refund lure |
| Delivery | Redelivery fee or card request · Incomplete-address notice · Package on hold |
| Bank | "Move your money to protect it" · Fake bank fraud alert |
| Account takeover | Verification-code request · Fake sign-in alert · Password expiry or account deletion |
| Tech support | Remote-access request · Fake charge or renewal ("call to cancel") · Fake virus or locked-computer warning |
| Job | Fake check job · Pay-to-work job offer · Job offer that asks for your ID or bank details |
| Shared | Payment problem or overdue invoice · Account locked or suspended · Identity verification request |

Every description and step paraphrases a cited FTC, IRS or USPIS page (reviewed 2026-10-15). For example, *Verification-code request* says "Anyone who asks for your verification code is a scammer" (FTC), and *Stimulus or relief payment* notes that the IRS has issued all Economic Impact Payments (IRS).

### Rules

Each scenario has a list of alternative conditions (`when`), and matches if any of them holds. Inside a condition every field must hold, and a list field holds when any of its values is present:

| Field | Reads |
|---|---|
| `category` | the category of the brand the message claims, or the brand of its official or lookalike link (the same brand the next steps name) |
| `threats`, `requests`, `payments`, `call_to_action` | the merged features (§5) |
| `phrases` | the message text (email: sender, subject and body; screenshot: the transcription). Whole phrases, case-insensitive, skipped after a negation in the same clause, like the rule extractor |
| `phone`, `link` | whether the message has a phone number / a link that isn't official |

Load-time validation: condition fields and their values must be known types (an unknown threat or request type fails), every condition needs at least one field, ids are unique `snake_case` and never `none`, sources are `https://`, and categories must exist in `brands.yaml` (the guide refuses to start otherwise).

### Its own next step

Each scenario has one `step: {text, source, replaces}`, inserted after the "don't" steps and before the contact step (§18). `replaces` lists generic steps it already covers, so the advice doesn't repeat itself. For example, *Fake virus warning* ("Don't call the number, install anything or pay…") replaces `dont_call` and `dont_pay`. Only `dont_open_link`, `dont_share`, `dont_pay` and `dont_call` can be replaced: contact, policy-citing and reporting steps always stay. Step texts can't contain links or phone numbers other than curated official sites (`irs.gov`, `usps.com`); a test checks every step, and the E1 safety tests check the advice of every eval sample.

### Why it doesn't change scores, and can't be steered

- **No points, no floors.** The scenario is chosen after `aggregate()` and never feeds back into it. A test runs every text eval sample with and without the scenario catalog and compares score, verdict and reasons.
- **Only on flagged results.** A `likely_legitimate` result never gets a scenario, so a real fraud alert isn't labeled a scam story. On a *suspicious* result the UI says the message *resembles* a known scam pattern; on a *likely scam*, that it *follows* one.
- **Rules and wording are data.** The LLM can't name a scenario or write its text. An LLM-extracted feature can satisfy a condition, but the same grounded, merged features already drive the score.
- **`matched_on` quotes only our vocabulary**: threat and request types, the brand's category, and the phrase from our list that matched, never free text from the message. A test checks every reported item.

### Evaluation

Every text and email scam sample was hand-labeled with its expected scenario, or `none`, in `data/eval/scenario_labels.yaml`. The labels were written **before** the rules, by reading each message, and kept out of `samples.jsonl` so splits don't move. Tests require every scam message to have a label and every scenario to have at least one labeled sample. The eval harness adds a scenario section to its report:
- *right scenario*;
- *wrong* (another scenario, or one where `none` was expected);
- *missed* (flagged, but no rule matched);
- *undetected* (scored likely legitimate, so no scenario could be shown);
- accuracy overall and when detected;
- how many legitimate samples got a scenario.

Results (rules only, 2026-10-15): test split 16/21 (76%), **16/17 when detected (94%)**; dev 23/26, 23/23 when detected; all samples 106/121, 106/109 when detected. Every test-split miss is a detection miss. 3 of 154 legitimate samples got a scenario, all already *suspicious* triage false positives. Details and the misses: [README](README.md#named-scenarios-e4).

**Tests:** `tests/unit/test_scenarios.py` covers:
- one fresh example per scenario (not an eval sample);
- priority between overlapping scenarios;
- negation;
- no scenario on legitimate results or URL-only input;
- `matched_on` vocabulary;
- step placement and replacement, and the report step always last;
- step texts free of links and numbers;
- scores unchanged across the eval set;
- label and catalog integrity;
- validation errors;
- the eval metrics.

### Adding a scenario

1. Add it to `data/scenarios.yaml` at the right priority: name, category, a description and step paraphrased from a cited source, and conditions over existing signals. Prefer threats and requests to phrases.
2. Label the eval samples it should match in `scenario_labels.yaml`. Every scenario needs at least one.
3. Check dev, then run the test split once, and report the numbers.

### Limitations

- **One scenario per message.** A message that tells two stories (a refund lure that also asks for a verification code) gets the first one in priority order.
- **Phrases are English and from the same author as the samples**, so recognition on real-world messages is likely lower than measured. 5 of the 21 scenarios have only 1–2 labeled samples. *Tax debt relief offer* has one, and that sample is scored likely legitimate, so the scenario is untested on a real detection.
- **Wording overlaps.** "Suspended" and "login attempts" are shared by several stories; the measured wrong picks come from exactly those words.
- **No scenario without a detection.** That keeps legitimate messages from being labeled, but scams scored likely legitimate get no explanation of their story either.

---

## 22. "Learn more" reading list

Each result carries `resources[]`: links where the reader can learn about the type of scam they're facing, and the impersonated organization's own guidance. It changes no score.

```json
"resources": [
  { "kind": "scam_type", "title": "How To Recognize and Avoid Phishing Scams",
    "publisher": "Federal Trade Commission", "url": "https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams",
    "last_reviewed": "2026-10-15" },
  { "kind": "official_help", "title": "If your Apple Account is locked, not active, or disabled",
    "publisher": "Apple", "url": "https://support.apple.com/en-us/102640", "last_reviewed": "2026-10-15" },
  { "kind": "official_help", "title": "Recognize and avoid social engineering schemes including phishing messages, phony support calls, and other scams",
    "publisher": "Apple", "url": "https://support.apple.com/en-us/102568", "last_reviewed": "2026-10-15" }
]
```
(for *"Apple: Your Apple ID has been locked. Verify your identity at appleid-unlock-support.com within 24 hours."*, scenario *Account locked or suspended*)

| Kind | Chosen by | Shown |
|---|---|---|
| `scam_type` (up to 2) | the named scenario (§21), else the category of the claimed or linked brand, else the FTC phishing guide | suspicious and likely-scam results |
| `official_help` (up to 2) | the brand the next steps name (§18); pages marked for the current scenario first (Apple's locked-account page for *Account locked*, the IRS refund tracker for *Refund lure*), then the brand's general pages | every result with a known brand, including likely legitimate, where they help verify the message |

**Data:** `data/resources.yaml` lists 11 articles (FTC, IRS, USPIS) and help pages for 11 of the 12 brands. Credit Karma has none, because no current official scam-help page was found. Every page was opened and checked on its `reviewed` date.

**Safety.** These are the only clickable links ScamSentinel shows, so they're locked down:
- They come only from the data file, never from the analyzed message.
- Load-time checks require `https://`, scam-type articles on `trusted_domains` (`ftc.gov`, `irs.gov`, `uspis.gov`), and an organization's help pages on that brand's official domains from `brands.yaml`. They also reject unknown brands, categories, scenarios and article ids.
- The UI builds each link with `createElement`, links only `https://` URLs, and opens them with `rel="noopener noreferrer"`.
- A test runs every eval sample and checks that each link is a curated URL and never one that appears in the input.

**Tests:** `tests/unit/test_resources.py`.

**Limitations:** links can go stale or be renamed (the IRS consumer-alerts page is now titled "Recognize tax scams and fraud"), so they need re-checking like facts. The pages are US English.

---

## 23. Lightweight page fetch (P2)

Until P2, a link was judged only by its name, so a `bit.ly` link or a neutral domain like `parcel-redeliver-now.com` scored 0. P2 can look at the page behind the link: one plain GET, like `curl`, not a browser. It's **off by default**. P2a built the fetch and its defenses; P2b scores what the page shows (see [P2b](#p2b-scoring-with-page-evidence) below). The headline metrics are rules-only with no pages, so they're unchanged.

### Modes (`SCAMSENTINEL_PAGE_FETCH`)

| Mode | What happens |
|---|---|
| `off` (default) | Links are analyzed as strings only, exactly as before. No `pages` in the result |
| `dry_run` | The links that would be fetched go through the URL checks and are reported as "would fetch" (or "blocked"). **Nothing is resolved or connected to** |
| `live` | Those links are fetched through every layer below |

Which links are inspected: the submitted URL, or the first `page_fetch_max_links` (3) non-official links of a message. That covers email link targets, but never sender domains. There's one fetch per host. Bare domains are fetched as `https://`.

### How a page is visited (live)

```
URL ─▶ validate_url(): http/https, port 80/443, no userinfo, IDNA host
       IP literal (incl. 2852039166, 0xA9FEA9FE, 127.1)? check it
       else resolve ONCE ─▶ reject if ANY address isn't public ─▶ pin one IP
    ─▶ only_connect_to(pinned ip, port)      egress lock (audit hook)
         GET https://<pinned ip>/path   Host: real.host   TLS SNI: real.host (cert verified)
    ─▶ 3xx? Location ─▶ back to validate_url (max 5 hops)
    ─▶ text/html only ─▶ read ≤ 2 MB counted after decompression ─▶ PageAnalyzer
```

### Layers of protection, each a fallback for the one before

1. **Mode switch:** nothing touches the network unless `live` is set. `dry_run` exercises everything else without network access.
2. **URL guard** (`security/url_guard.py`): resolve, check every address, pin the IP, re-check every redirect hop.
3. **Egress lock** (`security/egress.py`): during the request, a Python audit hook allows socket lookups and connections only to the pinned IP and port. A second DNS lookup, a proxy, a Unix socket or any other address raises `EgressBlocked` before the system call. Outside a fetch nothing is restricted, so LLM calls and the CT watcher are unaffected.
4. **Circuit breaker:** if the egress lock ever fires, a lower layer failed. Live fetching turns itself off for the rest of the process (`disabled:safety`) and the event is logged as an error.
5. **Fail closed:** every failure is a "not fetched" report with a stable code, and the analysis continues on strings. Nothing is retried with weaker settings: no `http` after `https`, no unverified TLS, no second lookup. An unexpected exception becomes `internal_error`, never a broken analysis.

**Limits:**
- GET only;
- no cookies (cleared between hops), no environment proxies (`trust_env=False`), no user-controlled headers or methods;
- one deadline per fetch (8 s);
- `text/html` only;
- `Accept-Encoding: gzip, deflate`, decompressed by a bounded `zlib` object, so a 20 KB gzip bomb stops at the 2 MB cap;
- a global rate limit (20 per minute);
- a descriptive User-Agent.

### What the page analyzer reads

The HTML is attacker-written, so it goes through the standard library's pure-Python `html.parser`: no C parser, no DOM, nothing executed. Scripts, styles and templates are skipped. Findings (`pages[].findings`):

| Signal | Example detail |
|---|---|
| `sensitive_fields` | "The page asks you to type in: password, verification code". Hidden fields don't count |
| `form_posts_elsewhere` | "A form sends what you type to collector.example.net, not to appleid-unlock-support.com" (or emails it via `mailto:`) |
| `brand_on_unofficial_page` | "The page presents itself as Apple, but it's on appleid-unlock-support.com, not an official Apple domain (apple.com, icloud.com)". Uses the curated mention phrases ("Apple ID", not "apple") from the title, or repeated in the text |
| `redirected` | "The link redirected 2 times and ended at appleid-unlock-support.com, which looks like an Apple domain but isn't one" |
| `meta_refresh` | "The page sends you on to next-hop.example automatically" |

Titles are capped at 150 characters, visible text at 50,000. Titles, URLs and findings go through the SSN/card redaction, and the UI ("What the linked page shows") renders them as plain text, never links.

### P2b: scoring with page evidence

Page findings feed a **page module** (`page/score.py`, `page_points` in `config/scoring.yaml`). Points come mostly from combinations, because every real login page has a password field:

| Finding | Points |
|---|---|
| `brand_on_unofficial_page` | 40 |
| Sensitive fields: password 10, card 10, code 15, SSN 20 | capped at 30 |
| `form_posts_elsewhere` | 15 |
| `meta_refresh` | 5 |

The highest-scoring page counts. A page that presents itself as a brand on a domain the brand doesn't own **and** asks for a password, card, code or SSN triggers the `page_credential_harvest` floor (85). A brand found on the page also lets the next steps, scenario and help links name it, which matters for brandless messages. A redirect's final destination is scored by the domain engine like any other link.

**Measured without the network.** `data/eval/pages/` holds hand-written page snapshots keyed by URL (85 files; 17 of the 21 test-split URL samples have one). `SnapshotFetcher` answers fetches from them, and `python -m scamsentinel.eval --pages snapshot|off` gives the with/without ablation.

**Page evidence only raises the score.** The aggregator computes the weighted score with and without the page module and keeps the higher one. The `weighted_score` reason says when a page was set aside ("page 40 not weighted: it would lower the score"). Without this, a page whose only finding is `brand_on_unofficial_page` (40) pulled a stronger domain score down. The first measurement (2026-10-21, test split, rules only) showed it: `u-s-010` 70 → 57 and `d-u-s-006` 60 → 51, and strict recall fell from 75.0% to 68.8%.

**Measurement after the fix (2026-10-21, rules only, `--pages snapshot` vs `--pages off`):** checked on dev first, then test run once.

| Split | Strict recall (snapshot / off) | Triage recall | FPR |
|---|---|---|---|
| Test (61) | 75.0% / 75.0% | 87.5% / 87.5% | 0% / 0% |
| Dev (68) | 81.1% / 81.1% | 89.2% / 86.5% | 0% / 0% |

Pages with a brand plus sensitive fields reach the 85 `page_credential_harvest` floor (6 test scams, none previously missed). Two legitimate test URLs gain 10–15 points and stay likely legitimate. No brandless miss is recovered yet: every page finding in the test split is on a URL that already names a brand. That would need snapshots for brandless scam links in message samples.

### Limitations

- **Not a browser:** pages built with JavaScript, pages that show bots something harmless (cloaking), and pages already taken down look empty or clean. P3 covers those.
- **Live mode reveals the visit:** the scam site sees this machine's IP address and the ScamSentinel User-Agent. That's why `live` is opt-in.
- **The system resolver's own timeout applies to DNS.** The fetch deadline starts after resolution.
- **The egress lock is per process:** it covers this Python process, not a separate browser process (P3 needs a network-level egress proxy).
