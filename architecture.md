# Architecture

This document describes the **MVP**. Features planned for after the MVP are summarized in [§14 Post-MVP roadmap](#14-post-mvp-roadmap).

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
  domain/         # registrable-domain parsing, homoglyphs, distance, keywords, scorer
  message/        # feature schema, rule extractor, LLM extractor, merger
  verify/         # trusted-facts checks
  ocr/            # vision.py: Groq vision transcriber + cache
  web/            # browser UI (index.html, app.js, app.css), served at / and /static
  aggregate/      # weights, floors, verdict bands, reason assembly
  security/       # upload_guard.py, image_sanitize.py, redaction.py (url_guard.py is post-MVP)
  ct/             # P1: crt.sh client, CT watcher (python -m scamsentinel.ct), candidate store
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

Output: `[{check, claim, verified: true|false|null, source, detail}]`. Checks that come back `false` become reasons. A check that passes, such as "link goes to irs.gov," is shown as a mitigating reason and lowers the score.

---

## 7. Input handling

| Input | Handling |
|---|---|
| Text (`text`) | Up to 20,000 characters. URLs and domains extracted, including defanged forms |
| URL (`url`) | Scored by the domain engine only (running the message analyzer on the URL string would count the same evidence twice). **Never fetched** |
| Email (`email_raw`) | Parsed with Python's `email` package. HTML bodies converted to text with an HTML parser, never rendered; link `href` targets are collected separately. Attachments listed by name/type/size, never opened. The domain module scores body links, link targets, and the From / Reply-To domains |
| Screenshot (`POST /v1/analyze/image`, raw body) | Upload guard → sanitize → vision transcription (§8) → treated as text, with `input_type: "image"` |

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
| Impersonates IRS **and** demands gift card / crypto / wire | 85 |
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

152 hand-written samples (MVP): 40/35 scam/legitimate texts, 12/10 emails, 30/25 URLs, across all four brands plus brandless scams, with deliberate hard negatives and off-vocabulary scams. Composition, rules and limitations are in [`data/eval/SOURCES.md`](data/eval/SOURCES.md). Real-world corpora (OpenPhish / PhishTank URLs, public phishing-email corpora) are the planned next addition, marked `synthetic: false` and reported separately. Screenshots aren't in the set yet.

Every record: `{id, group?, input_type, label, brand, content (scam URLs defanged), source, synthetic, notes?}`. Validated by `eval/dataset.py` (unique ids, known fields), and tests enforce that scam links are defanged.

### Splits (`eval/dataset.py`)
60/20/20 train/dev/test, **stratified** by `input_type × label` and **grouped**: variants of one template share a `group`, and whole groups are ordered by a seeded SHA-256 hash and cut by position, so a template never straddles two splits and the assignment is deterministic.

**Protocol:** rules, weights and floors are tuned on **dev** only. **Test** is run once per release for the reported numbers, and its errors are reported, not fixed. (M6 example: the dev run exposed a dilution bug and two missing floors, which were fixed. The test run was then made once, and its misses, brandless scams, are documented as limitations.)

### Metrics (`eval/metrics.py`, `eval/report.py`)
- Precision, recall, F1, FPR and confusion counts with scam as the positive class: **strict** counts `likely_scam` only; **triage** also counts `suspicious`.
- Broken down by input type, brand, and synthetic vs. real; a verdicts-by-label table; and every misclassified sample with its score and signals.
- **Ablations** (`--ablation`): `rules_only` (default, no API calls), `full` (rules + LLM when `GROQ_API_KEY` is set; results cached in `var/eval.db`), `no_verify` (verification contributes 0 points).
- **Robustness** is tested separately: the 30-variant prompt-injection paired corpus (`tests/security/test_prompt_injection.py`).

### Running
`python -m scamsentinel.eval --split test --report reports/eval-test.md --json reports/eval-test.json` writes a markdown report and JSON metrics plus predictions (`reports/` is gitignored). The README table is copied from the latest test-split report.

---

## 11. Data model (SQLite)

```
analyses(id PK, created_at, expires_at, input_type, input_hash, verdict, risk_score, result_json)
llm_cache(key PK, provider, model, features_json, created_at)   -- key = sha256(provider, model, prompt version, normalized text)
ct_candidates(domain PK, registrable, score, brand, techniques, cert_id, issuer, not_before, first_seen, last_seen)   -- P1
ct_polls(id PK, started_at, finished_at, queries, failed_queries, names_seen, candidates, new_candidates)             -- P1
```

`scamsentinel/store.py` opens a fresh connection per call (safe under FastAPI's thread pool). The raw input is never stored, only its SHA-256 hash and the result. Expired analyses are hidden immediately and deleted on startup. Cached LLM features quote the analyzed text, so they expire on the same 7-day schedule. Uploaded images are processed in memory and never written to disk.

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

Built only after the MVP works end to end and has evaluation numbers. Order: P1 → E1–E4 → P2 → P3 → P4.

### Next: explain and guide (E1–E4)

ScamSentinel's niche is being a focused, explainable checker for **tax-related** scams that runs locally and shows its evidence, not another generic scam detector. The next phase builds on that before any page fetching. All four items follow design principle 1: the output comes from deterministic templates and data files keyed on signals the rules already produce. The LLM doesn't write advice or explanations.

| Phase | What | Notes |
|---|---|---|
| **E1** | **"What should I do next?"** | Each result gets a short, cautious `next_steps[]` list, chosen from fixed templates by the evidence that fired. Examples: a sensitive-data request → "Don't reply with personal information"; an IRS or brand impersonation → "Contact the agency using a number from its official website or your paperwork, not the one in the message"; a gift-card or crypto demand → "The IRS doesn't take payment this way. Don't pay." Official contact details come only from `data/facts.yaml`, with sources. **Links and phone numbers found in the analyzed message are never repeated, opened or recommended.** Advice is worded cautiously and never promises safety; a `likely_legitimate` verdict still says to verify through a channel you already trust. Shown in the UI below the verdict. |
| **E2** | **Richer domain explanations** | Today each domain technique carries a one-line `detail`. Add a structured explanation of *what* differs from the real brand: the swapped characters (`0` for `o`, Cyrillic `і` for `i`), the misspelling (`turbotxa` vs. `turbotax`), the misleading extra words (`-refund-secure`), or the real owner of a brand-in-subdomain URL. Built from data the engine already computes (skeleton, edit operations, keywords, PSL split). |
| **E3** | **Fact-check summary** | The verification layer already evaluates every check as matched / conflicts / can't verify (`CheckResult.verified`), but only failures and mitigations reach the response, as reasons. Expose the full list as `fact_checks[]`: each claim in the message, the trusted fact it was compared with, the outcome, and the fact's source and last-reviewed date. Shown in the UI as a matches / conflicts table. |
| **E4** | **Tax-specific scenarios** | Recognize named scenarios, such as refund delay or "refund on hold", balance due or payment demand, identity verification, account suspension, and fake tax-prep or "IRS agent" offers. Each scenario is a rule over existing signals in a new `data/scenarios.yaml` with a plain-language description and its own E1 next steps. Reported as `scenario` on the result (0 points: it explains the score and doesn't change it). New scenarios are added over time as data, each with eval samples. |

E1–E4 change no scores, so evaluation numbers stay comparable. Each needs tests that the advice and explanations never quote a URL or phone number from the input, and that every result still has at least one reason (AC-6).

### Infrastructure phases

| Phase | What | Notes |
|---|---|---|
| **P1** ✅ | **Certificate Transparency watcher** | Poll crt.sh politely (every 6 h, sequential, backoff) for certificates containing brand tokens. Score each new name with the existing domain engine and store candidates ≥ 50. Expose `GET /v1/ct/candidates`. Cheap, because the domain engine already exists. See [§15](#15-certificate-transparency-watcher-p1). |
| **P2** | **Lightweight page fetch** | `httpx` + an HTML parser (no browser). Look for credential/SSN forms, forms posting to other domains, and brand mentions on unofficial domains. **Requires the SSRF URL guard first** (strict parsing, resolve-then-pin, reject non-global IPs, re-check every redirect hop). Guard stub and payload tests already exist. |
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
