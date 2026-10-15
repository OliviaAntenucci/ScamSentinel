# Architecture

## 1. Design principles

1. **The LLM extracts, the rules decide.** The language model turns messy text into structured features. Deterministic, unit-tested rules turn the features into a score. This keeps verdicts explainable and limits the damage prompt injection can do.
2. **Every point is accounted for.** The risk score is the sum of reason contributions (after weighting), so each verdict can be audited.
3. **Untrusted by default.** User input, web pages, CT data, and LLM output all get validated at the boundary. See [`SECURITY.md`](SECURITY.md).
4. **Graceful degradation.** If the LLM, sandbox, or OCR is unavailable, the analysis still finishes. It notes which modules ran and which didn't.
5. **Isolation for dangerous work.** Browsing and image parsing run in separate, locked-down containers.

---

## 2. System overview

```
                         ┌───────────────────────────────────────────────┐
  text / email / URL /   │                  API (FastAPI)                │
  screenshot  ─────────▶ │  validate · rate-limit · size caps · dedupe   │
                         └───────────────┬───────────────────────────────┘
                                         │ Analysis job
                                         ▼
                         ┌───────────────────────────────────────────────┐
                         │             Ingest / Normalizer               │
                         │  .eml parse · HTML→text · defang-aware URL    │
                         │  extraction · OCR dispatch (image)            │
                         └──────┬───────────────┬───────────────┬────────┘
                                │ domains       │ text          │ urls
                                ▼               ▼               ▼
                    ┌────────────────┐ ┌─────────────────┐ ┌───────────────────┐
                    │ Domain Engine  │ │ Message Analyzer│ │ URL Detonator     │
                    │ PSL · IDN ·    │ │ LLM features +  │ │ (sandbox ctr)     │
                    │ homoglyph ·    │ │ rule features   │ │ Playwright +      │
                    │ edit distance ·│ │                 │ │ URL guard         │
                    │ keyword stuff  │ └────────┬────────┘ └─────────┬─────────┘
                    └───────┬────────┘          │                    │
                            │                   ▼                    │
                            │          ┌─────────────────┐           │
                            │          │ Verification    │◀──────────┘
                            │          │ (trusted facts) │  page brand/domain claims
                            │          └────────┬────────┘
                            ▼                   ▼
                         ┌───────────────────────────────────────────────┐
                         │                Risk Aggregator                │
                         │  weights · renormalize · overrides · bands    │
                         └───────────────────────┬───────────────────────┘
                                                 ▼
                                   verdict · score · reasons[]

   ┌────────────────────┐        ┌──────────────────┐
   │ CT Watcher (cron)  │──────▶ │  Domain Engine   │──▶ ct_candidates table
   │ crt.sh poller      │        └──────────────────┘
   └────────────────────┘
   ┌────────────────────┐
   │ OCR Worker (ctr)   │  ◀── re-encoded image, no network
   └────────────────────┘
```

### Interface

ScamSentinel is **API-only**. There is no web UI. It runs on the user's own computer, and the user calls the HTTP API from the command line (e.g. `curl`) at `http://127.0.0.1:8000`. Results come back as JSON. Sandbox screenshots download as PNG files from `/v1/analysis/{id}/screenshot.png`. FastAPI's auto-generated OpenAPI schema at `/docs` serves as the API reference.

### Deployment (Docker Compose)

| Service | Network | Secrets | Notes |
|---|---|---|---|
| `api` | `internal` + `public` | `ANTHROPIC_API_KEY` | FastAPI, domain engine, analyzer, aggregator, SQLite. Published as `127.0.0.1:8000:8000` (loopback only) |
| `sandbox` | `sandbox_net` → egress proxy only | none | Playwright/Chromium, hardened (see SECURITY.md T4) |
| `egress-proxy` | `sandbox_net` + `public` | none | Denies private/link-local/metadata ranges; second line of SSRF defense |
| `ocr` | `internal`, **no egress** | none | Pillow re-encode + Tesseract |
| `ct-watcher` | `internal` + `public` | none | Scheduled crt.sh polling |

---

## 3. Repository layout

```
scamsentinel/
  config.py       # Settings (env vars, localhost-only bind policy)
  models.py       # Verdict, Reason, ModuleResult, AnalysisResult
  data.py         # validated loaders for data/*.yaml and config/scoring.yaml
  pipeline.py     # orchestrator: ingest -> modules -> verify -> aggregate
  api/            # FastAPI app, routes, request/response schemas, middleware
  ingest/         # eml parsing, html→text, URL extraction (incl. defanged)
  domain/         # registrable-domain parsing, homoglyphs, distance, keywords, scorer
  ct/             # crt.sh client, scheduler, candidate store
  message/        # LLM client, prompt, feature schema, rule extractor, merger
  verify/         # trusted-facts store + claim checks
  sandbox/        # detonator worker, URL guard, page analyzers
  ocr/            # upload validation, re-encode, OCR worker
  aggregate/      # weights, overrides, verdict bands, reason assembly
  security/       # url_guard.py, upload_guard.py, redaction.py (shared)
  eval/           # dataset loader, runner, metrics, ablations, report
config/
  scoring.yaml    # weights, bands, floors, technique/signal points
data/
  brands.yaml     # protected brands, official domains, brand tokens
  keywords.yaml   # stuffing keywords, urgency phrases, payment methods
  facts.yaml      # trusted facts for verification (with sources)
  confusables.txt # Unicode TR39 confusables subset
  eval/           # labeled samples + SOURCES.md
tests/
  unit/ integration/ security/
docker/
  api.Dockerfile sandbox.Dockerfile ocr.Dockerfile egress-proxy/
```

`confusables.txt` is added in M1.

---

## 4. Lookalike-domain engine

**Input:** a hostname or URL. **Output:** `DomainResult {registrable, score, brand, techniques[], normalized, official}`.

### Pipeline

1. **Canonicalize.** Lowercase, strip the trailing dot, and decode punycode (`xn--trbotax-…` → Unicode). Keep both forms.
2. **Split with the Public Suffix List** (`tldextract`): `subdomain`, `domain` (the label), `suffix`.
   - Example: `turbotax.com.refund-help.co.uk` → subdomain `turbotax.com`, label `refund-help`, suffix `co.uk`.
3. **Allowlist check.** If `label.suffix` matches an official registrable domain in `brands.yaml`, the result is `official=true, score=0` and processing stops.
4. **Normalize to a skeleton.**
   - Unicode confusables → ASCII (UTS #39 skeleton): `tսrbotax` (Armenian `ս`) → `turbotax`.
   - ASCII lookalikes: `0→o, 1→l, 3→e, 5→s, 7→t, rn→m, vv→w, cl→d`.
   - Strip separators to get the compact form: `turbo-tax` → `turbotax`.
5. **Tokenize** the label on `-`, digits, and dictionary word boundaries (a greedy split over brand tokens + keywords).
6. **Run the detectors:**

| Technique | How | Example | Points (initial) |
|---|---|---|---|
| `exact_brand_unofficial` | Skeleton/compact equals a brand token, but the domain isn't official | `turbotax.net`, `turbo-tax.com` | 70 |
| `homoglyph` | Raw ≠ skeleton, and the skeleton matches a brand | `turb0tax.com`, `ιrs.gov` | 85 |
| `typosquat` | Normalized Damerau-Levenshtein ≤ 0.2 to a brand token (min length 4) | `turbotxa.com`, `quickbook.com` | 60–80 (scaled by similarity) |
| `brand_plus_keywords` | Contains a brand token + ≥1 stuffing keyword | `turbotax-refund-secure.com` | 50 + 10 per keyword (cap 90) |
| `brand_in_subdomain` | Brand token or official domain appears in the subdomain of an unrelated registrable domain | `irs.gov.refund-claim.net` | 75 |
| `tld_swap` | Brand label on a different/odd TLD | `irs.gov.co`, `creditkarma.support` | 65 |
| `idn_mixed_script` | Label mixes scripts (Latin + Cyrillic) | `сreditkarma.com` | +15 bonus |

The domain score is the maximum over techniques, plus capped bonuses. Every technique that fires becomes a reason. Short tokens like `irs` (three letters) need extra care: `irs` only fires when it appears as a whole token (`irs-refund`, `irsgov`) or next to tax keywords. This stops false positives on words like `first` or `shirts`.

7. **Enrichment (optional):** domain age from RDAP and certificate age from the sandbox TLS info. Domains registered less than 30 days ago get +10.

### Testing
- A generated suite with every technique × every brand (target ≥95% recall, AC-2).
- Negative suite: official domains, popular legitimate domains (`firstbank.com`, `taxact.com`, `hrblock.com`), and words containing `irs`.
- `hypothesis`: normalization is idempotent, and no official domain ever scores above 0.

---

## 5. Certificate Transparency watcher

```
every 6h ─▶ for token in brand_tokens:
              GET https://crt.sh/?q=%25{token}%25&output=json&exclude=expired
            ─▶ parse name_value (SANs, may be multi-line, wildcards)
            ─▶ dedupe by (cert_id, name); skip names already seen
            ─▶ domain_engine.score(name)
            ─▶ if score ≥ 50: upsert ct_candidates
```

- **Politeness:** sequential requests, 2 s spacing, exponential backoff on 429/5xx, 60 s timeout (crt.sh is slow on wildcard queries), and a descriptive User-Agent.
- **Wildcards:** `*.irs-refund.com` → score `irs-refund.com`.
- **Noise control:** legitimate subdomains of official domains are skipped by the allowlist. Very broad tokens (`irs`) are queried with tax keywords (`%irs%refund%`, `%irs%gov%`) to keep result sizes manageable.
- **Optional source:** a Certstream websocket for near-real-time data (later milestone).
- **Output:** `ct_candidates(domain, score, brand, techniques, cert_id, issuer, not_before, first_seen)`.

---

## 6. Message analyzer

Two extractors run in parallel, and a merger combines their results.

### 6.1 LLM feature extractor

- **Model:** Claude via the Anthropic API, using **tool use with a strict input schema** so output is structured JSON. Temperature 0.
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

  There is no verdict or score field.
- **Grounding check:** each `span` must appear in the normalized input (case/whitespace-insensitive). Features that fail the check are dropped and counted in telemetry.
- **Caching:** results are keyed on `sha256(model_id + prompt_version + normalized_text)`.

### 6.2 Rule extractor

Regex and phrase lists from `keywords.yaml`: urgency phrases ("within 24 hours", "final notice", "immediately"), payment rails, PII requests (`social security`, `SSN`, `routing number`, `verification code`), brand mentions, injection phrases, and phone numbers / URLs (including defanged ones).

### 6.3 Merge

Union both extractors' features, tagging each one with `source: llm|rule|both`. Features found by both carry full weight. Rule-only features also carry full weight, since they're deterministic and visible in the text. LLM-only features carry full weight when their span is grounded. Big disagreements (rules see a payment method the LLM missed) are logged as possible injection or extraction failures.

---

## 7. Verification layer (VerifyVault-style)

The verification layer turns claims in the message into checks against `data/facts.yaml`. Each fact records a source URL and a last-reviewed date.

| Check | Input | Fails when |
|---|---|---|
| `official_domain` | Each URL/domain + impersonated brand | Domain is not in the brand's official list |
| `contact_channel` | Input type + entity | IRS + SMS/email/social first contact asking for info or payment |
| `payment_method_policy` | Payment methods + entity | IRS/Intuit + gift card / crypto / wire / P2P app |
| `phone_number` | Claimed phone numbers + entity | Number is not in the entity's published numbers |
| `sender_alignment` (email) | From / Reply-To / Return-Path / DKIM d= | Display name claims a brand but the sending domain isn't official, or Reply-To differs |
| `page_brand_mismatch` | Sandbox: brand terms/logo on page + final domain | Brand shown on a non-official domain |

Output: `[{claim, verified: true|false|unknown, source, detail}]`. Checks that come back `false` become reasons. A check that passes, such as "link goes to irs.gov," is also shown as a mitigating reason and lowers the score.

---

## 8. URL detonator

### Flow

```
api ──job{url, id}──▶ sandbox worker
  1. url_guard.validate(url)                      # scheme, port, resolve, all-IPs-global
  2. browser = chromium.launch(sandbox on, downloads off)
     ctx = new_context(no storage, permissions denied, JS on, UA = generic)
  3. ctx.route("**/*", guard_every_request)       # SSRF check per request + redirect hop
  4. page.goto(url, timeout=20s, wait_until="networkidle"|"load")
  5. capture:
       redirect chain (response.request.redirected_from …)
       final URL, status, TLS issuer / validity (via CDP Security domain)
       screenshot (full-page, max height capped)
       DOM → visible text, hidden text (separately)
       forms: action URLs, method, input names/types/autocomplete
       title, meta, favicon (mmh3 hash), external script domains
  6. teardown context; return SandboxReport (schema-validated)
```

### Page analyzers → signals

| Signal | Rule | Points (initial) |
|---|---|---|
| `credential_form` | `input[type=password]` or name/id/label matches ssn/social/routing/account/card/cvv/otp | 30 |
| `brand_on_unofficial_domain` | Page text/title/logo mentions a protected brand, and the final domain is not official | 30 |
| `cross_domain_form_action` | Form posts to a different registrable domain | 15 |
| `redirect_chain` | > 2 cross-domain hops | 10 |
| `new_certificate` | TLS `notBefore` < 14 days | 10 |
| `hidden_instructions` | Hidden text contains injection phrases | 15 |
| `final_domain_lookalike` | Final domain scored by the domain engine | uses domain score |

The final URL is fed back into the domain engine, so a redirect from a clean-looking short link to `turbotax-verify.top` is still caught.

---

## 9. Screenshot OCR

```
upload ─▶ upload_guard (size, magic bytes, pixel cap)
       ─▶ ocr worker [no network]: decode → re-encode PNG (strip metadata)
                                   → grayscale + upscale if small → tesseract (psm 6/11)
       ─▶ text + mean confidence ─▶ ingest (URL extraction) ─▶ message analyzer
```

When OCR confidence is low (<60), the reasons say so, and that input's message-module weight is reduced.

---

## 10. Risk aggregator

### Module scores
Each module produces `score ∈ [0,100]` and `reasons[]` (each with `points`). Verification has no module score of its own. Its reasons add points to the message module (contact/payment/phone/sender) or the sandbox module (page brand mismatch).

### Weighted combination with renormalization
Default weights: `domain 0.40, message 0.30, sandbox 0.30`. Only modules that **ran** count, and their weights are renormalized:

```
active = {m: w for m, w in weights if m ran}
risk   = Σ (w / Σ active_w) · score_m
```

So a text-only input with no URL isn't dragged toward zero by a missing domain or sandbox score.

### Overrides (floors)
High-confidence combinations set a minimum score, regardless of averaging:

| Condition | Floor |
|---|---|
| Credential/PII form **and** (lookalike domain ≥ 60 **or** brand on unofficial domain) | 90 |
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
  "risk_score": 94,
  "module_scores": { "domain": 95, "message": 82, "sandbox": 90 },
  "modules_run": ["domain", "message", "verify", "sandbox"],
  "degraded": [],
  "reasons": [
    {
      "module": "domain",
      "signal": "brand_plus_keywords",
      "detail": "irs-refund-secure.com contains brand token 'irs' with keywords 'refund', 'secure'",
      "evidence": "irs-refund-secure.com",
      "points": 35
    }
  ],
  "overrides_applied": ["credential_form_on_lookalike"],
  "artifacts": { "screenshot": "/v1/analysis/an_01J…/screenshot.png" }
}
```

Weights, points, and floors live in `config/scoring.yaml`. They're tuned on the **dev** split only.

---

## 11. Evaluation harness

### Dataset (`data/eval/`)

| Slice | Source | Label |
|---|---|---|
| Phishing URLs | OpenPhish community feed, PhishTank archives (filtered to tax/financial brands where possible) | scam |
| Phishing email bodies | Public phishing corpora (e.g. Nazario corpus), filtered + relabeled | scam |
| Synthetic tax scams | Hand-written + LLM-generated, then manually reviewed: SMS, email, refund, suspension, payment demands, all 4 brands, with injection variants | scam |
| Legitimate tax comms | Official IRS public pages/notices text, Intuit public help/marketing emails, real legitimate domains | legitimate |
| Hard negatives | Legit messages that are *urgent* or mention refunds (real deadline reminders, H&R Block/TaxAct domains, banks) | legitimate |
| Lookalike domain suite | Generated per technique × brand + CT-sourced (manually labeled) | scam / legitimate |

Every record: `{id, input_type, content (URLs defanged), label, brand, source, synthetic: bool, split}`. Splits are 60/20/20 with a fixed seed, stratified by `input_type × label × synthetic`. Near-duplicates are clustered **before** splitting so templates can't leak across splits.

### Metrics
- Precision, recall, F1, FPR, and confusion matrix, treating `likely_scam` as positive. `suspicious` is counted both ways and reported as a separate "triage" rate.
- Broken down by input type, brand, and real vs. synthetic.
- **Ablations:** rules-only · LLM+rules · ±sandbox · ±verification.
- **Robustness:** the injection-paired set (verdict-band stability).
- Sandbox metrics use **archived captures** (saved HTML + screenshots) because live phishing pages go offline fast.

### Running
`python -m scamsentinel.eval --split test --report reports/eval-YYYYMMDD.md` writes a markdown report and JSON metrics. The README table is copied from the latest test-split report.

---

## 12. Data model (SQLite, MVP)

```
analyses(id, created_at, input_type, input_hash, verdict, risk_score, result_json, expires_at)
artifacts(analysis_id, kind, path, sha256, created_at)        -- screenshots, dom.txt
ct_candidates(domain PK, score, brand, techniques_json, cert_id, issuer, not_before, first_seen, last_seen)
llm_cache(key PK, model, prompt_version, features_json, created_at)
```

A daily job purges `analyses` and `artifacts` older than `expires_at` (7 days by default).

---

## 13. Observability
- Structured JSON logs with PII redaction (`security/redaction.py`).
- Per-module latency, LLM token usage, cache hit rate, grounding-drop rate, LLM/rule disagreement rate, and SSRF-block counts by reason.
- `/healthz` reports the status of the LLM, sandbox, OCR, and CT watcher.

---

## 14. Key trade-offs

| Decision | Alternative | Why |
|---|---|---|
| LLM → features, rules → verdict | End-to-end LLM classification | Explainability and injection resistance; testable scoring |
| Max-over-techniques domain score | Learned domain classifier | Transparent and needs no training data; a classifier can be an ablation later |
| Renormalized weights + floors | Plain weighted average | Missing modules don't dilute scores; strong combos aren't averaged away |
| Separate sandbox + egress proxy | App-level SSRF check only | Defense in depth against parser/rebinding bugs |
| SQLite | Postgres | Single-node MVP; schema is portable |
| Images only for uploads | PDF/Office support | Much smaller parser attack surface for MVP |
