# Evaluation data sources

| File | Source | License / terms | Count |
|---|---|---|---|
| `samples.jsonl` | Hand-written for this project (`source: synthetic-handwritten`) | Same as the repository | 191 |

## What's in `samples.jsonl`

Each sample has a `category` (default `tax`). Metrics are reported per category, and splits are stratified by category so adding one never moves another category's samples between splits.

| Category | Input type | Scam | Legitimate |
|---|---|---|---|
| Tax (`tax`) | Text (SMS / chat) | 40 | 35 |
| | Email (raw `.eml`) | 12 | 10 |
| | URL | 30 | 25 |
| Delivery (`delivery`) | Text | 10 | 8 |
| | Email | 5 | 5 |
| | URL | 6 | 5 |

### Tax

- **Scams** cover all four brands plus brandless tax scams: refund holds, account suspensions, stimulus claims, audits and arrest threats, fake invoices, credential and card harvesting, unusual payment methods (gift cards, crypto, wire, Zelle, Cash App), prompt-injection attempts, homoglyph / typo / keyword-stuffed / subdomain-abuse domains, a link shortener, and HTML emails whose link text differs from the real target.
- **Some scams were deliberately written outside the rules' vocabulary** (e.g. "officers may visit your home", "tax office", unbranded domains) so recall isn't flattered.
- **Legitimate samples include hard negatives** that resemble scams: one-time passcode texts, gift-card balances, payment-app receipts, urgent but genuine IRS reminders, lockout notices, IRS newsletters sent through GovDelivery, QuickBooks invoices whose Reply-To is the merchant, and one brand linking to another brand's official site.

### Delivery

- **Scams** impersonate USPS (plus two brandless ones): "package on hold", incomplete address, "returned to sender", redelivery and customs fees, card and date-of-birth harvesting, an Informed Delivery account-lock lure, a gift-card demand, a callback number, a spoofed `usps.com` sender with a foreign Reply-To, and lookalike domains (keyword stuffing, a Cyrillic `р` homoglyph, `usps.com-…` subdomain tricks, a typo).
- **Off-vocabulary scams** are included on purpose (`uspz-parcel`, "sent back" instead of a known hold phrase).
- **Legitimate samples include hard negatives**: opted-in USPS tracking texts, Informed Delivery digests, a real missed-delivery notice that links to usps.com, UPS (one letter from "usps"), Amazon and FedEx notices, a mailroom message, and a merchant email that mentions USPS.

### Both categories

- **Variants of the same template share a `group`** and always land in the same split.

## Rules
- Scam URLs are stored **defanged** (`hxxps://example[.]com`); a test enforces it. Domains in scam samples are invented.
- Synthetic samples are marked `synthetic: true`. Metrics are reported per data source.
- Raw downloads go in `data/eval/raw/`, which git ignores.
- User submissions are never added without consent.

## Limitations and next steps
- All samples were written by the same author as the detection rules, which likely inflates the numbers. Adding a real corpus is the most valuable next step: OpenPhish community feed / PhishTank archives for URLs (filtered to tax and financial brands), and a public phishing-email corpus for message bodies, each listed here with its license, with `synthetic: false`.
- Screenshots aren't in the evaluation set (they need the vision model).
