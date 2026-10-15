# Evaluation data sources

| File | Source | License / terms | Count |
|---|---|---|---|
| `samples.jsonl` | Hand-written for this project (`source: synthetic-handwritten`) | Same as the repository | 332 |

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
| Bank (`bank`) | Text | 10 | 8 |
| | Email | 5 | 5 |
| | URL | 6 | 5 |
| Account takeover (`account_takeover`) | Text | 8 | 6 |
| | Email | 5 | 5 |
| | URL | 5 | 5 |
| Tech support (`tech_support`) | Text | 8 | 6 |
| | Email | 5 | 5 |
| | URL | 5 | 5 |
| Job (`job`) | Text | 8 | 6 |
| | Email | 5 | 5 |
| | URL | 5 | 5 |

### Tax

- **Scams** cover all four brands plus brandless tax scams: refund holds, account suspensions, stimulus claims, audits and arrest threats, fake invoices, credential and card harvesting, unusual payment methods (gift cards, crypto, wire, Zelle, Cash App), prompt-injection attempts, homoglyph / typo / keyword-stuffed / subdomain-abuse domains, a link shortener, and HTML emails whose link text differs from the real target.
- **Some scams were deliberately written outside the rules' vocabulary** (e.g. "officers may visit your home", "tax office", unbranded domains) so recall isn't flattered.
- **Legitimate samples include hard negatives** that resemble scams: one-time passcode texts, gift-card balances, payment-app receipts, urgent but genuine IRS reminders, lockout notices, IRS newsletters sent through GovDelivery, QuickBooks invoices whose Reply-To is the merchant, and one brand linking to another brand's official site.

### Delivery

- **Scams** impersonate USPS (plus two brandless ones): "package on hold", incomplete address, "returned to sender", redelivery and customs fees, card and date-of-birth harvesting, an Informed Delivery account-lock lure, a gift-card demand, a callback number, a spoofed `usps.com` sender with a foreign Reply-To, and lookalike domains (keyword stuffing, a Cyrillic `р` homoglyph, `usps.com-…` subdomain tricks, a typo).
- **Off-vocabulary scams** are included on purpose (`uspz-parcel`, "sent back" instead of a known hold phrase).
- **Legitimate samples include hard negatives**: opted-in USPS tracking texts, Informed Delivery digests, a real missed-delivery notice that links to usps.com, UPS (one letter from "usps"), Amazon and FedEx notices, a mailroom message, and a merchant email that mentions USPS.

### Bank

- **Scams** impersonate Chase, Bank of America and Wells Fargo (plus two brandless ones): fake fraud alerts and blocked sign-ins with lookalike links, one-time-code and password requests, "send your balance to yourself with Zelle" and "move it to a protected account by wire", card-and-PIN harvesting, a callback number, a spoofed `wellsfargo.com` sender with a foreign Reply-To, and lookalike domains (keyword stuffing, `rn` for `m`, a zero for `o`, `bankofamerica.com-…` subdomain tricks, a TLD swap).
- **An off-vocabulary scam** is included on purpose ("Did you try to send $500? Text back NO", with no link or request yet).
- **Legitimate samples include hard negatives**: YES/NO fraud alerts naming a card by its last four digits, incoming-Zelle notices, one-time-code texts, statement emails, a real-style alert that says "unusual activity", a merchant receipt that mentions a Chase card, "chase" as a verb, and `purchase.edu` / `phaseone.com`.

### Account takeover

- **Scams** impersonate Google and Apple (plus brandless ones): locked Apple IDs, "your account will be permanently deleted", "your password expires today, keep your current password", one-time-code requests after a fake sign-in alert, a "Gmail Team" sender on another provider's domain, and lookalike domains (`appleid-…`, `icloud-…`, `g00gle-…`, a one for `l` in `app1e`, `accounts.google.com-…` subdomain tricks).
- **Off-vocabulary scams**: a fake $999 purchase with a callback number, and a "friend" asking for the code you just got.
- **Legitimate samples include hard negatives**: codes delivered with the code first ("G-482913 is your Google verification code"), "your password was changed", "someone knows your password", "your iCloud storage is full", a work password-expiry notice, a library account closing, apple the fruit, and `applebees.com`.

### Tech support

- **Scams** impersonate Microsoft (plus brandless ones): "virus detected, call Microsoft Support", "your computer has been locked, pay in Bitcoin", Google Play cards "to activate your firewall", remote-access installs, Microsoft account phishing (Microsoft's category is tech support), and lookalike domains (`rnicrosoft`, `micros0ft`, `microsoft.com-…`).
- **Off-vocabulary scams**: Norton and Geek Squad renewal and refund lures (not protected brands), and `pc-virus-cleanup-alert.net`.
- **Legitimate samples include hard negatives**: "Use 482913 as Microsoft account security code", a real-style unusual sign-in alert, Microsoft 365 receipts, an IT desk saying "do not shut down your computer", a real Geek Squad appointment, and `outlookindia.com`.

### Job

- **Scams** impersonate Indeed recruiters (plus many brandless ones, which is how most job scams arrive): ID-photo and SSN requests before an interview, laptop and "training" fees by Zelle, gift card, USDT or Bitcoin, fake checks with a Cash App or Western Union pay-back, a mystery-shopper gift-card assignment, a spoofed `indeed.com` sender with a foreign Reply-To, and lookalike domains (`indeed-hiring-portal`, `lndeed-careers`, `indeed.com-…`).
- **Off-vocabulary scams**: "add our HR on WhatsApp" with no ask yet, and `remote-jobs-hiring-now.com`.
- **Legitimate samples include hard negatives**: real recruiter interview requests, onboarding paperwork (I-9, direct deposit in the HR portal), Indeed job alerts and application receipts, "Indeed, the team loved your presentation", and real job boards.

### All categories

- **Variants of the same template share a `group`** and always land in the same split.
- **Scenario labels (E4).** Every text and email scam sample has an expected named scenario (or `none`) in `scenario_labels.yaml`, hand-labeled from its content before the scenario rules were written. The labels live outside `samples.jsonl`, so they never change which split a sample lands in. URL samples have no message and aren't labeled.

## Rules
- Scam URLs are stored **defanged** (`hxxps://example[.]com`); a test enforces it. Domains in scam samples are invented.
- Synthetic samples are marked `synthetic: true`. Metrics are reported per data source.
- Raw downloads go in `data/eval/raw/`, which git ignores.
- User submissions are never added without consent.

## Limitations and next steps
- All samples were written by the same author as the detection rules, which likely inflates the numbers. Adding a real corpus is the most valuable next step: OpenPhish community feed / PhishTank archives for URLs (filtered to tax and financial brands), and a public phishing-email corpus for message bodies, each listed here with its license, with `synthetic: false`.
- Screenshots aren't in the evaluation set (they need the vision model).
