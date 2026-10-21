const $ = (selector) => document.querySelector(selector);
const pageError = $("#page-error");
const savedPage = Boolean($("#saved-list"));
let authMode = "login";
let currentResult = null;
let currentEmail = null;

function text(parent, tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = value ?? "";
  parent.append(node);
  return node;
}

async function jsonRequest(url, options = {}) {
  const response = await fetch(url, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = body.detail;
    throw new Error(typeof detail === "string" ? detail : `Request failed (${response.status}).`);
  }
  return body;
}

function renderScenario(scenario, verdict) {
  const box = $("#scenario");
  if (!box) return;
  box.hidden = !scenario;
  if (!scenario) return;
  $("#scenario-label").textContent = verdict === "likely_scam"
    ? "Known scam pattern"
    : "Resembles a known scam pattern";
  $("#scenario-name").textContent = scenario.name;
  $("#scenario-description").textContent = scenario.description;
  $("#scenario-meta").textContent = [
    scenario.matched_on?.length ? `Matched on: ${scenario.matched_on.join(" · ")}` : "",
    scenario.source ? `Source: ${scenario.source}` : "",
  ].filter(Boolean).join(" — ");
}

function renderSteps(steps) {
  const list = $("#next-steps-list");
  list.replaceChildren();
  for (const step of steps) text(list, "li", "next-step", step.text);
  $("#no-next-steps").hidden = steps.length > 0;
}

function renderResources(resources) {
  const list = $("#resource-list");
  list.replaceChildren();
  const safe = resources.filter((item) => typeof item.url === "string" && item.url.startsWith("https://"));
  for (const resource of safe) {
    const item = document.createElement("li");
    item.className = "resource";
    text(item, "span", "resource-kind",
      resource.kind === "official_help" ? `From ${resource.publisher}` : `About this type of scam · ${resource.publisher}`);
    const link = document.createElement("a");
    link.className = "resource-link";
    link.href = resource.url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = resource.title;
    item.append(link);
    list.append(item);
  }
  $("#no-resources").hidden = safe.length > 0;
}

// Domains that were checked but don't imitate a brand still get a row, so a link is never
// silently left out of this card.
const PLAIN_DOMAIN_NOTES = {
  no_lookalike_signals: "It doesn’t imitate a brand ScamSentinel protects, so there’s no official site list to compare it with. That alone doesn’t make it safe.",
  official_domain: "It’s on the brand’s official site list.",
  ip_address_host: "Links that use a bare IP address instead of a name are unusual for real organizations.",
};

function domainRow(list, domain, lines) {
  const item = document.createElement("div");
  item.className = "domain-explanation";
  text(item, "span", "domain-name", domain);
  const summary = document.createElement("ul");
  summary.className = "domain-summary";
  for (const line of lines) text(summary, "li", "", line);
  item.append(summary);
  list.append(item);
}

function renderDomainExplanations(explanations, reasons) {
  const list = $("#domain-explanations-list");
  list.replaceChildren();
  for (const explanation of explanations) domainRow(list, explanation.domain, explanation.summary ?? []);
  const explained = new Set(explanations.map((explanation) => explanation.domain));
  const shown = new Set();
  for (const reason of reasons) {
    const host = reason.evidence;
    const note = PLAIN_DOMAIN_NOTES[reason.signal];
    if (reason.module !== "domain" || !host || !note || shown.has(host)) continue;
    if ([...explained].some((domain) => host === domain || host.endsWith(`.${domain}`))) continue;
    shown.add(host);
    domainRow(list, host, [reason.detail, note]);
  }
  $("#no-domain-explanations").hidden = list.childElementCount > 0;
}

function sayClaims(count) {
  return count === 1 ? "1 claim conflicts" : `${count} claims conflict`;
}

// The heading is only as firm as the evidence: a page that impersonates a brand and asks
// for credentials, or a link that isn't on the brand's official domain list, are facts;
// otherwise it stays neutral.
function linkCheckHeading(result) {
  const analyzed = (result.pages ?? []).filter((page) => page.status === "analyzed" && page.brand);
  const harvest = analyzed.find((page) => page.asks_for?.length);
  const fake = (result.domain_explanations ?? [])[0];
  const conflicts = (result.fact_checks ?? []).filter((row) => row.outcome === "conflicts").length;
  const andClaims = conflicts ? `, and ${sayClaims(conflicts)} with published facts` : "";
  if (harvest) {
    return [
      `This is a fake ${harvest.brand} page`,
      `It uses ${harvest.brand}’s name on a site ${harvest.brand} doesn’t own and asks for ${harvest.asks_for.join(", ")}${andClaims}`,
    ];
  }
  if (fake) {
    const official = fake.official_domains.slice(0, 2).join(" or ");
    return [
      `This link isn’t ${fake.brand}`,
      `${fake.domain} isn’t an official ${fake.brand} site${official ? ` (${official})` : ""}${andClaims}`,
    ];
  }
  if (analyzed.length) {
    const page = analyzed[0];
    return [`This page isn’t ${page.brand}’s`, `It uses ${page.brand}’s name on a site ${page.brand} doesn’t own${andClaims}`];
  }
  const offSite = (result.reasons ?? []).find((reason) => reason.signal === "link_sender_mismatch");
  if (offSite) return ["This link doesn’t go to the sender’s site", offSite.detail];
  if (conflicts) return ["The claims don’t add up", `${sayClaims(conflicts)} with published facts`];
  return ["Link and claim checks", "Domain clues and claims checked against known facts"];
}

const PAGE_ERRORS = {
  timeout: "The page took too long to answer.",
  unreachable: "The site couldn’t be reached (or its certificate isn’t valid).",
  not_html: "The link doesn’t lead to a web page.",
  too_many_redirects: "The link redirected too many times.",
  unsupported_encoding: "The page used an encoding ScamSentinel doesn’t read.",
};

function describePageError(error) {
  if (!error) return "The page couldn’t be analyzed.";
  if (error === "blocked:egress" || error === "disabled:safety") {
    return "Not fetched: a safety check stopped page fetching, so it’s turned off until ScamSentinel restarts.";
  }
  if (error.startsWith("blocked:")) {
    return "Not fetched: the link points to a private or disallowed address, so ScamSentinel refused to connect.";
  }
  if (error === "rate_limited") return "Not fetched: too many pages were fetched in the last minute.";
  if (error.startsWith("http_")) return `The site answered with an error (HTTP ${error.slice(5)}).`;
  return PAGE_ERRORS[error] ?? "The page couldn’t be analyzed.";
}

function renderPages(pages) {
  const card = $("#pages-card");
  if (!card) return;
  card.hidden = !pages.length;
  const list = $("#page-reports");
  list.replaceChildren();
  for (const page of pages) {
    // Everything here comes from an attacker-written page: plain text only, no links.
    const item = document.createElement("div");
    item.className = "page-report";
    text(item, "span", "domain-name", page.final_url || page.requested_url);
    if (page.redirects?.length) {
      text(item, "span", "page-meta", `Redirects: ${[page.requested_url, ...page.redirects].join(" → ")}`);
    }
    if (page.title) text(item, "span", "page-meta", `Title: “${page.title}”`);
    const lines = document.createElement("ul");
    lines.className = "domain-summary";
    if (page.status === "dry_run") {
      text(lines, "li", "", "Dry run: the link passed the safety checks and would be fetched in live mode. Nothing was looked up or downloaded.");
    } else if (page.status !== "analyzed") {
      text(lines, "li", "", `${describePageError(page.error)} That doesn’t mean the link is safe.`);
    } else if (!page.findings?.length) {
      text(lines, "li", "", "Nothing suspicious found on the page. That doesn’t make it safe.");
    } else {
      for (const finding of page.findings) text(lines, "li", "", finding.detail);
    }
    if (page.truncated) text(lines, "li", "", "Only the first part of a very large page was read.");
    item.append(lines);
    list.append(item);
  }
}

function renderSubmitted(result, fromSaved) {
  const card = $("#submitted-card");
  if (!card) return;
  const submitted = result.submitted;
  card.hidden = !submitted;
  if (!submitted) return;
  // Attacker-written content: plain text only, so links in it are never clickable.
  $("#submitted-text").textContent = submitted.content;
  const image = $("#submitted-image");
  const isImage = Boolean(submitted.image_mime);
  image.hidden = !isImage;
  $("#submitted-text-label").hidden = !isImage;
  if (isImage) {
    const id = encodeURIComponent(result.analysis_id);
    image.src = fromSaved ? `/v1/saved/${id}/image` : `/v1/analysis/${id}/image`;
    image.addEventListener("error", () => { image.hidden = true; }, { once: true });
  } else {
    image.removeAttribute("src");
  }
}

const FACT_OUTCOMES = {
  conflicts: ["Conflicts", "conflicts"],
  cannot_verify: ["Can’t verify", "unverified"],
  matches: ["Matches", "matches"],
};
const FACT_BASIS = {
  published_fact: "",
  brand_list: "Official domain list",
  email_headers: "The email’s own headers",
  model_knowledge: "AI model knowledge (unverified)",
  no_fact: "No published fact",
};

function renderFactChecks(rows) {
  const body = $("#fact-check-rows");
  body.replaceChildren();
  const conflicts = rows.filter((row) => row.outcome === "conflicts").length;
  $("#fact-check-count").textContent = `${conflicts} of ${rows.length} claims conflict`;
  for (const row of rows) {
    const tr = document.createElement("tr");
    text(tr, "td", "fact-claim", row.claim);
    const against = document.createElement("td");
    against.className = "fact-against";
    const basis = FACT_BASIS[row.basis] ?? "";
    if (basis) text(against, "span", "fact-basis", basis);
    text(against, "span", "", row.fact ?? row.detail);
    if (row.source || row.last_reviewed) {
      text(against, "span", "fact-source",
        [row.source, row.last_reviewed && `reviewed ${row.last_reviewed}`].filter(Boolean).join(" · "));
    }
    tr.append(against);
    const [label, tone] = FACT_OUTCOMES[row.outcome] ?? ["Unknown", "unverified"];
    const result = document.createElement("td");
    text(result, "span", `fact-outcome ${tone}`, label);
    tr.append(result);
    body.append(tr);
  }
  $("#no-fact-checks").hidden = rows.length > 0;
}

function renderEvidence(reasons, score) {
  const list = $("#evidence-list");
  list.replaceChildren();
  const meaningful = reasons.filter((reason) => reason.module !== "aggregate" || reason.evidence);
  $("#signal-count").textContent = `${meaningful.length} ${meaningful.length === 1 ? "signal" : "signals"} · Risk score ${score}/100`;
  $("#signals-score").textContent = `Risk score ${score}/100`;
  if (!meaningful.length) {
    text(list, "p", "no-evidence", "No specific warning signs were detected in this content.");
    return;
  }
  for (const reason of meaningful) {
    const row = document.createElement("div");
    row.className = "evidence-item";
    text(row, "span", "module-tag", reason.module);
    const detail = document.createElement("div");
    detail.className = "evidence-detail";
    text(detail, "span", "", reason.detail);
    const evidence = reason.evidence?.trim();
    const unquotedEvidence = evidence?.replace(/^["“”'‘’]+|["“”'‘’]+$/g, "").trim();
    if (
      evidence &&
      !reason.detail.includes(evidence) &&
      !(unquotedEvidence && reason.detail.includes(unquotedEvidence))
    ) {
      text(detail, "span", "evidence-quote", `“${unquotedEvidence || evidence}”`);
    }
    row.append(detail);
    const points = document.createElement("span");
    points.className = `evidence-points${reason.points < 0 ? " mitigating" : ""}`;
    points.textContent = reason.points > 0 ? `+${reason.points} pts` : reason.points < 0 ? `${reason.points} pts` : "info";
    row.append(points);
    list.append(row);
  }
}

// The score counts up while the ring fills in (app.css: same 0.2s delay and 1.1s length),
// unless motion is reduced.
function countUp(node, value) {
  node.textContent = value;
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const start = performance.now() + 200;
  const step = (now) => {
    const t = Math.min(1, Math.max(0, (now - start) / 1100));
    node.textContent = t < 1 ? Math.round(value * (1 - (1 - t) ** 3)) : value;
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function renderResult(result, fromSaved = false) {
  const verdicts = {
    likely_legitimate: ["Likely legitimate", "No major warning signs found", "legitimate"],
    suspicious: ["Suspicious", "Some warning signs need a closer look", "suspicious"],
    likely_scam: ["Likely a scam", "Strong warning signs detected", "likely-scam"],
  };
  const [label, title, tone] = verdicts[result.verdict] ?? ["Analysis complete", "Review the evidence below", "suspicious"];
  $("#result-card").className = `result-overview ${tone}`;
  const ring = $("#score-ring");
  const scoreColor = result.risk_score >= 60 ? "#d65f6a" : result.risk_score >= 30 ? "#e3a64f" : "#65b68e";
  ring.style.setProperty("--score", `${Math.max(0, Math.min(100, result.risk_score))}%`);
  ring.style.setProperty("--score-color", scoreColor);
  countUp($("#risk-score"), result.risk_score);
  $("#verdict-pill").textContent = label;
  $("#result-title").textContent = title;
  const inputName = { text: "Message", url: "Link", email: "Email", image: "Screenshot" }[result.input_type] ?? "Content";
  $("#result-summary").textContent =
    `${inputName} analyzed${result.llm_used ? " with AI-assisted signal extraction" : " with local detection rules"}.`;
  const created = new Date(result.created_at);
  $("#result-meta").textContent = Number.isNaN(created.getTime()) ? "" : created.toLocaleString();
  $("#analysis-id").textContent = `Analysis ${result.analysis_id} · Use your judgment; this is an aid, not a guarantee.`;
  const notes = $("#result-notes");
  if (result.degraded?.length) {
    notes.hidden = false;
    notes.textContent = result.degraded.includes("llm_not_configured")
      ? "AI signal extraction is not configured; this result uses ScamSentinel’s local rules."
      : "Some optional analysis features were unavailable. This result may rely on fewer signals.";
  } else {
    notes.hidden = true;
    notes.textContent = "";
  }
  renderScenario(result.scenario ?? null, result.verdict);
  renderSubmitted(result, fromSaved);
  renderSteps(result.next_steps ?? []);
  renderResources(result.resources ?? []);
  const [linkTitle, linkCaption] = linkCheckHeading(result);
  $("#link-check-title").textContent = linkTitle;
  $("#link-check-caption").textContent = linkCaption;
  renderDomainExplanations(result.domain_explanations ?? [], result.reasons ?? []);
  renderFactChecks(result.fact_checks ?? []);
  renderPages(result.pages ?? []);
  renderEvidence(result.reasons ?? [], result.risk_score);
  $("#analysis-view").hidden = false;
  currentResult = result;
  refreshSavedState();
}

function setAuthMode(next) {
  authMode = next;
  for (const button of document.querySelectorAll("[data-auth-mode]")) {
    const selected = button.dataset.authMode === authMode;
    button.classList.toggle("selected", selected);
    button.setAttribute("aria-pressed", String(selected));
  }
  const submit = $("#auth-submit");
  if (submit) submit.textContent = authMode === "login" ? "Log in" : "Create account";
  const password = document.querySelector('#auth-form input[name="password"]');
  if (password) password.autocomplete = authMode === "login" ? "current-password" : "new-password";
}

async function refreshSavedState() {
  if (!currentEmail) return;
  const button = $("#save-analysis");
  if (!button || !currentResult) return;
  try {
    const saved = await jsonRequest("/v1/saved");
    const exists = saved.some((item) => item.analysis_id === currentResult.analysis_id);
    button.disabled = exists;
    button.textContent = exists ? "Analysis saved" : "Save analysis";
    if (exists) $("#save-confirmation").textContent = "This analysis is saved to your account.";
    $("#save-confirmation").hidden = !exists;
  } catch (error) {
    if (error.message.includes("log in")) showAuth(null);
    else {
      const authError = $("#auth-error");
      authError.textContent = error.message;
      authError.hidden = false;
    }
  }
}

function showAuth(email) {
  currentEmail = email;
  const auth = $("#auth-controls");
  const actions = $("#account-actions");
  if (!auth || !actions) return;
  auth.hidden = Boolean(email);
  actions.hidden = !email;
  if (email) {
    $("#account-email").textContent = email;
    if ($("#save-heading")) $("#save-heading").textContent = savedPage ? "You’re signed in" : "Signed in";
    if ($("#save-description")) $("#save-description").textContent = savedPage
      ? "Review or remove your saved analyses below."
      : "Save this result to revisit it later.";
  }
}

for (const button of document.querySelectorAll("[data-auth-mode]")) {
  button.addEventListener("click", () => setAuthMode(button.dataset.authMode));
}

const authForm = $("#auth-form");
if (authForm) {
  authForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const error = $("#auth-error");
    error.hidden = true;
    const form = new FormData(authForm);
    try {
      const account = await jsonRequest(`/v1/auth/${authMode === "login" ? "login" : "register"}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: form.get("email"), password: form.get("password") }),
      });
      authForm.reset();
      showAuth(account.email);
      if (savedPage) await loadSaved();
      else await refreshSavedState();
    } catch (requestError) {
      error.textContent = requestError.message;
      error.hidden = false;
    }
  });
}

const saveButton = $("#save-analysis");
if (saveButton) {
  saveButton.addEventListener("click", async () => {
    const error = $("#auth-error");
    const confirmation = $("#save-confirmation");
    error.hidden = true;
    confirmation.hidden = true;
    try {
      await jsonRequest(`/v1/saved/${encodeURIComponent(currentResult.analysis_id)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      saveButton.disabled = true;
      saveButton.textContent = "Analysis saved";
      confirmation.textContent = "Saved to your local account. You can find it under Saved analyses.";
      confirmation.hidden = false;
    } catch (requestError) {
      error.textContent = requestError.message;
      error.hidden = false;
    }
  });
}

const logoutButton = $("#logout");
if (logoutButton) {
  logoutButton.addEventListener("click", async () => {
    const error = $("#auth-error");
    error.hidden = true;
    try {
      await jsonRequest("/v1/auth/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      showAuth(null);
      if ($("#save-heading")) $("#save-heading").textContent = savedPage ? "Log in to view saved analyses" : "Keep this analysis";
      if ($("#save-description")) $("#save-description").textContent = savedPage
        ? "Your account and saved results are stored on this ScamSentinel installation."
        : "Create a local account or log in to save and revisit this result.";
      if (savedPage) $("#saved-view").hidden = true;
      if (saveButton) {
        saveButton.disabled = false;
        saveButton.textContent = "Save analysis";
      }
    } catch (requestError) {
      error.textContent = requestError.message;
      error.hidden = false;
    }
  });
}

// Email header lines (and a mail app's chrome in screenshots) aren't part of the excerpt.
const SHOWN_HEADER = /^\s*(?:(?:from|to|reply-to|subject|date|cc|content-type)\s*:.*|message details|mail\s*\|\s*inbox)\s*$/i;

function shorten(value, limit) {
  return value.length > limit ? `${value.slice(0, limit - 1).trimEnd()}…` : value;
}

// Words from a mail app's menus that a screenshot picks up ("Inbox Starred Sent ...").
const MAIL_UI_WORDS = new Set([
  "mail", "inbox", "compose", "starred", "snoozed", "sent", "drafts", "spam", "trash", "archive",
  "important", "more", "reply", "forward", "delete", "search", "primary", "promotions", "social",
  "updates", "labels", "+", "|", "←", "→",
]);

// Drops the menu words a line starts with ("Mail + Compose Inbox Sent Unusual sign-in" →
// "Unusual sign-in"); a line that is only menu words becomes empty.
function withoutMailChrome(line) {
  const words = line.trim().split(/\s+/).filter(Boolean);
  let start = 0;
  while (start < words.length && MAIL_UI_WORDS.has(words[start].toLowerCase())) start += 1;
  return words.slice(start).join(" ");
}

// What a message is about, in a few words, from the threat the rules found. The reason
// details are fixed templates ("Threatens <label>: ..."), see message/scoring.py.
const THREAT_TOPICS = [
  ["suspicious activity on your account", "Sign-in alert"],
  ["account suspension", "Account suspension notice"],
  ["losing access to your account", "Account lockout warning"],
  ["a held or undeliverable package", "Package delivery notice"],
  ["losing your refund", "Tax refund notice"],
  ["an infected or hacked device", "Virus warning"],
  ["losing a job offer", "Job offer"],
  ["arrest", "Arrest threat"],
  ["legal action", "Legal threat"],
  ["penalties", "Penalty notice"],
];

function topicFrom(reasons) {
  const details = reasons.map((reason) => reason.detail ?? "");
  for (const [label, topic] of THREAT_TOPICS) {
    if (details.some((detail) => detail.startsWith(`Threatens ${label}:`))) return topic;
  }
  if (reasons.some((reason) => reason.signal === "unusual_payment_method")) return "Payment demand";
  if (details.some((detail) => /^Asks for a password|^Asks for a verification/.test(detail))) return "Login details request";
  if (reasons.some((reason) => reason.signal === "sensitive_request")) return "Personal details request";
  return null;
}

function fewWords(value, count) {
  const words = value.replace(/\s+/g, " ").trim().split(" ");
  return words.length > count ? `${words.slice(0, count).join(" ")}…` : words.join(" ");
}

// A saved card's title is a few descriptive words built from the findings: the named
// scenario, else what the message threatens or asks for, else the email subject or the
// link's site. The brand it claims to be is added when there is one. The excerpt is the
// text itself, without email headers or the mail app's menus.
function savedSummary(result) {
  const kind = { text: "Message", url: "Link", email: "Email", image: "Screenshot" }[result.input_type] ?? "Analysis";
  const reasons = result.reasons ?? [];
  const content = result.submitted?.content ?? "";
  const lines = content.split(/\r?\n/);
  const subject = lines.map((line) => line.match(/^\s*subject\s*:\s*(.+)$/i)?.[1]).find(Boolean);
  const brand = reasons.map((reason) => reason.detail?.match(/^Presents itself as (.+?):/)?.[1]).find(Boolean);

  let title = result.scenario?.name ?? topicFrom(reasons);
  if (!title && subject) title = fewWords(subject, 6);
  if (!title && result.input_type === "url") {
    const host = content.trim().replace(/^[a-z]+:\/\//i, "").split(/[/?#]/)[0];
    title = host ? `Link to ${host}` : null;
  }
  if (!title) title = `${kind} analysis`;
  if (brand && !title.includes(brand)) {
    title += result.verdict === "likely_legitimate" ? ` from ${brand}` : ` posing as ${brand}`;
  }

  const excerpt = result.input_type === "url" ? "" : lines
    .filter((line) => !SHOWN_HEADER.test(line))
    .map(withoutMailChrome)
    .join(" ").replace(/\s+/g, " ").trim();
  return { title: shorten(title, 60), excerpt: shorten(excerpt, 220) };
}

async function loadSaved() {
  try {
    const results = await jsonRequest("/v1/saved");
    $("#saved-view").hidden = false;
    $("#saved-count").textContent = `${results.length} ${results.length === 1 ? "analysis" : "analyses"}`;
    const list = $("#saved-list");
    list.replaceChildren();
    for (const result of results) {
      const item = document.createElement("article");
      const tone = result.verdict === "likely_scam" ? "likely-scam"
        : result.verdict === "suspicious" ? "suspicious" : "legitimate";
      item.className = `saved-item ${tone}`;
      const verdict = result.verdict === "likely_scam" ? "Likely a scam"
        : result.verdict === "suspicious" ? "Suspicious" : "Likely legitimate";

      const ring = document.createElement("div");
      ring.className = "saved-ring";
      ring.style.setProperty("--score", `${Math.max(0, Math.min(100, result.risk_score))}%`);
      ring.setAttribute("aria-label", `Risk score ${result.risk_score} of 100`);
      text(ring, "strong", "", String(result.risk_score));
      item.append(ring);

      const details = document.createElement("div");
      details.className = "saved-details";
      const meta = document.createElement("div");
      meta.className = "saved-meta";
      text(meta, "span", "verdict-pill", verdict);
      const date = new Date(result.created_at);
      text(meta, "span", "saved-date", Number.isNaN(date.getTime()) ? "" : date.toLocaleString());
      details.append(meta);
      const { title, excerpt } = savedSummary(result);
      text(details, "h3", "saved-title", title);
      if (excerpt) text(details, "p", "saved-excerpt", excerpt);
      item.append(details);

      const actions = document.createElement("div");
      actions.className = "saved-actions";
      const link = document.createElement("a");
      link.className = "text-button";
      link.href = `/results?analysis=${encodeURIComponent(result.analysis_id)}&saved=1`;
      link.textContent = "View result →";
      actions.append(link);
      const remove = document.createElement("button");
      remove.className = "text-button remove-saved";
      remove.type = "button";
      remove.textContent = "Remove";
      remove.addEventListener("click", async () => {
        remove.disabled = true;
        try {
          await jsonRequest(`/v1/saved/${encodeURIComponent(result.analysis_id)}`, { method: "DELETE" });
          await loadSaved();
        } catch (error) {
          pageError.textContent = error.message;
          pageError.hidden = false;
          remove.disabled = false;
        }
      });
      actions.append(remove);
      item.append(actions);
      list.append(item);
    }
    $("#saved-empty").hidden = results.length > 0;
  } catch (error) {
    if (error.message.includes("log in")) {
      $("#saved-view").hidden = true;
      return;
    }
    pageError.textContent = error.message;
    pageError.hidden = false;
  }
}

async function initialize() {
  setAuthMode("login");
  try {
    const me = await jsonRequest("/v1/auth/me");
    showAuth(me.email);
    if (savedPage) {
      if (me.email) await loadSaved();
      return;
    }
    const params = new URLSearchParams(window.location.search);
    const id = params.get("analysis");
    if (!id) throw new Error("No analysis was selected. Start a new analysis to see its results.");
    const fromSaved = params.get("saved") === "1";
    const endpoint = fromSaved ? `/v1/saved/${encodeURIComponent(id)}` : `/v1/analysis/${encodeURIComponent(id)}`;
    renderResult(await jsonRequest(endpoint), fromSaved);
  } catch (error) {
    pageError.textContent = error.message;
    pageError.hidden = false;
  }
}

initialize();
