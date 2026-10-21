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

function renderDomainExplanations(explanations) {
  const list = $("#domain-explanations-list");
  list.replaceChildren();
  for (const explanation of explanations) {
    const item = document.createElement("div");
    item.className = "domain-explanation";
    text(item, "span", "domain-name", explanation.domain);
    const lines = document.createElement("ul");
    lines.className = "domain-summary";
    for (const line of explanation.summary ?? []) text(lines, "li", "", line);
    item.append(lines);
    list.append(item);
  }
  $("#no-domain-explanations").hidden = explanations.length > 0;
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
  $("#risk-score").textContent = result.risk_score;
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
  renderDomainExplanations(result.domain_explanations ?? []);
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

async function loadSaved() {
  try {
    const results = await jsonRequest("/v1/saved");
    $("#saved-view").hidden = false;
    $("#saved-count").textContent = `${results.length} ${results.length === 1 ? "analysis" : "analyses"}`;
    const list = $("#saved-list");
    list.replaceChildren();
    for (const result of results) {
      const item = document.createElement("article");
      item.className = "saved-item";
      const verdict = result.verdict === "likely_scam" ? "Likely a scam"
        : result.verdict === "suspicious" ? "Suspicious" : "Likely legitimate";
      const details = document.createElement("div");
      text(details, "span", "saved-verdict", verdict);
      text(details, "strong", "saved-score", `Risk score ${result.risk_score}/100`);
      const date = new Date(result.created_at);
      text(details, "span", "saved-date", Number.isNaN(date.getTime()) ? "" : date.toLocaleString());
      if (result.submitted) {
        const kind = { text: "Message", url: "Link", email: "Email", image: "Screenshot" }[result.input_type] ?? "Input";
        const preview = result.submitted.content.replace(/\s+/g, " ").trim().slice(0, 160);
        text(details, "span", "saved-input", `${kind}: ${preview}`);
      }
      item.append(details);
      const link = document.createElement("a");
      link.className = "text-button";
      link.href = `/results?analysis=${encodeURIComponent(result.analysis_id)}&saved=1`;
      link.textContent = "View result →";
      item.append(link);
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
      item.append(remove);
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
