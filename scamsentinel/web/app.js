const tabs = [...document.querySelectorAll(".input-tab")];
const form = document.querySelector("#analysis-form");
const content = document.querySelector("#content-input");
const contentLabel = document.querySelector("#content-label");
const hint = document.querySelector("#input-hint");
const counter = document.querySelector("#char-count");
const analyzeButton = document.querySelector("#analyze-button");
const errorBox = document.querySelector("#form-error");
const resultSection = document.querySelector("#result-section");
const resultCard = document.querySelector("#result-card");
const textShell = document.querySelector("#text-shell");
const imageShell = document.querySelector("#image-shell");
const imageInput = document.querySelector("#image-input");
const imagePreview = document.querySelector("#image-preview");
const imageDropText = document.querySelector("#image-drop-text");
const imageMeta = document.querySelector("#image-meta");
const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const IMAGE_TYPES = ["image/png", "image/jpeg", "image/webp"];
let mode = "text";
let llmConfigured = false;
let selectedImage = null;
let previewUrl = null;

const modes = {
  text: {
    label: "Paste the suspicious message",
    placeholder: "Example: Your package is on hold. Pay a small redelivery fee now to avoid having it returned...",
    hint: "Your message is sent to the local ScamSentinel API for analysis.",
    maxLength: 20000,
  },
  url: {
    label: "Paste the suspicious link",
    placeholder: "https://example.com/verify-account",
    hint: "We inspect the address as text. ScamSentinel never opens submitted links.",
    maxLength: 2048,
  },
  email: {
    label: "Paste the full email source",
    placeholder: "From: Support <help@example.com>\nSubject: Action required\n\nPaste the email headers and body here...",
    hint: "For best results, include the From, Reply-To, and Subject headers.",
    maxLength: 2097152,
  },
  image: {
    label: "Upload a screenshot of the message",
  },
};

function updatePrivacyHint() {
  if (mode === "text") {
    hint.textContent = llmConfigured
      ? "An LLM provider is configured; message text may be sent to that provider."
      : "Your message is sent to the local API and analyzed with local rules.";
  }
}

function setMode(nextMode) {
  mode = nextMode;
  for (const tab of tabs) {
    const selected = tab.dataset.mode === mode;
    tab.classList.toggle("selected", selected);
    tab.setAttribute("aria-selected", String(selected));
  }
  const config = modes[mode];
  const imageMode = mode === "image";
  textShell.hidden = imageMode;
  imageShell.hidden = !imageMode;
  contentLabel.textContent = config.label;
  contentLabel.htmlFor = imageMode ? "image-input" : "content-input";
  if (imageMode) return;
  content.placeholder = config.placeholder;
  content.maxLength = config.maxLength;
  hint.textContent = config.hint;
  counter.textContent = content.value.length.toLocaleString();
  updatePrivacyHint();
}

function formatBytes(bytes) {
  return bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : `${Math.ceil(bytes / 1024)} KB`;
}

function selectImage(file) {
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = null;
  selectedImage = null;
  imagePreview.hidden = true;
  imagePreview.removeAttribute("src");
  imageDropText.hidden = false;
  imageMeta.textContent = "";
  errorBox.hidden = true;
  if (!file) return;
  if (!IMAGE_TYPES.includes(file.type)) {
    errorBox.textContent = "Please choose a PNG, JPEG or WebP image.";
    errorBox.hidden = false;
    return;
  }
  if (file.size > MAX_IMAGE_BYTES) {
    errorBox.textContent = `That image is ${formatBytes(file.size)}; the limit is 5 MB.`;
    errorBox.hidden = false;
    return;
  }
  selectedImage = file;
  previewUrl = URL.createObjectURL(file);
  imagePreview.src = previewUrl;
  imagePreview.hidden = false;
  imageDropText.hidden = true;
  imageMeta.textContent = formatBytes(file.size);
}

imageInput.addEventListener("change", () => selectImage(imageInput.files[0]));
imageShell.addEventListener("dragover", (event) => {
  event.preventDefault();
  imageShell.classList.add("dragging");
});
imageShell.addEventListener("dragleave", () => imageShell.classList.remove("dragging"));
imageShell.addEventListener("drop", (event) => {
  event.preventDefault();
  imageShell.classList.remove("dragging");
  selectImage(event.dataTransfer.files[0]);
});

for (const tab of tabs) {
  tab.addEventListener("click", () => setMode(tab.dataset.mode));
}

content.addEventListener("input", () => {
  counter.textContent = content.value.length.toLocaleString();
});

document.querySelector("#new-analysis").addEventListener("click", () => {
  resultSection.hidden = true;
  content.focus();
  document.querySelector("#analyzer").scrollIntoView({ behavior: "smooth" });
});

function explainError(body, status) {
  const detail = body?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail.map((item) => item.msg).filter(Boolean).join(" ") || `Request failed (${status}).`;
  }
  return `The analysis could not be completed (HTTP ${status}). Please try again.`;
}

function addText(parent, tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = value;
  parent.append(node);
  return node;
}

function renderEvidence(reasons) {
  const list = document.querySelector("#evidence-list");
  list.replaceChildren();
  const meaningful = reasons.filter((reason) => reason.module !== "aggregate" || reason.evidence);
  document.querySelector("#signal-count").textContent =
    `${meaningful.length} ${meaningful.length === 1 ? "signal" : "signals"}`;
  if (!meaningful.length) {
    addText(list, "p", "no-evidence", "No specific warning signs were detected in this content.");
    return;
  }
  for (const reason of meaningful) {
    const row = document.createElement("div");
    row.className = "evidence-item";
    addText(row, "span", "module-tag", reason.module);
    const detail = document.createElement("div");
    detail.className = "evidence-detail";
    addText(detail, "span", "", reason.detail);
    if (reason.evidence) addText(detail, "span", "evidence-quote", `“${reason.evidence}”`);
    row.append(detail);
    const points = document.createElement("span");
    const mitigating = reason.points < 0;
    points.className = `evidence-points${mitigating ? " mitigating" : ""}`;
    points.textContent = reason.points > 0 ? `+${reason.points} pts` : reason.points < 0 ? `${reason.points} pts` : "info";
    row.append(points);
    list.append(row);
  }
}

function renderNextSteps(steps) {
  const box = document.querySelector("#next-steps");
  const list = document.querySelector("#next-steps-list");
  list.replaceChildren();
  box.hidden = !steps.length;
  for (const step of steps) {
    // Plain text only: the advice is never rendered as HTML or turned into links.
    addText(list, "li", "next-step", step.text);
  }
}

function renderDomainExplanations(explanations) {
  const box = document.querySelector("#domain-explanations");
  const list = document.querySelector("#domain-explanations-list");
  list.replaceChildren();
  box.hidden = !explanations.length;
  for (const explanation of explanations) {
    // The domain is attacker-chosen: plain text only, never a link.
    const item = document.createElement("div");
    item.className = "domain-explanation";
    addText(item, "span", "domain-name", explanation.domain);
    const lines = document.createElement("ul");
    lines.className = "domain-summary";
    for (const line of explanation.summary ?? []) addText(lines, "li", "", line);
    item.append(lines);
    list.append(item);
  }
}

function renderScenario(scenario, verdict) {
  const box = document.querySelector("#scenario");
  box.hidden = !scenario;
  if (!scenario) return;
  // A suspicious result only resembles the pattern; a likely scam follows it.
  document.querySelector("#scenario-label").textContent =
    verdict === "likely_scam" ? "Known scam pattern" : "Resembles a known scam pattern";
  document.querySelector("#scenario-name").textContent = scenario.name;
  document.querySelector("#scenario-description").textContent = scenario.description;
  const matched = (scenario.matched_on ?? []).join(" · ");
  // Plain text: the source comes from a data file but is still not turned into a link.
  document.querySelector("#scenario-meta").textContent =
    [matched && `Matched on: ${matched}`, scenario.source && `Source: ${scenario.source}`]
      .filter(Boolean)
      .join(" — ");
}

const FACT_OUTCOMES = {
  conflicts: ["Conflicts", "conflicts"],
  cannot_verify: ["Can't verify", "unverified"],
  matches: ["Matches", "matches"],
};
const FACT_BASIS = {
  published_fact: "",
  brand_list: "Official domain list",
  email_headers: "The email's own headers",
  model_knowledge: "AI model knowledge (unverified)",
  no_fact: "No published fact",
};

function renderFactChecks(rows) {
  const box = document.querySelector("#fact-checks");
  const body = document.querySelector("#fact-check-rows");
  body.replaceChildren();
  box.hidden = !rows.length;
  const conflicts = rows.filter((row) => row.outcome === "conflicts").length;
  document.querySelector("#fact-check-count").textContent =
    `${conflicts} of ${rows.length} ${rows.length === 1 ? "claim conflicts" : "claims conflict"}`;
  for (const row of rows) {
    // Claims quote the message: plain text only. Sources come from data files but are
    // still shown as text, not links.
    const tr = document.createElement("tr");
    addText(tr, "td", "fact-claim", row.claim);
    const against = document.createElement("td");
    against.className = "fact-against";
    const label = FACT_BASIS[row.basis] ?? "";
    if (label) addText(against, "span", "fact-basis", label);
    addText(against, "span", "", row.fact ?? row.detail);
    if (row.source || row.last_reviewed) {
      const meta = [row.source, row.last_reviewed && `reviewed ${row.last_reviewed}`].filter(Boolean);
      addText(against, "span", "fact-source", meta.join(" · "));
    }
    tr.append(against);
    const [text, tone] = FACT_OUTCOMES[row.outcome] ?? ["", ""];
    const cell = document.createElement("td");
    addText(cell, "span", `fact-outcome ${tone}`, text);
    tr.append(cell);
    body.append(tr);
  }
}

function renderResult(result) {
  const verdicts = {
    likely_legitimate: ["Likely legitimate", "No major warning signs found", "legitimate"],
    suspicious: ["Suspicious", "Some warning signs need a closer look", "suspicious"],
    likely_scam: ["Likely a scam", "Strong warning signs detected", "likely-scam"],
  };
  const [label, title, tone] = verdicts[result.verdict] ?? ["Analysis complete", "Review the evidence below", "suspicious"];
  resultCard.className = `result-card ${tone}`;
  const ring = document.querySelector("#score-ring");
  // Same thresholds as the verdict bands in config/scoring.yaml (60 / 30).
  const scoreColor = result.risk_score >= 60 ? "#d65f6a" : result.risk_score >= 30 ? "#e3a64f" : "#65b68e";
  ring.style.setProperty("--score", `${Math.max(0, Math.min(100, result.risk_score))}%`);
  ring.style.setProperty("--score-color", scoreColor);
  document.querySelector("#risk-score").textContent = result.risk_score;
  document.querySelector("#verdict-pill").textContent = label;
  document.querySelector("#result-title").textContent = title;
  const inputName = { text: "Message", url: "Link", email: "Email", image: "Screenshot" }[result.input_type] ?? "Content";
  document.querySelector("#result-summary").textContent =
    `${inputName} analyzed${result.llm_used ? " with AI-assisted signal extraction" : " with local detection rules"}.`;
  const created = new Date(result.created_at);
  document.querySelector("#result-meta").textContent =
    Number.isNaN(created.getTime()) ? "" : created.toLocaleString();
  document.querySelector("#analysis-id").textContent = `Analysis ${result.analysis_id}`;
  const notes = document.querySelector("#result-notes");
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
  renderNextSteps(result.next_steps ?? []);
  renderDomainExplanations(result.domain_explanations ?? []);
  renderFactChecks(result.fact_checks ?? []);
  renderEvidence(result.reasons ?? []);
  resultSection.hidden = false;
  resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.hidden = true;
  errorBox.textContent = "";
  const imageMode = mode === "image";
  if (imageMode ? !selectedImage : !content.value.trim()) {
    errorBox.textContent = imageMode ? "Choose a screenshot to analyze." : "Paste some content to analyze.";
    errorBox.hidden = false;
    (imageMode ? imageInput : content).focus();
    return;
  }
  analyzeButton.disabled = true;
  analyzeButton.classList.add("loading");
  analyzeButton.querySelector(".button-label").textContent = "Analyzing...";
  try {
    let response;
    if (imageMode) {
      // Raw image body with an image/* Content-Type, as /v1/analyze/image expects.
      response = await fetch("/v1/analyze/image", {
        method: "POST",
        headers: { "Content-Type": selectedImage.type },
        body: selectedImage,
      });
    } else {
      const key = { text: "text", url: "url", email: "email_raw" }[mode];
      response = await fetch("/v1/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ [key]: content.value.trim() }),
      });
    }
    const body = await response.json();
    if (!response.ok) throw new Error(explainError(body, response.status));
    renderResult(body);
  } catch (error) {
    errorBox.textContent = error instanceof TypeError
      ? "Could not reach the local ScamSentinel API. Make sure it is running, then refresh this page."
      : error.message;
    errorBox.hidden = false;
  } finally {
    analyzeButton.disabled = false;
    analyzeButton.classList.remove("loading");
    analyzeButton.querySelector(".button-label").textContent = "Analyze content";
  }
});

async function updateApiStatus() {
  const status = document.querySelector("#api-status");
  try {
    const response = await fetch("/healthz");
    if (!response.ok) throw new Error("API unavailable");
    const health = await response.json();
    llmConfigured = health.llm === "configured";
    updatePrivacyHint();
    status.className = "local-status online";
    status.lastElementChild.textContent = "Local API connected";
  } catch {
    status.className = "local-status offline";
    status.lastElementChild.textContent = "Local API unavailable";
  }
}

updateApiStatus();
