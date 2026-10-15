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
let mode = "text";
let llmConfigured = false;

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
  contentLabel.textContent = config.label;
  content.placeholder = config.placeholder;
  content.maxLength = config.maxLength;
  hint.textContent = config.hint;
  counter.textContent = content.value.length.toLocaleString();
  updatePrivacyHint();
}

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

function renderResult(result) {
  const verdicts = {
    likely_legitimate: ["Likely legitimate", "No major warning signs found", "legitimate"],
    suspicious: ["Suspicious", "Some warning signs need a closer look", "suspicious"],
    likely_scam: ["Likely a scam", "Strong warning signs detected", "likely-scam"],
  };
  const [label, title, tone] = verdicts[result.verdict] ?? ["Analysis complete", "Review the evidence below", "suspicious"];
  resultCard.className = `result-card ${tone}`;
  const ring = document.querySelector("#score-ring");
  const scoreColor = result.risk_score >= 70 ? "#d65f6a" : result.risk_score >= 35 ? "#e3a64f" : "#65b68e";
  ring.style.setProperty("--score", `${Math.max(0, Math.min(100, result.risk_score))}%`);
  ring.style.setProperty("--score-color", scoreColor);
  document.querySelector("#risk-score").textContent = result.risk_score;
  document.querySelector("#verdict-pill").textContent = label;
  document.querySelector("#result-title").textContent = title;
  document.querySelector("#result-summary").textContent =
    `${result.input_type[0].toUpperCase()}${result.input_type.slice(1)} analyzed${result.llm_used ? " with AI-assisted signal extraction" : " with local detection rules"}.`;
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
  renderEvidence(result.reasons ?? []);
  resultSection.hidden = false;
  resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.hidden = true;
  errorBox.textContent = "";
  if (!content.value.trim()) {
    errorBox.textContent = "Paste some content to analyze.";
    errorBox.hidden = false;
    content.focus();
    return;
  }
  analyzeButton.disabled = true;
  analyzeButton.classList.add("loading");
  analyzeButton.querySelector(".button-label").textContent = "Analyzing...";
  try {
    const key = { text: "text", url: "url", email: "email_raw" }[mode];
    const response = await fetch("/v1/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ [key]: content.value.trim() }),
    });
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
