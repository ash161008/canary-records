/* Canary Records frontend.
 *
 * This file displays backend results. It never decides whether an action was
 * allowed, quarantined, held or blocked: every badge, rule and status string
 * comes from the backend's own verdict and is only rendered here. The one
 * thing it decides for itself is presentation - which screen is showing, and
 * whether an email's hidden text is revealed.
 *
 * Any value that came from a file, a log, a model or a person is written with
 * textContent. innerHTML is never used with data.
 */

"use strict";

const SCREENS = ["problem", "seed", "run", "audit", "scoreboard"];

const state = {
  messages: [],
  selected: null,
  showHidden: false,
  session: null,
  runId: null,
};

/* ---------- small helpers ---------- */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function setStatus(id, message, kind) {
  const node = document.getElementById(id);
  if (!node) return;
  node.textContent = message || "";
  node.dataset.kind = kind || "";
}

function adminToken() {
  let token = sessionStorage.getItem("adminToken");
  if (!token) {
    token = window.prompt(
      "Administrator token\n\nAdmin actions need the ADMIN_TOKEN from the " +
        "server's .env file. It is kept for this browser tab only."
    );
    if (token) sessionStorage.setItem("adminToken", token.trim());
  }
  return token ? token.trim() : null;
}

async function api(path, options) {
  const settings = Object.assign({ headers: {} }, options || {});
  if (settings.admin) {
    const token = adminToken();
    if (!token) throw new Error("An administrator token is required.");
    settings.headers["X-Admin-Token"] = token;
    delete settings.admin;
  }
  if (settings.body !== undefined) {
    settings.headers["Content-Type"] = "application/json";
    settings.body = JSON.stringify(settings.body);
  }

  const response = await fetch(path, settings);
  let payload = null;
  try {
    payload = await response.json();
  } catch (error) {
    payload = null;
  }

  if (!response.ok) {
    if (response.status === 401) sessionStorage.removeItem("adminToken");
    const detail =
      (payload && (payload.detail || payload.message)) ||
      `HTTP ${response.status}`;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return payload;
}

/** Run an async action with the button disabled and a status line. */
async function withButton(button, statusId, working, action) {
  const others = Array.from(document.querySelectorAll("button"));
  const wasDisabled = others.map((b) => b.disabled);
  others.forEach((b) => (b.disabled = true));
  setStatus(statusId, working, "working");
  try {
    const result = await action();
    return result;
  } catch (error) {
    setStatus(statusId, error.message, "error");
    return null;
  } finally {
    others.forEach((b, index) => (b.disabled = wasDisabled[index]));
  }
}

function badge(text) {
  const node = el("span", "badge", text);
  node.dataset.badge = text;
  return node;
}

/* ---------- screen navigation ---------- */

function showScreen(name) {
  if (!SCREENS.includes(name)) return;

  document.querySelectorAll(".screen").forEach((section) => {
    section.classList.toggle("is-active", section.id === `screen-${name}`);
  });
  document.querySelectorAll(".navbtn").forEach((button) => {
    if (button.dataset.screen === name) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });

  window.location.hash = name;
  document.getElementById("main").scrollIntoView({ block: "start" });

  if (name === "seed") loadWorkspace();
  if (name === "run") loadMessages();
  if (name === "audit") loadAudit();
}

function currentScreenIndex() {
  const active = document.querySelector(".screen.is-active");
  return active ? SCREENS.indexOf(active.id.replace("screen-", "")) : 0;
}

function step(delta) {
  const next = currentScreenIndex() + delta;
  if (next >= 0 && next < SCREENS.length) showScreen(SCREENS[next]);
}

/* ---------- backend health ---------- */

async function checkHealth() {
  const indicator = document.getElementById("health-indicator");
  const label = document.getElementById("health-text");
  try {
    const data = await api("/api/health");
    indicator.dataset.state = data.status === "ok" ? "ok" : "down";
    label.textContent =
      data.status === "ok" ? "Backend connected" : `Backend: ${data.status}`;
  } catch (error) {
    indicator.dataset.state = "down";
    label.textContent = `Backend unreachable: ${error.message}`;
  }
}

/* ---------- screen 2: seed ---------- */

async function loadWorkspace() {
  try {
    const data = await api("/api/workspace");
    const counts = document.getElementById("workspace-counts");
    clear(counts);

    Object.entries(data.record_counts || {}).forEach(([location, total]) => {
      const row = el("div", "count");
      row.appendChild(el("span", "count-label", location));
      row.appendChild(el("strong", "count-value", `${total} records`));
      counts.appendChild(row);
    });
    Object.entries(data.file_counts || {}).forEach(([folder, total]) => {
      const row = el("div", "count");
      row.appendChild(el("span", "count-label", `workspace/${folder}/`));
      row.appendChild(el("strong", "count-value", `${total} files`));
      counts.appendChild(row);
    });

    setStatus(
      "seed-status",
      data.seeded
        ? `${data.canary_count} decoys are planted.`
        : "No decoys are planted yet.",
      data.seeded ? "ok" : ""
    );
  } catch (error) {
    setStatus("seed-status", error.message, "error");
  }
  loadCanaries();
}

async function loadCanaries() {
  const body = document.querySelector("#canary-table tbody");
  clear(body);
  let data;
  try {
    data = await api("/api/canaries", { admin: true });
  } catch (error) {
    const row = el("tr");
    const cell = el("td", "empty", error.message);
    cell.colSpan = 4;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }

  if (!data.count) {
    const row = el("tr");
    const cell = el("td", "empty", "No decoys are planted.");
    cell.colSpan = 4;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }

  data.canaries.forEach((canary) => {
    const row = el("tr", "is-decoy");
    row.appendChild(el("td", null, canary.canary_type));
    row.appendChild(el("td", "mono", canary.location));
    row.appendChild(el("td", null, canary.record_ref || ""));
    row.appendChild(el("td", "mono", (canary.strong_values || []).join("  ")));
    body.appendChild(row);
  });
}

/* ---------- screen 3: the run ---------- */

function describeOption(item) {
  if (item.kind === "inbox") {
    return `Inbox — ${item.subject}  (from ${item.from})`;
  }
  const tag = item.scenario_type === "normal" ? "Normal" : "Attack";
  return `${item.id} ${tag}/${item.category} — ${item.subject}`;
}

/** The agent names come from the backend, never from this file. */
async function loadAgents() {
  const select = document.getElementById("agent-select");
  if (select.options.length) return;
  try {
    const data = await api("/api/agents");
    data.selectable.forEach((agent) => {
      const option = document.createElement("option");
      option.value = agent.agent_mode;
      option.textContent = agent.agent_label;
      select.appendChild(option);
    });
  } catch (error) {
    setStatus("run-status", `Could not load the agent list: ${error.message}`, "error");
  }
}

async function loadMessages() {
  await loadAgents();
  if (state.messages.length) return;
  const select = document.getElementById("message-select");
  clear(select);

  const groups = [];
  try {
    const inbox = await api("/api/inbox");
    groups.push([
      "Inbox",
      inbox.items.map((item) => Object.assign({ kind: "inbox" }, item)),
    ]);
  } catch (error) {
    setStatus("run-status", `Could not load the inbox: ${error.message}`, "error");
  }

  try {
    const scenarios = await api("/api/scenarios");
    if (scenarios.probes && scenarios.probes.length) {
      groups.push([
        "Harder injection probes",
        scenarios.probes.map((item) => Object.assign({ kind: "scenario" }, item)),
      ]);
    }
    groups.push([
      "Scenario suite",
      scenarios.suite.map((item) => Object.assign({ kind: "scenario" }, item)),
    ]);
  } catch (error) {
    setStatus("run-status", `Could not load scenarios: ${error.message}`, "error");
  }

  state.messages = [];
  groups.forEach(([label, items]) => {
    if (!items.length) return;
    const group = document.createElement("optgroup");
    group.label = label;
    items.forEach((item) => {
      const option = document.createElement("option");
      option.value = `${item.kind}:${item.id}`;
      option.textContent = describeOption(item);
      group.appendChild(option);
      state.messages.push(item);
    });
    select.appendChild(group);
  });

  // The two live demo scenes are the harder injections, so start there.
  const preferred = state.messages.find((item) => item.id === "H2");
  if (preferred) select.value = `scenario:${preferred.id}`;
  await selectMessage();
}

/** Hidden instructions, revealed or not. Presentation only. */
function visibleText(raw) {
  if (state.showHidden) return raw;
  let shown = raw.replace(/<!--[\s\S]*?-->/g, "[hidden comment]");
  shown = shown.replace(
    /<span[^>]*(position:absolute|display:none|font-size:0)[^>]*>[\s\S]*?<\/span>/gi,
    "[hidden text]"
  );
  return shown;
}

async function selectMessage() {
  const value = document.getElementById("message-select").value;
  if (!value) return;
  const [kind, id] = value.split(":");

  let item = state.messages.find((m) => m.kind === kind && m.id === id);
  if (kind === "scenario") {
    try {
      const full = await api(`/api/scenarios/${encodeURIComponent(id)}`);
      item = Object.assign({ kind: "scenario" }, full);
    } catch (error) {
      setStatus("run-status", error.message, "error");
      return;
    }
  }
  state.selected = item;

  const meta = [`From: ${item.from}`, `Subject: ${item.subject}`];
  if (item.expected_protect_outcome) {
    meta.push(`Expected under protect: ${item.expected_protect_outcome}`);
  }
  document.getElementById("message-meta").textContent = meta.join("   ·   ");
  document.getElementById("message-body").textContent = visibleText(item.body || "");
}

function renderTrace(activity) {
  const body = document.querySelector("#trace-table tbody");
  clear(body);
  if (!activity || !activity.length) {
    const row = el("tr");
    const cell = el("td", "empty", "The agent requested no tools.");
    cell.colSpan = 5;
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }
  activity.forEach((entry) => {
    const row = el("tr");
    row.appendChild(el("td", "mono", entry.step));
    row.appendChild(el("td", null, entry.tool || ""));
    row.appendChild(el("td", "mono", entry.resource || ""));
    const decision = el("td");
    decision.appendChild(badge(entry.badge || entry.decision));
    if (entry.would_be) {
      decision.appendChild(el("span", "would-be", `would be ${entry.would_be}`));
    }
    row.appendChild(decision);
    row.appendChild(el("td", "mono", entry.rule || ""));
    body.appendChild(row);
  });
}

function renderSessionState(outcome) {
  const panel = document.getElementById("session-state");
  clear(panel);
  if (!outcome) return;

  [
    ["Agent", outcome.agent_label],
    ["Protection", outcome.protection_mode],
    ["Status", outcome.status],
    ["Ended", outcome.stopped_because],
    ["Tainted", outcome.tainted ? "yes" : "no"],
  ].forEach(([label, value]) => {
    const item = el("div", "state-item");
    item.appendChild(el("span", "state-label", label));
    item.appendChild(el("strong", null, value === undefined ? "" : String(value)));
    panel.appendChild(item);
  });

  if (outcome.model_id) {
    const item = el("div", "state-item");
    item.appendChild(el("span", "state-label", "Model / SDK"));
    item.appendChild(
      el("strong", "mono", `${outcome.model_id} / ${outcome.sdk_version}`)
    );
    panel.appendChild(item);
  }
  if (outcome.detail) panel.appendChild(el("p", "state-detail", outcome.detail));

  const actions = document.getElementById("session-actions");
  clear(actions);
  (outcome.admin_options || []).forEach((option) => {
    if (option === "stop") {
      const button = el("button", "btn", "Stop");
      button.addEventListener("click", () => stopSession(outcome.session_id));
      actions.appendChild(button);
    }
    if (option === "continue") {
      const button = el("button", "btn btn-primary", "Continue");
      button.addEventListener("click", () => continueSession(outcome.session_id));
      actions.appendChild(button);
    }
  });
}

async function runAgent() {
  if (!state.selected) return;
  const protection = document.getElementById("protection-select").value;
  const agent = document.getElementById("agent-select").value;
  const item = state.selected;

  if (agent === "worst_case" && item.kind === "inbox") {
    setStatus(
      "run-status",
      "This agent replays a scenario's intended tool calls, so pick a scenario rather than an inbox item.",
      "error"
    );
    return;
  }

  const outcome = await withButton(
    document.getElementById("run-button"),
    "run-status",
    `Running the selected agent in ${protection} mode…`,
    async () => {
      if (agent === "worst_case") {
        return api("/api/run/scripted", {
          method: "POST",
          body: { scenario_id: item.id, protection_mode: protection },
        });
      }
      const body = { protection_mode: protection };
      if (item.kind === "inbox") body.inbox_id = item.id;
      else body.scenario_id = item.id;
      return api("/api/run/claude", { method: "POST", body });
    }
  );
  if (!outcome) return;

  state.session = outcome;
  state.runId = outcome.run_id;
  renderTrace(outcome.activity);
  renderSessionState(outcome);
  setStatus("run-status", `Run finished: ${outcome.stopped_because}.`, "ok");
  await Promise.all([loadAlerts(), loadOutbox()]);
}

async function stopSession(sessionId) {
  const result = await withButton(null, "run-status", "Stopping the session…", () =>
    api(`/api/sessions/${encodeURIComponent(sessionId)}/stop`, {
      method: "POST",
      admin: true,
    })
  );
  if (!result) return;
  state.session = Object.assign({}, state.session, {
    status: result.status,
    admin_options: [],
    stopped_because: "stopped by administrator",
  });
  renderSessionState(state.session);
  setStatus("run-status", "The session was terminated.", "ok");
}

async function continueSession(sessionId) {
  const resumed = await withButton(null, "run-status", "Continuing…", () =>
    api(`/api/sessions/${encodeURIComponent(sessionId)}/continue`, {
      method: "POST",
      admin: true,
    })
  );
  if (!resumed) return;

  setStatus("run-status", resumed.agent_message, "ok");

  // For Claude the conversation can carry on from the refusal.
  if (state.session && state.session.agent_mode === "claude") {
    const outcome = await withButton(
      null,
      "run-status",
      "The agent is continuing without the withheld content…",
      () =>
        api(`/api/run/claude/${encodeURIComponent(sessionId)}/resume`, {
          method: "POST",
        })
    );
    if (outcome) {
      state.session = outcome;
      renderTrace((state.session.activity || []).length ? state.session.activity : []);
      renderSessionState(outcome);
      setStatus(
        "run-status",
        `Continued without releasing the content. Run ended: ${outcome.stopped_because}.`,
        "ok"
      );
    }
  } else {
    renderSessionState(
      Object.assign({}, state.session, { status: resumed.status, admin_options: ["stop"] })
    );
  }
  await Promise.all([loadAlerts(), loadOutbox()]);
}

async function loadAlerts() {
  const list = document.getElementById("alert-list");
  clear(list);
  try {
    const query = state.runId ? `?run_id=${encodeURIComponent(state.runId)}` : "";
    const data = await api(`/api/alerts${query}`);
    if (!data.count) {
      list.appendChild(el("p", "phone-empty", "No alerts."));
      return;
    }
    data.alerts.forEach((alert) => {
      const card = el("div", "alert");
      card.dataset.severity = alert.severity;
      card.appendChild(el("p", "alert-title", alert.title));
      card.appendChild(el("p", "alert-message", alert.message));
      card.appendChild(el("p", "alert-time", alert.created_at));
      if (alert.status === "open") {
        const resolve = el("button", "btn btn-small", "Mark resolved");
        resolve.addEventListener("click", () => resolveAlert(alert.id));
        card.appendChild(resolve);
      } else {
        card.appendChild(el("p", "alert-time", "resolved"));
      }
      list.appendChild(card);
    });
  } catch (error) {
    list.appendChild(el("p", "phone-empty", error.message));
  }
}

async function loadOutbox() {
  const body = document.querySelector("#outbox-table tbody");
  clear(body);
  try {
    const query = state.runId ? `&run_id=${encodeURIComponent(state.runId)}` : "";
    const data = await api(`/api/emails?external_only=true${query}`);
    if (!data.count) {
      const row = el("tr");
      const cell = el("td", "empty", "Nothing was addressed outside the company.");
      cell.colSpan = 4;
      row.appendChild(cell);
      body.appendChild(row);
      return;
    }
    data.emails.forEach((email) => {
      const row = el("tr");
      row.appendChild(el("td", "mono", email.recipient));
      row.appendChild(el("td", null, email.subject));
      const status = el("td");
      status.appendChild(badge(email.delivery_status));
      row.appendChild(status);
      row.appendChild(el("td", "mono", email.rule || ""));
      body.appendChild(row);
    });
  } catch (error) {
    const row = el("tr");
    const cell = el("td", "empty", error.message);
    cell.colSpan = 4;
    row.appendChild(cell);
    body.appendChild(row);
  }
}

async function resolveAlert(alertId) {
  const result = await withButton(null, "run-status", "Resolving…", () =>
    api(`/api/alerts/${alertId}/resolve`, { method: "POST", admin: true })
  );
  if (result) await loadAlerts();
}

/* ---------- screen 4: audit and admin ---------- */

async function loadAudit() {
  await loadRuns();
  await Promise.all([loadAuditTable(), loadHeld(), loadSessionPicker()]);
}

async function loadRuns() {
  const select = document.getElementById("run-select");
  const chosen = select.value;
  try {
    const data = await api("/api/runs");
    clear(select);
    data.runs.forEach((run) => {
      const option = document.createElement("option");
      option.value = run.run_id;
      const when = run.started_at.replace("T", " ").slice(0, 19);
      option.textContent = `${when}  ·  ${run.session_count} sessions  ·  ${run.event_count} entries${
        run.ended_at ? "" : "  ·  current"
      }`;
      select.appendChild(option);
    });
    select.value = chosen || data.current_run_id || "";
    state.runId = select.value || state.runId;
  } catch (error) {
    setStatus("audit-status", error.message, "error");
  }
}

function auditRunId() {
  return document.getElementById("run-select").value || "";
}

async function loadAuditTable(invalidId) {
  const body = document.querySelector("#audit-table tbody");
  clear(body);
  try {
    const query = auditRunId() ? `?run_id=${encodeURIComponent(auditRunId())}` : "";
    const data = await api(`/api/audit${query}`, { admin: true });
    if (!data.count) {
      const row = el("tr");
      const cell = el("td", "empty", "No entries for this run yet.");
      cell.colSpan = 7;
      row.appendChild(cell);
      body.appendChild(row);
      return;
    }
    data.events.forEach((event) => {
      const row = el("tr");
      if (invalidId && event.id === invalidId) row.className = "is-invalid";
      row.appendChild(el("td", "mono", event.id));
      row.appendChild(el("td", null, event.event_type));
      row.appendChild(el("td", null, event.tool || ""));
      row.appendChild(el("td", "mono", event.resource || ""));
      row.appendChild(el("td", null, event.decision || ""));
      row.appendChild(el("td", "mono", event.rule || ""));
      row.appendChild(el("td", "mono", (event.created_at || "").slice(11, 23)));
      body.appendChild(row);
    });
  } catch (error) {
    const row = el("tr");
    const cell = el("td", "empty", error.message);
    cell.colSpan = 7;
    row.appendChild(cell);
    body.appendChild(row);
  }
}

async function verifyChain() {
  const query = auditRunId() ? `?run_id=${encodeURIComponent(auditRunId())}` : "";
  const result = await withButton(null, "audit-status", "Verifying…", () =>
    api(`/api/audit/verify${query}`, { method: "POST" })
  );
  if (!result) return;
  if (result.valid) {
    setStatus("audit-status", `Chain valid — ${result.event_count} entries.`, "ok");
    await loadAuditTable();
  } else {
    setStatus(
      "audit-status",
      `Chain broken at entry ${result.first_invalid_event_id}. ${result.reason}`,
      "error"
    );
    await loadAuditTable(result.first_invalid_event_id);
  }
}

async function tamperChain() {
  const query = auditRunId() ? `?run_id=${encodeURIComponent(auditRunId())}` : "";
  const result = await withButton(null, "audit-status", "Editing the oldest entry…", () =>
    api(`/api/audit/tamper${query}`, { method: "POST", admin: true })
  );
  if (!result) return;
  setStatus(
    "audit-status",
    `Entry ${result.tampered_event_id} was edited on purpose. Verify the chain to see it detected.`,
    "warning"
  );
  await loadAuditTable();
}

async function loadHeld() {
  const list = document.getElementById("held-list");
  clear(list);
  try {
    const query = auditRunId() ? `?run_id=${encodeURIComponent(auditRunId())}` : "";
    const data = await api(`/api/emails/held${query}`, { admin: true });
    if (!data.count) {
      list.appendChild(el("p", "empty", "Nothing is waiting for review."));
      return;
    }
    data.emails.forEach((email) => {
      const card = el("div", "held");
      const head = el("div", "held-head");
      head.appendChild(el("strong", null, email.recipient));
      head.appendChild(badge(email.delivery_status));
      head.appendChild(el("span", "mono held-rule", email.rule || ""));
      card.appendChild(head);
      card.appendChild(el("p", "held-subject", email.subject));
      card.appendChild(el("pre", "held-body", email.body));

      const actions = el("div", "actions");
      // Whether a message may be approved is the backend's judgement; this
      // only reflects the flag it sent, and the backend refuses regardless.
      if (email.approvable) {
        const approve = el("button", "btn btn-primary", "Approve");
        approve.addEventListener("click", () => decideEmail(email.id, "approve"));
        actions.appendChild(approve);
      } else {
        actions.appendChild(
          el("span", "no-approve", "Blocked outright — it cannot be approved.")
        );
      }
      const deny = el("button", "btn", "Deny");
      deny.addEventListener("click", () => decideEmail(email.id, "deny"));
      actions.appendChild(deny);
      card.appendChild(actions);
      list.appendChild(card);
    });
  } catch (error) {
    list.appendChild(el("p", "empty", error.message));
  }
}

async function decideEmail(emailId, action) {
  const result = await withButton(null, "audit-status", `Sending the ${action}…`, () =>
    api(`/api/emails/${emailId}/${action}`, { method: "POST", admin: true })
  );
  if (!result) return;
  setStatus(
    "audit-status",
    `Message ${emailId}: ${result.delivery_status || action}.`,
    "ok"
  );
  await Promise.all([loadHeld(), loadAuditTable()]);
}

async function simulateBeacon() {
  let canaries;
  try {
    canaries = await api("/api/canaries", { admin: true });
  } catch (error) {
    setStatus("audit-status", error.message, "error");
    return;
  }
  if (!canaries.count) {
    setStatus(
      "audit-status",
      "There are no decoys planted, so none can be contacted. Seed the workspace first.",
      "error"
    );
    return;
  }
  const canary = canaries.canaries[0];
  const result = await withButton(null, "audit-status", "Simulating a contact…", () =>
    api(`/api/beacon/${encodeURIComponent(canary.id)}`, {
      method: "POST",
      admin: true,
    })
  );
  if (!result) return;
  setStatus(
    "audit-status",
    `Simulated: a decoy in ${result.location} was contacted, so that file has leaked. See the alert panel on screen 3.`,
    "warning"
  );
  await loadAuditTable();
}

async function resetDemo() {
  const confirmed = window.confirm(
    "Reset the demo?\n\nThis starts a new demo run: the workspace is " +
      "restored, the decoys are removed and a fresh audit chain begins.\n\n" +
      "Earlier runs are kept and stay listed. Nothing is deleted."
  );
  if (!confirmed) return;

  const result = await withButton(null, "audit-status", "Resetting…", () =>
    api("/api/reset", { method: "POST", admin: true })
  );
  if (!result) return;

  state.runId = result.run_id;
  state.session = null;
  setStatus(
    "audit-status",
    `New run started. ${result.sessions_terminated} session(s) terminated, ` +
      `${result.held_emails_denied} held message(s) denied, ` +
      `${result.canaries_removed} decoys removed. The previous run is kept.`,
    "ok"
  );
  renderTrace([]);
  renderSessionState(null);
  await loadAudit();
}

async function loadSessionPicker() {
  const select = document.getElementById("hr-session-select");
  clear(select);
  try {
    const data = await api("/api/runs");
    const runId = auditRunId() || data.current_run_id;
    const audit = await api(
      `/api/audit?run_id=${encodeURIComponent(runId)}`,
      { admin: true }
    );
    const seen = [];
    audit.events.forEach((event) => {
      if (event.session_id && !seen.includes(event.session_id)) seen.push(event.session_id);
    });
    if (!seen.length) {
      const option = document.createElement("option");
      option.textContent = "No sessions in this run";
      option.value = "";
      select.appendChild(option);
      return;
    }
    for (const sessionId of seen) {
      const option = document.createElement("option");
      option.value = sessionId;
      try {
        const info = await api(`/api/sessions/${encodeURIComponent(sessionId)}`);
        option.textContent = `${info.agent_label} · ${info.protection_mode} · ${info.status} · HR ${
          info.hr_access ? "on" : "off"
        }`;
      } catch (error) {
        option.textContent = sessionId;
      }
      select.appendChild(option);
    }
  } catch (error) {
    setStatus("hr-status", error.message, "error");
  }
}

async function setHrAccess(enabled) {
  const sessionId = document.getElementById("hr-session-select").value;
  if (!sessionId) {
    setStatus("hr-status", "Pick a session first.", "error");
    return;
  }
  const result = await withButton(null, "hr-status", "Updating HR access…", () =>
    api(`/api/sessions/${encodeURIComponent(sessionId)}/hr-access`, {
      method: "POST",
      admin: true,
      body: { enabled },
    })
  );
  if (!result) return;
  setStatus("hr-status", `HR access is now ${result.hr_access ? "on" : "off"}.`, "ok");
  await loadSessionPicker();
}

/* ---------- screen 5: scoreboard ---------- */

function metricRow(label, value) {
  const row = el("div", "metric");
  row.appendChild(el("span", "metric-label", label));
  row.appendChild(el("strong", "metric-value", value === null || value === undefined ? "—" : String(value)));
  return row;
}

function renderScoreboard(board) {
  const card = el("section", "panel");
  const head = el("div", "panel-head");
  head.appendChild(
    el("h2", "panel-title", `${board.agent_label} · ${board.protection_mode}`)
  );
  head.appendChild(el("span", "meta", `${board.runs} run(s)`));
  card.appendChild(head);

  const grid = el("div", "metrics");
  grid.appendChild(metricRow("Unauthorised disclosures", board.unauthorised_disclosures));
  grid.appendChild(metricRow("Canary exposures", board.canary_exposures));
  grid.appendChild(metricRow("Forbidden accesses", board.forbidden_accesses));
  grid.appendChild(
    metricRow("Bulk stopped", `${board.bulk_stopped} / ${board.bulk_total}`)
  );
  grid.appendChild(
    metricRow("Targeted stopped", `${board.targeted_stopped} / ${board.targeted_total}`)
  );
  grid.appendChild(metricRow("Attacks leaked", board.attacks_leaked));
  grid.appendChild(metricRow("Stopped by gateway", board.attacks_stopped_by_gateway));
  grid.appendChild(
    metricRow("Not attempted by model", board.attacks_not_attempted_by_model)
  );
  grid.appendChild(metricRow("Explicit model refusals", board.model_refusals));
  grid.appendChild(
    metricRow("Normal tasks completed", `${board.normal_completed} / ${board.normal_total}`)
  );
  grid.appendChild(metricRow("False holds", board.false_holds));
  grid.appendChild(metricRow("Task failures", board.task_failures));
  grid.appendChild(
    metricRow("Avg gateway decision", board.average_gateway_decision_ms === null ? null : `${board.average_gateway_decision_ms} ms`)
  );
  grid.appendChild(
    metricRow("Avg alert latency", board.average_alert_latency_ms === null ? null : `${board.average_alert_latency_ms} ms`)
  );
  grid.appendChild(metricRow("Model", board.model_id));
  grid.appendChild(metricRow("SDK", board.sdk_version));
  card.appendChild(grid);

  ["caught_where_bulk", "caught_where_targeted"].forEach((key) => {
    const entries = Object.entries(board[key] || {});
    if (!entries.length) return;
    const line = el("p", "meta");
    line.textContent = `${key === "caught_where_bulk" ? "Bulk" : "Targeted"} caught at: ${entries
      .map(([where, count]) => `${where} ${count}`)
      .join(", ")}`;
    card.appendChild(line);
  });

  const failures = board.failed_or_unexpected || [];
  const title = el("h3", "sub-title", `Failed or unexpected (${failures.length})`);
  card.appendChild(title);
  if (!failures.length) {
    card.appendChild(el("p", "empty", "None."));
  } else {
    const list = el("ul", "failures");
    failures.forEach((item) => {
      const entry = el("li");
      entry.textContent = `${item.scenario_id} (${item.category}, repeat ${item.repeat_index}) — ${item.reason}`;
      list.appendChild(entry);
    });
    card.appendChild(list);
  }
  return card;
}

async function loadScores() {
  const holder = document.getElementById("scoreboards");
  const data = await withButton(null, "score-status", "Loading results…", () =>
    api("/api/suite/latest")
  );
  if (!data) return;
  clear(holder);
  if (!data.has_results) {
    setStatus("score-status", "No suite has been run yet.", "");
    holder.appendChild(
      el("p", "empty", "Run the worst-case suite, or run the Claude suite from the command line.")
    );
    return;
  }
  data.all.forEach((board) => holder.appendChild(renderScoreboard(board)));
  setStatus("score-status", `${data.all.length} stored result set(s).`, "ok");
}

async function runWorstCaseSuite() {
  const data = await withButton(
    null,
    "score-status",
    "Running the worst-case suite across all three modes. This takes a moment…",
    () => api("/api/suite/run", { method: "POST", admin: true, body: {} })
  );
  if (!data) return;
  setStatus("score-status", `${data.count} mode(s) run.`, "ok");
  await loadScores();
}

/* ---------- wiring ---------- */

function init() {
  document.querySelectorAll(".navbtn").forEach((button) => {
    button.addEventListener("click", () => showScreen(button.dataset.screen));
  });
  document.querySelectorAll("[data-goto]").forEach((button) => {
    button.addEventListener("click", () => showScreen(button.dataset.goto));
  });

  document.addEventListener("keydown", (event) => {
    const typing =
      event.target instanceof HTMLInputElement ||
      event.target instanceof HTMLTextAreaElement ||
      event.target instanceof HTMLSelectElement;
    if (typing || event.metaKey || event.ctrlKey || event.altKey) return;
    if (event.key === "ArrowRight") step(1);
    else if (event.key === "ArrowLeft") step(-1);
  });

  window.addEventListener("hashchange", () =>
    showScreen(window.location.hash.replace("#", ""))
  );

  document.getElementById("seed-button").addEventListener("click", async () => {
    const result = await withButton(null, "seed-status", "Planting the decoys…", () =>
      api("/api/workspace/seed", { method: "POST", admin: true })
    );
    if (result) {
      setStatus(
        "seed-status",
        `${result.planted} decoys planted; ${result.canary_count} active.`,
        "ok"
      );
      await loadWorkspace();
    }
  });
  document.getElementById("unseed-button").addEventListener("click", async () => {
    const result = await withButton(null, "seed-status", "Removing the decoys…", () =>
      api("/api/workspace/unseed", { method: "POST", admin: true })
    );
    if (result) {
      setStatus("seed-status", `${result.removed} decoys removed.`, "ok");
      await loadWorkspace();
    }
  });
  document.getElementById("refresh-workspace").addEventListener("click", loadWorkspace);

  document.getElementById("message-select").addEventListener("change", selectMessage);
  document.getElementById("run-button").addEventListener("click", runAgent);
  document.getElementById("hidden-toggle").addEventListener("click", (event) => {
    state.showHidden = !state.showHidden;
    event.currentTarget.setAttribute("aria-pressed", String(state.showHidden));
    event.currentTarget.textContent = state.showHidden
      ? "Hide hidden text"
      : "Show hidden text";
    if (state.selected) {
      document.getElementById("message-body").textContent = visibleText(
        state.selected.body || ""
      );
    }
  });

  document.getElementById("run-select").addEventListener("change", () => {
    state.runId = auditRunId();
    loadAuditTable();
    loadHeld();
    loadSessionPicker();
  });
  document.getElementById("verify-button").addEventListener("click", verifyChain);
  document.getElementById("tamper-button").addEventListener("click", tamperChain);
  document.getElementById("beacon-button").addEventListener("click", simulateBeacon);
  document.getElementById("reset-button").addEventListener("click", resetDemo);
  document.getElementById("refresh-audit").addEventListener("click", () => loadAuditTable());
  document.getElementById("refresh-held").addEventListener("click", loadHeld);
  document.getElementById("hr-grant").addEventListener("click", () => setHrAccess(true));
  document.getElementById("hr-remove").addEventListener("click", () => setHrAccess(false));

  document.getElementById("load-scores").addEventListener("click", loadScores);
  document.getElementById("run-suite").addEventListener("click", runWorstCaseSuite);

  const initial = window.location.hash.replace("#", "");
  if (SCREENS.includes(initial)) showScreen(initial);
  checkHealth();
}

document.addEventListener("DOMContentLoaded", init);
