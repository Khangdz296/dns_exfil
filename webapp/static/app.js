const state = {
  currentJob: null,
  agents: [],
  socket: null,
};

const titles = {
  analyze: "Analyze DNS Traffic",
  pipeline: "Agent Pipeline Monitor",
  report: "Security Report",
};

const qs = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? "")
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#039;");

document.querySelectorAll(".nav-item").forEach((button) => {
  button.addEventListener("click", () => selectView(button.dataset.view));
});

function selectView(name) {
  document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === name));
  document.querySelectorAll(".view").forEach((view) => view.classList.toggle("active", view.id === `${name}-view`));
  qs("#page-title").textContent = titles[name];
}

async function request(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed (${response.status})`);
  }
  return response.json();
}

async function loadAgents() {
  state.agents = await request("/api/agents");
  renderAgents({});
}

document.querySelectorAll(".source-tab").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".source-tab").forEach((tab) => {
      tab.classList.toggle("active", tab === button);
    });
    document.querySelectorAll(".source-panel").forEach((panel) => {
      panel.classList.toggle("active", panel.id === `${button.dataset.source}-source`);
    });
    if (button.dataset.source === "live") loadInterfaces();
  });
});

async function loadInterfaces() {
  const select = qs("#interface-select");
  qs("#capture-error").textContent = "";
  try {
    const result = await request("/api/interfaces");
    if (!result.available) {
      select.innerHTML = '<option value="">Capture unavailable</option>';
      select.disabled = true;
      qs("#capture-start").disabled = true;
      qs("#capture-error").textContent = result.detail;
      return;
    }
    select.disabled = false;
    const captureActive = state.currentJob?.mode === "live"
      && ["queued", "capturing", "stopping"].includes(state.currentJob.status);
    qs("#capture-start").disabled = captureActive;
    select.innerHTML = '<option value="">Default interface</option>' + result.interfaces.map((item) =>
      `<option value="${escapeHtml(item.id)}">${escapeHtml(item.label)}</option>`
    ).join("");
  } catch (error) {
    qs("#capture-error").textContent = error.message;
  }
}

function renderAgents(agentStates) {
  [1, 2, 3].forEach((stage) => {
    const container = qs(`#stage-${stage}`);
    container.innerHTML = state.agents.filter((agent) => agent.stage === stage).map((agent) => {
      const status = agentStates[agent.name] || "pending";
      return `<article class="agent-card ${escapeHtml(status)}">
        <span class="agent-state">${escapeHtml(status)}</span>
        <strong>${escapeHtml(agent.name)}</strong>
        <small>${escapeHtml(agent.description || "Pi agent configuration loaded")}</small>
      </article>`;
    }).join("");
  });
}

const fileInput = qs("#file-input");
const dropZone = qs("#drop-zone");
fileInput.addEventListener("change", () => {
  qs("#file-label").textContent = fileInput.files[0]?.name || "Drop a PCAP or CSV file here";
});
["dragenter", "dragover"].forEach((eventName) => dropZone.addEventListener(eventName, (event) => {
  event.preventDefault();
  dropZone.classList.add("dragging");
}));
["dragleave", "drop"].forEach((eventName) => dropZone.addEventListener(eventName, (event) => {
  event.preventDefault();
  dropZone.classList.remove("dragging");
}));
dropZone.addEventListener("drop", (event) => {
  if (event.dataTransfer.files.length) {
    fileInput.files = event.dataTransfer.files;
    qs("#file-label").textContent = fileInput.files[0].name;
  }
});

qs("#upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = fileInput.files[0];
  if (!file) return;
  const button = event.currentTarget.querySelector("button");
  button.disabled = true;
  button.textContent = "Uploading evidence...";
  qs("#form-error").textContent = "";
  try {
    const form = new FormData();
    form.append("file", file);
    const job = await request("/api/jobs", { method: "POST", body: form });
    useJob(job);
    selectView("pipeline");
    connectJob(job.id);
    await loadHistory();
  } catch (error) {
    qs("#form-error").textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = "Run multi-agent analysis";
  }
});

qs("#capture-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = qs("#capture-start");
  const timeout = Number(qs("#capture-timeout").value);
  const maxPackets = Number(qs("#capture-packets").value);
  if (!Number.isInteger(timeout) || timeout < 5 || timeout > 300) {
    qs("#capture-error").textContent = "Duration must be a whole number from 5 to 300 seconds.";
    return;
  }
  if (!Number.isInteger(maxPackets) || maxPackets < 1 || maxPackets > 10000) {
    qs("#capture-error").textContent = "Packet limit must be from 1 to 10000.";
    return;
  }
  button.disabled = true;
  qs("#capture-error").textContent = "";
  try {
    const job = await request("/api/captures", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        interface: qs("#interface-select").value || null,
        timeout,
        max_packets: maxPackets,
      }),
    });
    useJob(job);
    selectView("pipeline");
    connectJob(job.id);
    await loadHistory();
  } catch (error) {
    qs("#capture-error").textContent = error.message;
    button.disabled = false;
  }
});

async function stopCurrentCapture() {
  if (!state.currentJob || state.currentJob.mode !== "live") return;
  qs("#capture-stop").disabled = true;
  qs("#header-capture-stop").disabled = true;
  try {
    const job = await request(`/api/captures/${state.currentJob.id}`, { method: "DELETE" });
    useJob(job);
  } catch (error) {
    qs("#capture-error").textContent = error.message;
    qs("#capture-stop").disabled = false;
    qs("#header-capture-stop").disabled = false;
  }
}

qs("#capture-stop").addEventListener("click", stopCurrentCapture);
qs("#header-capture-stop").addEventListener("click", stopCurrentCapture);

function useJob(job) {
  state.currentJob = job;
  renderAgents(job.agents || {});
  const badge = qs("#job-badge");
  badge.classList.remove("hidden");
  badge.textContent = `${job.filename} | ${job.status}`;

  const captureActive = job.mode === "live"
    && ["queued", "capturing", "stopping"].includes(job.status);
  qs("#capture-start").disabled = captureActive || qs("#interface-select").disabled;
  qs("#capture-stop").classList.toggle("hidden", !captureActive);
  qs("#capture-stop").disabled = job.status === "stopping";
  qs("#header-capture-stop").classList.toggle("hidden", !captureActive);
  qs("#header-capture-stop").disabled = job.status === "stopping";
  const captureReady = job.mode === "live" && job.status === "completed";
  qs("#capture-download").classList.toggle("hidden", !captureReady);
  qs("#capture-download").href = captureReady ? `/api/jobs/${job.id}/capture` : "#";

  const summary = job.summary || {};
  qs("#metric-total").textContent = summary.total_queries ?? 0;
  qs("#metric-suspected").textContent = summary.suspected_count ?? 0;
  qs("#metric-risk").textContent = Number(summary.highest_risk_score ?? 0).toFixed(2);
  qs("#report-total").textContent = summary.total_queries ?? 0;
  qs("#report-suspected").textContent = summary.suspected_count ?? 0;
  qs("#report-risk").textContent = Number(summary.highest_risk_score ?? 0).toFixed(2);

  const completed = Object.values(job.agents || {}).filter((value) => value === "completed").length;
  qs("#metric-agents").textContent = `${completed} / 7`;
  qs("#log-output").textContent = (job.logs || []).join("\n") || "Pipeline job queued...";
  qs("#log-output").scrollTop = qs("#log-output").scrollHeight;
}

function connectJob(jobId) {
  state.socket?.close();
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  state.socket = new WebSocket(`${protocol}://${location.host}/ws/jobs/${jobId}`);
  state.socket.onmessage = async (event) => {
    const job = JSON.parse(event.data);
    if (job.error && !job.id) return;
    useJob(job);
    if (["completed", "failed"].includes(job.status)) {
      await loadHistory();
      if (job.status === "completed") await loadResults(job.id);
    }
  };
}

async function loadResults(jobId) {
  try {
    const [scores, report] = await Promise.all([
      request(`/api/jobs/${jobId}/scores?limit=100`),
      request(`/api/jobs/${jobId}/report`),
    ]);
    qs("#scores-body").innerHTML = scores.items.map((item) => `<tr>
      <td>${escapeHtml(item.domain)}</td>
      <td>${Number(item.entropy_score || 0).toFixed(2)}</td>
      <td>${Number(item.dga_score || 0).toFixed(2)}</td>
      <td>${Number(item.embed_score || 0).toFixed(2)}</td>
      <td><strong>${Number(item.combined_score || 0).toFixed(2)}</strong></td>
      <td><span class="verdict ${escapeHtml(item.verdict)}">${escapeHtml(item.verdict)}</span></td>
    </tr>`).join("") || '<tr><td colspan="6" class="empty">No DNS queries were scored.</td></tr>';
    qs("#report-output").textContent = report.markdown;
  } catch (error) {
    qs("#report-output").textContent = error.message;
  }
}

async function loadHistory() {
  const jobs = await request("/api/jobs");
  const container = qs("#history-list");
  if (!jobs.length) {
    container.innerHTML = '<p class="empty">No analysis jobs in this server session.</p>';
    return;
  }
  container.innerHTML = jobs.map((job) => `<div class="history-row" data-job="${job.id}">
    <strong>${escapeHtml(job.filename)}</strong>
    <small>${escapeHtml(job.mode.toUpperCase())}</small>
    <span class="state ${escapeHtml(job.status)}">${escapeHtml(job.status)}</span>
    <small>${job.summary?.suspected_count ?? 0} threats</small>
  </div>`).join("");
  container.querySelectorAll(".history-row").forEach((row) => row.addEventListener("click", async () => {
    const job = await request(`/api/jobs/${row.dataset.job}`);
    useJob(job);
    if (job.status === "completed") await loadResults(job.id);
    if (["queued", "running", "capturing", "stopping", "analyzing"].includes(job.status)) {
      connectJob(job.id);
    }
    selectView(job.status === "completed" ? "report" : "pipeline");
  }));
}

Promise.all([loadAgents(), loadHistory()]).catch((error) => {
  qs("#form-error").textContent = error.message;
});
