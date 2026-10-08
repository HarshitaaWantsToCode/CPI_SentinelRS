const API_BASE = window.location.port === "8080" ? "" : "http://localhost:8080";
const WS_URL = window.location.protocol === "https:" 
  ? `wss://${window.location.host}/ws/events`
  : `ws://${window.location.hostname || 'localhost'}:8080/ws/events`;

// State
const MAX_EVENTS_BUFFER = 500;
let eventBuffer = [];
let detectionsBuffer = [];
let assetInventory = [];
let activeIncident = null;
let currentGraphMode = 'attack'; // 'attack' or 'infra'
let isStreamPaused = false;
let eventCounter = 0;
let lastEventTime = Date.now();
let eventsPerSecond = 0;
let wsConnection = null;

// Tab Titles Map
const TAB_TITLES = {
  dashboard: "Live SOC Dashboard",
  detections: "Real-Time Detection Findings Feed",
  incidents: "Incident Investigation & Forensic Evidence",
  graph: "Dual-Layer Cloud Graph",
  explorer: "Attack Path Explorer",
  mitre: "MITRE ATT&CK Matrix for Cloud",
  guardduty: "AWS GuardDuty Findings Ingestion",
  threatintel: "Threat Intelligence IP Enrichment",
  posture: "Cloud Security Posture Management (CSPM)",
  drift: "Terraform & IaC Drift Detection",
  assets: "Cloud Asset Inventory",
  responses: "Autonomous & Gated Response Center",
  audit: "Immutable Response Audit Trail (SHA-256 Chained)",
  simulation: "Attack Simulation Lab"
};

// Page Level Routing (Landing Page <-> Platform App)
function navigateToApp(tabId = 'dashboard') {
  document.getElementById('page-landing').classList.remove('active');
  document.getElementById('page-app').classList.add('active');
  window.scrollTo(0, 0);
  switchTab(tabId);
}

function navigateToLanding() {
  document.getElementById('page-app').classList.remove('active');
  document.getElementById('page-landing').classList.add('active');
  window.scrollTo(0, 0);
}

// Tab Switching (Left Taskbar)
function switchTab(tabId) {
  // Update views
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.taskbar-btn').forEach(el => el.classList.remove('active'));

  const targetPane = document.getElementById(`tab-${tabId}`);
  if (targetPane) {
    targetPane.classList.add('active');
  }

  // Update button active state
  const buttons = document.querySelectorAll('.taskbar-btn');
  buttons.forEach(btn => {
    if (btn.getAttribute('onclick') && btn.getAttribute('onclick').includes(tabId)) {
      btn.classList.add('active');
    }
  });

  // Update top bar title
  const titleEl = document.getElementById('active-tab-title');
  if (titleEl && TAB_TITLES[tabId]) {
    titleEl.textContent = TAB_TITLES[tabId];
  }

  // Trigger data fetches
  if (tabId === 'assets') fetchAssetInventory();
  if (tabId === 'detections') fetchDetections();
  if (tabId === 'incidents') fetchIncidentEvidence();
  if (tabId === 'mitre') fetchMitreData();
  if (tabId === 'graph') renderGraph();
  if (tabId === 'explorer') executePathQuery();
  if (tabId === 'guardduty') fetchGuardDutyFindings();
  if (tabId === 'threatintel') executeThreatIntelLookup();
  if (tabId === 'posture') fetchPostureData();
  if (tabId === 'drift') fetchDriftFindings();
  if (tabId === 'responses') fetchResponses();
  if (tabId === 'audit') fetchAuditTrail();
}

// WebSocket Connection
function connectWebSocket() {
  const statusBadge = document.getElementById('aws-conn-pill');
  const statusText = document.getElementById('aws-status-text');
  const wsDot = document.getElementById('ws-dot');

  try {
    wsConnection = new WebSocket(WS_URL);

    wsConnection.onopen = () => {
      if (statusText) statusText.textContent = "AWS TELEMETRY: LIVE";
      if (statusBadge) statusBadge.className = "status-pill live-pill";
      if (wsDot) wsDot.style.backgroundColor = "var(--primary-green)";
      console.log("Connected to SentinelRS Real-Time WebSocket stream.");
    };

    wsConnection.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === "EVENT_RECEIVED") {
          handleIncomingEvent(msg.payload);
        } else if (msg.type === "DETECTION_TRIGGERED") {
          handleIncomingDetection(msg.payload);
        } else if (msg.type === "INCIDENT_UPDATED") {
          handleIncomingIncident(msg.payload);
        } else if (msg.type === "GUARDDUTY_FINDING") {
          fetchGuardDutyFindings();
        } else if (msg.type === "RESPONSE_ACTION_UPDATED") {
          fetchResponses();
        } else if (msg.id) {
          handleIncomingEvent(msg);
        }
      } catch (err) {
        console.error("Failed to parse incoming WS message:", err);
      }
    };

    wsConnection.onclose = () => {
      if (statusText) statusText.textContent = "AWS STREAM: RECONNECTING";
      if (statusBadge) statusBadge.className = "status-pill warning";
      if (wsDot) wsDot.style.backgroundColor = "var(--warning)";
      setTimeout(connectWebSocket, 3000);
    };

    wsConnection.onerror = () => {
      if (statusText) statusText.textContent = "AWS STREAM: OFFLINE";
      if (wsDot) wsDot.style.backgroundColor = "var(--danger)";
    };
  } catch (e) {
    setTimeout(connectWebSocket, 3000);
  }
}

// Event Ingestion Handler
function handleIncomingEvent(cloudEvent) {
  eventCounter++;
  
  const now = Date.now();
  const diffSec = (now - lastEventTime) / 1000;
  if (diffSec >= 1) {
    eventsPerSecond = Math.round(1 / diffSec);
    lastEventTime = now;
    const rateEl = document.getElementById('kpi-rate');
    if (rateEl) rateEl.innerHTML = `Throughput: <span class="mono">${eventsPerSecond} ev/s</span>`;
  }

  eventBuffer.unshift(cloudEvent);
  if (eventBuffer.length > MAX_EVENTS_BUFFER) {
    eventBuffer.pop();
  }

  const countEl = document.getElementById('kpi-events');
  if (countEl) countEl.textContent = eventCounter;

  if (!isStreamPaused) {
    renderFilteredEvents();
  }
}

function handleIncomingDetection(finding) {
  if (!detectionsBuffer.some(d => d.id === finding.id)) {
    detectionsBuffer.unshift(finding);
  }
  renderDetectionsView();
}

function handleIncomingIncident(inc) {
  activeIncident = inc;
  renderIncidentDashboard(inc);
}

// Render Telemetry Table
function renderFilteredEvents() {
  const tbody = document.getElementById('events-table-body');
  const searchInput = document.getElementById('filter-search');
  const severitySelect = document.getElementById('filter-severity');
  const visibleCount = document.getElementById('visible-count');

  const query = searchInput ? searchInput.value.toLowerCase() : "";
  const sevFilter = severitySelect ? severitySelect.value.toLowerCase() : "";

  const filtered = eventBuffer.filter(ev => {
    const act = (ev.action || "").toLowerCase();
    const actor = (ev.actor?.identity || "").toLowerCase();
    const res = (ev.resource?.identifier || "").toLowerCase();
    const sev = (ev.severity || "low").toLowerCase();

    const matchesQuery = query === "" || act.includes(query) || actor.includes(query) || res.includes(query);
    const matchesSev = sevFilter === "" || sev === sevFilter;
    return matchesQuery && matchesSev;
  });

  if (visibleCount) visibleCount.textContent = filtered.length;
  if (!tbody) return;

  tbody.innerHTML = '';
  filtered.forEach((ev, idx) => {
    const row = document.createElement('tr');
    if (idx === 0) row.className = 'event-row-new';

    const timeStr = ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : "--";
    const actorStr = ev.actor?.identity || "unknown";
    const actionStr = ev.action || "UnknownAction";
    const resStr = ev.resource?.identifier || "*";
    const sevStr = (ev.severity || "low").toUpperCase();

    const sevColor = sevStr === 'CRITICAL' ? 'var(--danger)' : sevStr === 'HIGH' ? 'var(--warning)' : 'var(--primary-green-dark)';

    row.innerHTML = `
      <td>${timeStr}</td>
      <td class="mono">${actorStr}</td>
      <td><strong>${actionStr}</strong></td>
      <td class="mono" style="max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${resStr}</td>
      <td><span style="color:${sevColor}; font-weight:700;">${sevStr}</span></td>
    `;
    row.onclick = () => openDrawer(ev);
    tbody.appendChild(row);
  });
}

function applyEventFilters() {
  renderFilteredEvents();
}

function toggleStreamPause() {
  isStreamPaused = !isStreamPaused;
  const btn = document.getElementById('btn-pause-stream');
  if (btn) {
    btn.textContent = isStreamPaused ? "Resume" : "Pause";
    btn.style.borderColor = isStreamPaused ? "var(--warning)" : "var(--border-accent)";
  }
  if (!isStreamPaused) {
    renderFilteredEvents();
  }
}

function clearEventFeed() {
  eventBuffer = [];
  renderFilteredEvents();
}

// Side Drawer Investigation Details
function openDrawer(ev) {
  const drawer = document.getElementById('event-drawer');
  const drawerId = document.getElementById('drawer-id');
  const metaGrid = document.getElementById('drawer-meta-grid');
  const rawJson = document.getElementById('drawer-raw-json');

  if (!drawer) return;

  drawerId.textContent = ev.id || "N/A";
  rawJson.textContent = JSON.stringify(ev.metadata || ev, null, 2);

  metaGrid.innerHTML = `
    <div class="meta-item"><span class="label">Action:</span> <strong class="mono">${ev.action}</strong></div>
    <div class="meta-item"><span class="label">Actor:</span> <span class="mono">${ev.actor?.identity}</span></div>
    <div class="meta-item"><span class="label">Resource:</span> <span class="mono">${ev.resource?.identifier}</span></div>
    <div class="meta-item"><span class="label">Region:</span> <span class="mono">${ev.region || 'global'}</span></div>
    <div class="meta-item"><span class="label">Source IP:</span> <span class="mono">${ev.source_ip || 'N/A'}</span></div>
    <div class="meta-item"><span class="label">Outcome:</span> <span class="badge ${ev.outcome === 'success' ? 'badge-success' : 'badge-critical'}">${ev.outcome || 'success'}</span></div>
  `;

  drawer.classList.add('open');
}

function closeDrawer() {
  const drawer = document.getElementById('event-drawer');
  if (drawer) drawer.classList.remove('open');
}

// -------------------------------------------------------------------
// Detections & Findings
// -------------------------------------------------------------------
async function fetchDetections() {
  try {
    const res = await fetch(`${API_BASE}/api/detections`);
    if (res.ok) {
      detectionsBuffer = await res.json();
      renderDetectionsView();
    }
  } catch (e) {
    console.error("Failed to fetch detections:", e);
  }
}

function renderDetectionsView() {
  const container = document.getElementById('findings-cards-list');
  const badge = document.getElementById('detection-count-badge');
  if (badge) badge.textContent = `${detectionsBuffer.length} FINDINGS ACTIVE`;
  if (!container) return;

  container.innerHTML = '';
  
  if (detectionsBuffer.length === 0) {
    container.innerHTML = `
      <div style="grid-column: 1 / -1; padding: 36px; text-align: center; background: #FFFFFF; border: 1px dashed var(--border-accent); border-radius: 8px;">
        <p style="color: var(--text-secondary); font-size: 0.95rem;">No detection findings active. Run an attack scenario in the Attack Simulation Lab to generate live findings.</p>
        <button class="btn btn-hero mt-2" onclick="switchTab('simulation')">Open Attack Lab</button>
      </div>
    `;
    return;
  }

  detectionsBuffer.forEach(f => {
    const card = document.createElement('div');
    card.className = 'finding-card';
    card.innerHTML = `
      <div class="fc-header">
        <div>
          <h4>${f.title}</h4>
          <div class="fc-sub mono">${f.detector_id} • ${f.tactic} • ${f.technique_id}</div>
        </div>
        <span class="badge badge-critical">${f.severity.toUpperCase()} (+${f.risk_contribution})</span>
      </div>
      <p class="mt-1" style="font-size:0.88rem; color:var(--text-secondary);">${f.description}</p>
      ${f.why_suspicious ? `<div class="mt-1" style="font-size:0.8rem; color:var(--text-muted);"><strong>Why Suspicious:</strong> ${f.why_suspicious}</div>` : ''}
      ${f.recommended_response ? `<div class="mt-1" style="font-size:0.8rem; color:var(--primary-green-dark);"><strong>Recommended Response:</strong> ${f.recommended_response}</div>` : ''}
    `;
    container.appendChild(card);
  });
}

// -------------------------------------------------------------------
// GuardDuty Ingestion
// -------------------------------------------------------------------
async function fetchGuardDutyFindings() {
  try {
    const res = await fetch(`${API_BASE}/api/aws/guardduty/findings`);
    if (res.ok) {
      const findings = await res.json();
      renderGuardDutyTable(findings);
    }
  } catch (e) {}
}

function renderGuardDutyTable(findings) {
  const tbody = document.getElementById('guardduty-table-body');
  const badge = document.getElementById('guardduty-count-badge');
  if (badge) badge.textContent = `${findings.length} FINDINGS MONITORED`;
  if (!tbody) return;

  tbody.innerHTML = '';
  findings.forEach(f => {
    const row = document.createElement('tr');
    const sevColor = f.severity >= 7.0 ? 'var(--danger)' : f.severity >= 4.0 ? 'var(--warning)' : 'var(--primary-green-dark)';
    row.innerHTML = `
      <td class="mono" style="font-size:0.8rem;">${f.id}</td>
      <td><strong>${f.title}</strong></td>
      <td class="mono" style="font-size:0.75rem; color:var(--text-secondary);">${f.finding_type}</td>
      <td><span style="color:${sevColor}; font-weight:700;">${f.severity.toFixed(1)} / 10</span></td>
      <td class="mono">${f.resource_id || '*'}</td>
      <td class="mono">${f.actor_ip || 'N/A'}</td>
      <td>${f.region || 'ap-south-1'}</td>
    `;
    tbody.appendChild(row);
  });
}

async function ingestDemoGuardDuty() {
  try {
    const res = await fetch(`${API_BASE}/api/aws/guardduty/ingest-demo`, { method: "POST" });
    if (res.ok) {
      const data = await res.json();
      alert(`GuardDuty Ingest Success: ${data.findings_ingested} findings ingested and correlated.`);
      fetchGuardDutyFindings();
      fetchInitialData();
    }
  } catch (e) {}
}

// -------------------------------------------------------------------
// Threat Intelligence
// -------------------------------------------------------------------
async function executeThreatIntelLookup() {
  const ipInput = document.getElementById('ti-input-ip');
  const ip = ipInput ? ipInput.value.trim() : "198.51.100.42";
  const resultPanel = document.getElementById('ti-result-panel');
  if (!resultPanel) return;

  try {
    const res = await fetch(`${API_BASE}/api/threat-intel/lookup/${ip}`);
    if (res.ok) {
      const data = await res.json();
      const isMal = data.malicious;
      resultPanel.innerHTML = `
        <div class="glass-panel" style="border-left: 4px solid ${isMal ? 'var(--danger)' : 'var(--primary-green)'};">
          <div class="panel-header">
            <div>
              <h3>Indicator: <span class="mono">${data.ip}</span></h3>
              <div class="panel-sub">Source: ${data.source} • Status: <span class="badge ${isMal ? 'badge-critical' : 'badge-success'}">${data.status}</span></div>
            </div>
            <div class="kpi-value" style="font-size:1.8rem; color:${isMal ? 'var(--danger)' : 'var(--primary-green-dark)'}">
              ${data.reputation_score ? data.reputation_score.toFixed(0) : '0'}<span class="unit">/100 Reputation</span>
            </div>
          </div>
          <div class="drawer-grid mt-2">
            <div class="meta-item"><span class="label">Classification:</span> <strong>${isMal ? 'MALICIOUS ADVERSARY' : 'BENIGN TRAFFIC'}</strong></div>
            <div class="meta-item"><span class="label">Confidence:</span> <span class="mono">${((data.confidence || 0.8) * 100).toFixed(0)}%</span></div>
            <div class="meta-item"><span class="label">Categories:</span> <span class="mono">${data.categories.join(', ')}</span></div>
            <div class="meta-item"><span class="label">First Seen:</span> <span class="mono">${data.first_seen ? new Date(data.first_seen).toLocaleDateString() : 'N/A'}</span></div>
          </div>
        </div>
      `;
    }
  } catch (e) {}
}

// -------------------------------------------------------------------
// Cloud Posture (CSPM)
// -------------------------------------------------------------------
async function fetchPostureData() {
  try {
    const res = await fetch(`${API_BASE}/api/posture`);
    if (res.ok) {
      const data = await res.json();
      renderPostureView(data);
    }
  } catch (e) {}
}

function renderPostureView(data) {
  const scoreVal = document.getElementById('posture-score-val');
  if (scoreVal) scoreVal.innerHTML = `${data.overall_score}<span class="unit">/100</span>`;

  const kpiScore = document.getElementById('kpi-posture-score');
  if (kpiScore) kpiScore.innerHTML = `${data.overall_score}<span class="unit">/100</span>`;

  const metaEl = document.getElementById('kpi-posture-meta');
  if (metaEl) metaEl.textContent = `${data.total_findings} Misconfigurations • ${data.critical_count} Critical`;

  const tbody = document.getElementById('posture-table-body');
  if (!tbody) return;

  tbody.innerHTML = '';
  (data.findings || []).forEach(f => {
    const row = document.createElement('tr');
    const sevColor = f.severity === 'critical' ? 'var(--danger)' : f.severity === 'high' ? 'var(--warning)' : 'var(--primary-green-dark)';
    row.innerHTML = `
      <td class="mono">${f.rule_id}</td>
      <td><strong>${f.title}</strong></td>
      <td>${f.category}</td>
      <td><span style="color:${sevColor}; font-weight:700;">${f.severity.toUpperCase()}</span></td>
      <td class="mono">${f.resource_id}</td>
      <td><span class="badge ${f.status === 'open' ? 'badge-critical' : 'badge-success'}">${f.status.toUpperCase()}</span></td>
      <td style="font-size:0.8rem; color:var(--text-secondary);">${f.remediation}</td>
    `;
    tbody.appendChild(row);
  });
}

async function triggerPostureScan() {
  try {
    const res = await fetch(`${API_BASE}/api/posture/scan`, { method: "POST" });
    if (res.ok) {
      alert("Posture scan executed across AWS asset inventory.");
      fetchPostureData();
    }
  } catch (e) {}
}

// -------------------------------------------------------------------
// IaC Drift Detection
// -------------------------------------------------------------------
async function fetchDriftFindings() {
  try {
    const res = await fetch(`${API_BASE}/api/drift/findings`);
    if (res.ok) {
      const drifts = await res.json();
      renderDriftTable(drifts);
    }
  } catch (e) {}
}

function renderDriftTable(drifts) {
  const tbody = document.getElementById('drift-table-body');
  if (!tbody) return;

  tbody.innerHTML = '';
  drifts.forEach(d => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td class="mono"><strong>${d.resource_address}</strong></td>
      <td class="mono">${d.resource_type}</td>
      <td><span class="badge badge-critical">${d.drift_type}</span></td>
      <td><span style="color:var(--danger); font-weight:700;">${d.severity.toUpperCase()}</span></td>
      <td style="font-size:0.85rem;">${d.security_impact}</td>
      <td class="mono" style="font-size:0.75rem; color:var(--text-secondary);">
        Expected: ${JSON.stringify(d.expected)}<br>
        Observed: ${JSON.stringify(d.observed)}
      </td>
    `;
    tbody.appendChild(row);
  });
}

async function triggerDriftEvaluation() {
  try {
    const res = await fetch(`${API_BASE}/api/drift/evaluate`, { method: "POST" });
    if (res.ok) {
      const data = await res.json();
      alert(`Drift evaluation completed: ${data.drift_findings_count} security-relevant drifts detected.`);
      fetchDriftFindings();
    }
  } catch (e) {}
}

// -------------------------------------------------------------------
// Response Center
// -------------------------------------------------------------------
async function fetchResponses() {
  try {
    const res = await fetch(`${API_BASE}/api/responses`);
    if (res.ok) {
      const actions = await res.json();
      renderResponses(actions);
    }
  } catch (e) {}
}

function renderResponses(actions) {
  const container = document.getElementById('responses-container');
  const dashList = document.getElementById('dashboard-containment-list');
  if (!container) return;

  container.innerHTML = '';
  if (dashList) dashList.innerHTML = '';

  actions.forEach(act => {
    const card = document.createElement('div');
    card.className = 'glass-panel mt-2';
    
    const isApproved = act.status === 'approved';
    const isExecuted = act.status === 'executed';
    const approvalsCount = (act.approvals || []).filter(a => a.decision === 'approved').length;

    card.innerHTML = `
      <div class="panel-header">
        <div>
          <h3>${act.title}</h3>
          <div class="panel-sub">Target: <span class="mono">${act.target_resource}</span> • Action: <span class="mono">${act.action_type}</span></div>
        </div>
        <div style="display:flex; gap:8px; align-items:center;">
          <span class="badge ${isExecuted ? 'badge-success' : isApproved ? 'badge-warning' : 'badge-critical'}">
            ${act.status.toUpperCase()}
          </span>
          <span class="badge badge-pulse">Mode: ${act.mode.toUpperCase()}</span>
        </div>
      </div>

      <p class="mt-1" style="color:var(--text-secondary); font-size:0.9rem;">${act.description}</p>

      ${act.simulation_result ? `
        <div class="mt-2 p-2" style="background:#F0FDF4; border-left:3px solid var(--primary-green); border-radius:4px; font-size:0.85rem;">
          <strong style="color:var(--primary-green-dark);">Dry-Run Simulation Validated:</strong>
          <div class="mono mt-1" style="font-size:0.8rem; color:#064E3B;">Call: ${act.simulation_result.hypothetical_aws_call}</div>
          <div style="color:var(--text-secondary); font-size:0.8rem; margin-top:2px;">Impact: ${act.simulation_result.expected_impact}</div>
        </div>
      ` : ''}

      <div class="mt-2" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
        <div style="font-size:0.85rem; color:var(--text-secondary);">
          <strong>Dual Approval Gate:</strong> ${approvalsCount} of ${act.required_approvals_count} Approvals Recorded
        </div>
        <div style="display:flex; gap:8px;">
          <button class="btn btn-sm btn-simulate" onclick="simulateResponseAction('${act.id}')">Run Simulation</button>
          <button class="btn btn-sm" onclick="approveResponseAction('${act.id}')" ${approvalsCount >= act.required_approvals_count ? 'disabled' : ''}>
            Submit Approval
          </button>
          <button class="btn btn-sm btn-hero" onclick="executeResponseAction('${act.id}')" ${!isApproved || isExecuted ? 'disabled' : ''}>
            Gated Execution
          </button>
        </div>
      </div>
    `;
    container.appendChild(card);

    if (dashList) {
      const item = document.createElement('div');
      item.className = 'containment-item';
      item.innerHTML = `
        <div class="ci-info">
          <strong>${act.title}</strong>
          <div class="ci-sub">Target: ${act.target_resource} • Status: ${act.status.toUpperCase()}</div>
        </div>
        <button class="btn btn-sm btn-simulate" onclick="simulateResponseAction('${act.id}')">Simulate</button>
      `;
      dashList.appendChild(item);
    }
  });
}

async function simulateResponseAction(id) {
  try {
    const res = await fetch(`${API_BASE}/api/responses/${id}/simulate`, { method: "POST" });
    if (res.ok) {
      alert("Simulation completed. Verification details and hypothetical AWS call recorded in immutable audit log.");
      fetchResponses();
      fetchAuditTrail();
    }
  } catch (e) {}
}

async function approveResponseAction(id) {
  const approver = prompt("Enter Authorized Approver Identity (e.g. sec-lead-alice, ciso-bob):", "sec-lead-alice");
  if (!approver) return;

  try {
    const res = await fetch(`${API_BASE}/api/responses/${id}/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        approver_id: approver,
        decision: "approved",
        reason: "Containment authorized following validated C2 threat intel findings."
      })
    });
    if (res.ok) {
      alert(`Approval recorded for ${approver}.`);
      fetchResponses();
      fetchAuditTrail();
    } else {
      const err = await res.text();
      alert(`Approval error: ${err}`);
    }
  } catch (e) {}
}

async function executeResponseAction(id) {
  const confirmExec = confirm("Execute Gated Response Action? Mode will default to Safe Simulation unless Live execution is configured.");
  if (!confirmExec) return;

  try {
    const res = await fetch(`${API_BASE}/api/responses/${id}/execute`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        executor: "lead-incident-commander",
        mode: "simulation"
      })
    });
    if (res.ok) {
      const data = await res.json();
      alert(`Execution Result: ${data.result_summary}`);
      fetchResponses();
      fetchAuditTrail();
    } else {
      const err = await res.text();
      alert(`Execution rejected: ${err}`);
    }
  } catch (e) {}
}

// -------------------------------------------------------------------
// Audit Trail
// -------------------------------------------------------------------
async function fetchAuditTrail() {
  try {
    const res = await fetch(`${API_BASE}/api/audit/response`);
    if (res.ok) {
      const records = await res.json();
      renderAuditTable(records);
    }
  } catch (e) {}
}

function renderAuditTable(records) {
  const tbody = document.getElementById('audit-table-body');
  if (!tbody) return;

  tbody.innerHTML = '';
  records.forEach(r => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td class="mono">#${r.sequence_number}</td>
      <td class="mono" style="font-size:0.75rem;">${new Date(r.timestamp).toLocaleTimeString()}</td>
      <td class="mono">${r.incident_id}</td>
      <td class="mono">${r.actor}</td>
      <td><strong>${r.action_type}</strong></td>
      <td><span class="badge badge-pulse">${r.execution_mode.toUpperCase()}</span></td>
      <td class="mono" style="font-size:0.8rem;">${r.previous_state} -> ${r.new_state}</td>
      <td class="mono" style="font-size:0.7rem; color:var(--text-secondary);">${r.current_hash.substring(0, 24)}...</td>
    `;
    tbody.appendChild(row);
  });
}

async function verifyAuditChain() {
  try {
    const res = await fetch(`${API_BASE}/api/audit/response/verify`);
    if (res.ok) {
      const data = await res.json();
      const banner = document.getElementById('audit-verify-banner');
      if (banner) {
        if (data.valid) {
          banner.innerHTML = `<span class="mono" style="color:var(--success-text);">CHAIN VERIFIED: ${data.records_checked} Records Validated. SHA-256 Hashes Continuously Anchored.</span>`;
          alert(`Cryptographic Verification Succeeded: All ${data.records_checked} audit log records verified intact.`);
        } else {
          banner.innerHTML = `<span class="mono" style="color:var(--danger);">INTEGRITY VIOLATION: Tampering detected at sequence #${data.first_invalid_record}.</span>`;
        }
      }
    }
  } catch (e) {}
}

// -------------------------------------------------------------------
// Asset Inventory
// -------------------------------------------------------------------
async function fetchAssetInventory() {
  try {
    const res = await fetch(`${API_BASE}/api/assets`);
    if (res.ok) {
      assetInventory = await res.json();
      const tbody = document.getElementById('assets-table-body');
      const badge = document.getElementById('assets-total-badge');
      if (badge) badge.textContent = `${assetInventory.length} ASSETS MONITORED`;
      if (tbody) {
        tbody.innerHTML = '';
        assetInventory.forEach(a => {
          const row = document.createElement('tr');
          const sensClass = a.sensitivity === 'critical' ? 'badge-critical' : a.sensitivity === 'sensitive' ? 'badge-warning' : 'badge-success';
          row.innerHTML = `
            <td><strong>${a.name}</strong></td>
            <td class="mono">${a.asset_type}</td>
            <td>${a.region || 'global'}</td>
            <td><span class="badge ${sensClass}">${a.sensitivity.toUpperCase()}</span></td>
            <td><strong>${a.criticality_score}/100</strong></td>
            <td class="mono" style="font-size:0.75rem; color:var(--text-secondary);">${a.arn || 'N/A'}</td>
          `;
          tbody.appendChild(row);
        });
      }
    }
  } catch (e) {}
}

// -------------------------------------------------------------------
// Incident Evidence View
// -------------------------------------------------------------------
async function fetchIncidentEvidence() {
  try {
    const res = await fetch(`${API_BASE}/api/incidents/SR-1042/evidence`);
    if (res.ok) {
      const data = await res.json();
      renderIncidentEvidenceView(data);
    }
  } catch (e) {}
}

function renderIncidentEvidenceView(data) {
  const grid = document.getElementById('inc-factors-grid');
  if (grid && data.risk_decomposition) {
    grid.innerHTML = '';
    (data.risk_decomposition.factors || []).forEach(factor => {
      const el = document.createElement('div');
      el.className = 'factor-item';
      el.innerHTML = `
        <span class="factor-delta">+${factor.score_delta}</span>
        <div>
          <strong style="color:#0F172A;">${factor.name}</strong>
          <div class="sub">${factor.description}</div>
        </div>
      `;
      grid.appendChild(el);
    });
  }

  const evList = document.getElementById('inc-evidence-list');
  if (evList && data.findings) {
    evList.innerHTML = '';
    data.findings.forEach(f => {
      const item = document.createElement('div');
      item.className = 'containment-item';
      item.innerHTML = `
        <div class="ci-info">
          <strong>${f.title} (${f.detector_id})</strong>
          <div class="ci-sub">Tactic: ${f.tactic} • Technique: ${f.technique_id}</div>
        </div>
        <span class="badge badge-critical">${f.severity.toUpperCase()}</span>
      `;
      evList.appendChild(item);
    });
  }
}

function renderIncidentDashboard(inc) {
  const riskVal = document.getElementById('kpi-risk');
  if (riskVal) riskVal.innerHTML = `${inc.risk_score}<span class="unit">/100</span>`;

  const timeline = document.getElementById('dashboard-timeline');
  if (timeline && inc.stages) {
    timeline.innerHTML = '';
    inc.stages.forEach(st => {
      const item = document.createElement('div');
      item.className = 'timeline-item';
      const timeStr = new Date(st.timestamp).toLocaleTimeString();
      item.innerHTML = `
        <div class="timeline-dot"></div>
        <div class="timeline-content">
          <span class="mono" style="color:var(--text-muted); font-size:0.75rem;">${timeStr}</span>
          <strong style="display:block; font-size:0.85rem; color:#0F172A;">${st.description}</strong>
          <span class="mono" style="font-size:0.75rem; color:var(--primary-green-dark);">${st.technique_id} • ${st.affected_resource}</span>
        </div>
      `;
      timeline.appendChild(item);
    });
  }
}

async function markFalsePositive() {
  const reason = prompt("Enter false positive justification for audit log:", "Approved disaster recovery exercise");
  if (!reason) return;

  try {
    const res = await fetch(`${API_BASE}/api/incidents/SR-1042/false-positive`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ analyst: "Senior SOC Analyst", reason })
    });
    if (res.ok) {
      alert("Incident SR-1042 marked as False Positive and dismissed.");
      const badge = document.getElementById('inc-risk-badge');
      if (badge) {
        badge.textContent = "DISMISSED (FALSE POSITIVE)";
        badge.className = "badge badge-success";
      }
    }
  } catch (e) {}
}

// -------------------------------------------------------------------
// MITRE Data
// -------------------------------------------------------------------
async function fetchMitreData() {
  const container = document.getElementById('mitre-matrix-grid');
  if (!container) return;

  try {
    const res = await fetch(`${API_BASE}/api/mitre`);
    if (res.ok) {
      const data = await res.json();
      container.innerHTML = '';
      (data.tactics || []).forEach(tactic => {
        const col = document.createElement('div');
        col.className = 'mitre-col';
        col.innerHTML = `<div class="mitre-col-header">${tactic}</div>`;

        const techs = (data.techniques || []).filter(t => t.tactic === tactic);
        techs.forEach(tech => {
          const cell = document.createElement('div');
          cell.className = 'mitre-cell active-cell';
          cell.innerHTML = `
            <div class="m-id">${tech.id}</div>
            <div class="m-name">${tech.name}</div>
            <div class="m-count">${tech.observed_count} Observations</div>
          `;
          col.appendChild(cell);
        });
        container.appendChild(col);
      });
    }
  } catch (e) {}
}

// -------------------------------------------------------------------
// Attack Graph & Explorer (Visual SVG Connector Engine)
// -------------------------------------------------------------------
function switchGraphMode(mode) {
  currentGraphMode = mode;
  document.getElementById('btn-layer-attack')?.classList.toggle('active', mode === 'attack');
  document.getElementById('btn-layer-infra')?.classList.toggle('active', mode === 'infra');
  renderGraph();
}

function renderGraph() {
  const canvas = document.getElementById('graph-diagram-canvas');
  if (!canvas) return;

  if (currentGraphMode === 'attack') {
    canvas.innerHTML = `
      <svg class="graph-svg-layer" viewBox="0 0 1000 520" preserveAspectRatio="none">
        <defs>
          <marker id="arrow-red" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3 z" fill="#DC2626" />
          </marker>
          <marker id="arrow-gray" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3 z" fill="#94A3B8" />
          </marker>
        </defs>
        <!-- Dynamic Curved & Straight Directed Edges -->
        <path d="M 170 170 C 230 170, 230 170, 290 170" class="graph-svg-edge highlighted" marker-end="url(#arrow-red)" />
        <path d="M 470 170 C 530 170, 530 170, 590 170" class="graph-svg-edge highlighted" marker-end="url(#arrow-red)" />
        <path d="M 770 170 C 820 170, 820 170, 850 170" class="graph-svg-edge highlighted" marker-end="url(#arrow-red)" />
        <path d="M 380 230 C 380 320, 480 380, 590 380" class="graph-svg-edge highlighted" marker-end="url(#arrow-red)" />
        <path d="M 380 230 C 380 340, 200 370, 180 370" class="graph-svg-edge" marker-end="url(#arrow-gray)" />
      </svg>

      <!-- Nodes -->
      <div class="graph-node-box critical highlighted-path" style="left:40px; top:125px; width:150px;">
        <span class="node-badge">Adversary Origin</span>
        <div class="gn-title mono">198.51.100.42</div>
        <div class="gn-sub">Reputation: 88/100 (C2)</div>
      </div>

      <div class="graph-edge-pill critical-pill" style="left:235px; top:150px;">
        [T1078 Auth]
      </div>

      <div class="graph-node-box critical highlighted-path" style="left:300px; top:125px; width:170px;">
        <span class="node-badge">Compromised Identity</span>
        <div class="gn-title mono">attacker-demo</div>
        <div class="gn-sub">IAM User (No MFA)</div>
      </div>

      <div class="graph-edge-pill critical-pill" style="left:530px; top:150px;">
        [T1098 PrivEsc]
      </div>

      <div class="graph-node-box critical highlighted-path" style="left:600px; top:125px; width:170px;">
        <span class="node-badge">Escalated Role</span>
        <div class="gn-title mono">AdministratorRole</div>
        <div class="gn-sub">Root Privileges Granted</div>
      </div>

      <div class="graph-edge-pill critical-pill" style="left:810px; top:150px;">
        [T1530 Exfil]
      </div>

      <div class="graph-node-box critical highlighted-path" style="left:840px; top:125px; width:150px;">
        <span class="node-badge">Crown Jewel</span>
        <div class="gn-title mono" style="font-size:0.78rem;">s3-customer-pii</div>
        <div class="gn-sub">Confidential Vault</div>
      </div>

      <!-- Secondary Attack Branches -->
      <div class="graph-edge-pill critical-pill" style="left:480px; top:360px;">
        [T1562 Tamper]
      </div>

      <div class="graph-node-box critical" style="left:600px; top:330px; width:170px;">
        <span class="node-badge">Evasion Target</span>
        <div class="gn-title mono">prod-audit-trail</div>
        <div class="gn-sub">CloudTrail Logging Disabled</div>
      </div>

      <div class="graph-edge-pill" style="left:260px; top:350px;">
        [T1098 KeyGen]
      </div>

      <div class="graph-node-box" style="left:40px; top:330px; width:160px;">
        <span class="node-badge">Persistence</span>
        <div class="gn-title mono" style="font-size:0.78rem;">AKIAIOSFODNN7...</div>
        <div class="gn-sub">Secondary Access Key</div>
      </div>
    `;
  } else {
    canvas.innerHTML = `
      <svg class="graph-svg-layer" viewBox="0 0 1000 520" preserveAspectRatio="none">
        <defs>
          <marker id="arrow-green" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3 z" fill="#059669" />
          </marker>
        </defs>
        <path d="M 180 180 C 230 180, 230 180, 280 180" class="graph-svg-edge green-highlight" marker-end="url(#arrow-green)" />
        <path d="M 450 180 C 500 180, 500 180, 550 180" class="graph-svg-edge green-highlight" marker-end="url(#arrow-green)" />
        <path d="M 720 180 C 770 180, 770 180, 810 180" class="graph-svg-edge green-highlight" marker-end="url(#arrow-green)" />
      </svg>

      <div class="graph-node-box" style="left:40px; top:135px; width:155px;">
        <span class="node-badge" style="color:var(--primary-green-dark);">Cloud Network</span>
        <div class="gn-title mono">VPC ap-south-1</div>
        <div class="gn-sub">CIDR 10.0.0.0/16</div>
      </div>

      <div class="graph-edge-pill" style="left:230px; top:160px;">CONTAINS</div>

      <div class="graph-node-box" style="left:290px; top:135px; width:165px;">
        <span class="node-badge" style="color:var(--warning);">Security Group</span>
        <div class="gn-title mono">sg-04a1bc9</div>
        <div class="gn-sub">Public Ingress 0.0.0.0/0</div>
      </div>

      <div class="graph-edge-pill" style="left:500px; top:160px;">ATTACHED_TO</div>

      <div class="graph-node-box" style="left:560px; top:135px; width:165px;">
        <span class="node-badge" style="color:var(--info-text);">Compute Node</span>
        <div class="gn-title mono">i-0a8b9c1d2e3f</div>
        <div class="gn-sub">App Server (EC2)</div>
      </div>

      <div class="graph-edge-pill" style="left:765px; top:160px;">LOGS_TO</div>

      <div class="graph-node-box" style="left:810px; top:135px; width:160px;">
        <span class="node-badge" style="color:var(--primary-green-dark);">Auditing</span>
        <div class="gn-title mono">prod-audit-trail</div>
        <div class="gn-sub">Multi-Region CloudTrail</div>
      </div>
    `;
  }
}

async function executePathQuery() {
  const source = document.getElementById('path-source').value;
  const target = document.getElementById('path-target').value;
  const depth = parseInt(document.getElementById('path-depth').value, 10) || 6;

  try {
    const res = await fetch(`${API_BASE}/api/graph/path`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source, target, max_depth: depth })
    });
    if (res.ok) {
      const data = await res.json();
      renderVisualPathJourney(data);
    }
  } catch (e) {
    console.error("Failed to execute path query:", e);
  }
}

function renderVisualPathJourney(data) {
  const container = document.getElementById('path-results-container');
  if (!container) return;

  const pathNodes = data.path_nodes || data.path || [
    "198.51.100.42",
    "attacker-demo",
    "AdministratorRole",
    "s3://sentinel-customer-pii-production"
  ];
  const risk = data.path_risk_score || 94;

  const nodeTypes = [
    "Attacker C2 IP",
    "Compromised IAM Identity",
    "Privileged IAM Role",
    "Crown-Jewel S3 Store"
  ];

  const edgeLabels = [
    "AUTHENTICATED",
    "CAN_ASSUME",
    "ACCESSES_DATA"
  ];

  let nodesHtml = '';
  pathNodes.forEach((node, idx) => {
    const typeLabel = nodeTypes[idx] || "Cloud Asset";
    nodesHtml += `
      <div class="path-node-card">
        <div class="node-idx-badge">${idx + 1}</div>
        <div class="node-text-group">
          <div class="node-name">${node}</div>
          <div class="node-type">${typeLabel}</div>
        </div>
      </div>
    `;

    if (idx < pathNodes.length - 1) {
      const edgeAction = edgeLabels[idx] || "TRAVERSES";
      nodesHtml += `
        <div class="path-edge-connector">
          <span>${edgeAction}</span>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <line x1="5" y1="12" x2="19" y2="12"></line>
            <polyline points="12 5 19 12 12 19"></polyline>
          </svg>
        </div>
      `;
    }
  });

  container.innerHTML = `
    <div class="panel-header">
      <div>
        <h4 style="font-size:1.05rem; font-weight:700; color:#064E3B;">Calculated Shortest Attack Traversal:</h4>
        <div class="panel-sub">${pathNodes.length} Hops to Crown Jewel Target</div>
      </div>
      <span class="badge badge-critical" id="path-risk-badge">PATH RISK: ${risk}/100 CRITICAL</span>
    </div>

    <div class="interactive-path-wrapper">
      <div class="visual-path-nodes">
        ${nodesHtml}
      </div>
    </div>

    <div class="mt-2" style="font-size: 0.88rem; color: var(--text-secondary); line-height:1.6;">
      <strong style="color:#0F172A;">Attack Vector Justification:</strong> 
      Direct lateral movement vector enabling an untrusted external adversary IP to authenticate via compromised credentials, assume <em>AdministratorRole</em> privileges, and access sensitive customer financial/PII data.
    </div>
  `;
}

// -------------------------------------------------------------------
// Simulation Engine
// -------------------------------------------------------------------
async function runSimulation(scenarioName) {
  const logBox = document.getElementById('console-logs');
  if (logBox) {
    logBox.textContent = `[${new Date().toLocaleTimeString()}] Submitting scenario to Rust Pipeline: "${scenarioName}"...\n`;
  }
  
  try {
    const res = await fetch(`${API_BASE}/api/simulate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: scenarioName })
    });
    if (res.ok) {
      const data = await res.json();
      if (logBox) {
        logBox.textContent += `[${new Date().toLocaleTimeString()}] Ingestion: Ingested & normalized ${data.events_injected} CloudTrail events.\n`;
        logBox.textContent += `[${new Date().toLocaleTimeString()}] Detection Engine: Evaluated against Asset Inventory Context -> ${data.detections_triggered} findings.\n`;
        logBox.textContent += `[${new Date().toLocaleTimeString()}] Threat Intel & Posture: IP reputation calculated.\n`;
        logBox.textContent += `[${new Date().toLocaleTimeString()}] Risk Engine: Computed incident risk score (94/100).\n`;
        logBox.textContent += `\n>> SUCCESS: Live SOC telemetry & Attack Graph updated.\n`;
      }
      fetchInitialData();
      return;
    }
  } catch (e) {
    if (logBox) {
      logBox.textContent += `[Error] Simulation failed: ${e.message}\n`;
    }
  }
}

// -------------------------------------------------------------------
// Initial Data Boot
// -------------------------------------------------------------------
async function fetchInitialData() {
  try {
    const [eventsRes, incRes, assetRes, gdRes, postRes, respRes, detRes] = await Promise.all([
      fetch(`${API_BASE}/api/events?limit=50`),
      fetch(`${API_BASE}/api/incidents`),
      fetch(`${API_BASE}/api/assets`),
      fetch(`${API_BASE}/api/aws/guardduty/findings`),
      fetch(`${API_BASE}/api/posture`),
      fetch(`${API_BASE}/api/responses`),
      fetch(`${API_BASE}/api/detections`)
    ]);

    if (eventsRes.ok) {
      eventBuffer = await eventsRes.json();
      eventCounter = eventBuffer.length;
      const countEl = document.getElementById('kpi-events');
      if (countEl) countEl.textContent = eventCounter;
      renderFilteredEvents();
    }

    if (incRes.ok) {
      const incs = await incRes.json();
      if (incs.length > 0) {
        activeIncident = incs[0];
        renderIncidentDashboard(activeIncident);
      }
    }

    if (assetRes.ok) {
      assetInventory = await assetRes.json();
      const badge = document.getElementById('assets-total-badge');
      if (badge) badge.textContent = `${assetInventory.length} ASSETS MONITORED`;
    }

    if (gdRes.ok) {
      const gd = await gdRes.json();
      renderGuardDutyTable(gd);
    }

    if (postRes.ok) {
      const post = await postRes.json();
      renderPostureView(post);
    }

    if (respRes.ok) {
      const resp = await respRes.json();
      renderResponses(resp);
    }

    if (detRes.ok) {
      detectionsBuffer = await detRes.json();
      renderDetectionsView();
    }
  } catch (e) {
    console.error("Initial data load error:", e);
  }
}

// Initial Boot
window.addEventListener('DOMContentLoaded', () => {
  fetchInitialData();
  connectWebSocket();
  renderGraph();
  fetchMitreData();
  fetchAuditTrail();
  executePathQuery();
});
