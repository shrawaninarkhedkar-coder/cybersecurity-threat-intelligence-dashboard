/**
 * Cybersecurity Awareness & Threat Intelligence Dashboard
 * Frontend Application Logic (Charts, APIs, IOC Lookup, Quiz, SOC Workflows)
 */

const API_BASE = '/api';

// Global state
let currentThreatsPage = 1;
let threatChartInstances = {};
let quizQuestions = [];
let userQuizAnswers = {};
let currentQuizIndex = 0;

document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  loadDashboardData();
  loadThreatsTable(1);
  loadAlerts();
  loadVulnerabilities();
  loadAwarenessModules();
  loadExecutiveSummary();
  initIOCSearch();
  initVulnCalculator();
});

// Navigation Handling
function initNavigation() {
  const navButtons = document.querySelectorAll('nav.main-nav button');
  navButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      navButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const targetTab = btn.getAttribute('data-tab');
      document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.remove('active');
      });
      const activePane = document.getElementById(targetTab);
      if (activePane) activePane.classList.add('active');

      // Refresh specific tab contents if needed
      if (targetTab === 'tab-dashboard') {
        loadDashboardData();
      } else if (targetTab === 'tab-threats') {
        loadThreatsTable(currentThreatsPage);
      } else if (targetTab === 'tab-alerts') {
        loadAlerts();
      } else if (targetTab === 'tab-quiz') {
        loadQuiz();
      }
    });
  });
}

// -------------------------------------------------------------
// 1. DASHBOARD & CHARTS
// -------------------------------------------------------------
async function loadDashboardData() {
  try {
    const [statsRes, trendsRes] = await Promise.all([
      fetch(`${API_BASE}/dashboard/stats`).then(r => r.json()),
      fetch(`${API_BASE}/dashboard/trends`).then(r => r.json())
    ]);

    if (statsRes.status === 'success') {
      const s = statsRes.data;
      document.getElementById('kpi-total-threats').innerText = s.total_threats.toLocaleString();
      document.getElementById('kpi-critical-threats').innerText = s.critical_threats;
      document.getElementById('kpi-high-threats').innerText = s.high_threats;
      document.getElementById('kpi-active-iocs').innerText = s.active_indicators.toLocaleString();
      document.getElementById('kpi-open-alerts').innerText = s.open_alerts;
      document.getElementById('kpi-avg-confidence').innerText = `${s.avg_confidence}%`;
      document.getElementById('kpi-avg-risk').innerText = `${s.avg_risk}/100`;
      document.getElementById('kpi-vulns').innerText = s.vulnerabilities_tracked;
      document.getElementById('kpi-awareness-score').innerText = `${s.avg_awareness_score}%`;
    }

    if (trendsRes.status === 'success') {
      renderCharts(trendsRes.data);
    }
  } catch (err) {
    console.error('Error loading dashboard data:', err);
  }
}

function renderCharts(data) {
  // Destroy existing charts to prevent canvas re-use errors
  Object.values(threatChartInstances).forEach(chart => chart.destroy());
  threatChartInstances = {};

  // 1. Severity Distribution
  const ctxSev = document.getElementById('chart-severity').getContext('2d');
  const sevLabels = data.severity_distribution.map(d => d.severity);
  const sevCounts = data.severity_distribution.map(d => d.count);
  threatChartInstances.severity = new Chart(ctxSev, {
    type: 'doughnut',
    data: {
      labels: sevLabels,
      datasets: [{
        data: sevCounts,
        backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981', '#9ca3af']
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { color: '#9ca3af' } } }
    }
  });

  // 2. Category Distribution
  const ctxCat = document.getElementById('chart-category').getContext('2d');
  const catLabels = data.category_distribution.map(d => d.category);
  const catCounts = data.category_distribution.map(d => d.count);
  threatChartInstances.category = new Chart(ctxCat, {
    type: 'bar',
    data: {
      labels: catLabels,
      datasets: [{
        label: 'Threats',
        data: catCounts,
        backgroundColor: '#06b6d4',
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: '#9ca3af', maxRotation: 45, minRotation: 45 } },
        y: { ticks: { color: '#9ca3af' }, grid: { color: '#374151' } }
      },
      plugins: { legend: { display: false } }
    }
  });

  // 3. Indicator Type Distribution
  const ctxInd = document.getElementById('chart-indicators').getContext('2d');
  const indLabels = data.indicator_distribution.map(d => d.indicator_type);
  const indCounts = data.indicator_distribution.map(d => d.count);
  threatChartInstances.indicators = new Chart(ctxInd, {
    type: 'pie',
    data: {
      labels: indLabels,
      datasets: [{
        data: indCounts,
        backgroundColor: ['#3b82f6', '#06b6d4', '#8b5cf6', '#10b981', '#f59e0b', '#ec4899']
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { color: '#9ca3af' } } }
    }
  });

  // 4. MITRE ATT&CK Tactics
  const ctxTactic = document.getElementById('chart-tactics').getContext('2d');
  const tacLabels = data.mitre_tactics.map(d => d.mitre_tactic);
  const tacCounts = data.mitre_tactics.map(d => d.count);
  threatChartInstances.tactics = new Chart(ctxTactic, {
    type: 'bar',
    data: {
      labels: tacLabels,
      datasets: [{
        label: 'Observations',
        data: tacCounts,
        backgroundColor: '#8b5cf6',
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: '#9ca3af' }, grid: { color: '#374151' } },
        y: { ticks: { color: '#9ca3af' } }
      },
      plugins: { legend: { display: false } }
    }
  });

  // 5. Risk Score Distribution
  const ctxRisk = document.getElementById('chart-risk-dist').getContext('2d');
  const riskLabels = Object.keys(data.risk_distribution);
  const riskCounts = Object.values(data.risk_distribution);
  threatChartInstances.risk = new Chart(ctxRisk, {
    type: 'bar',
    data: {
      labels: riskLabels,
      datasets: [{
        label: 'Threat Count',
        data: riskCounts,
        backgroundColor: ['#9ca3af', '#10b981', '#3b82f6', '#f59e0b', '#ef4444'],
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: '#9ca3af' } },
        y: { ticks: { color: '#9ca3af' }, grid: { color: '#374151' } }
      },
      plugins: { legend: { display: false } }
    }
  });

  // 6. Threat Status Distribution
  const ctxStatus = document.getElementById('chart-status').getContext('2d');
  const statLabels = data.status_distribution.map(d => d.status);
  const statCounts = data.status_distribution.map(d => d.count);
  threatChartInstances.status = new Chart(ctxStatus, {
    type: 'polarArea',
    data: {
      labels: statLabels,
      datasets: [{
        data: statCounts,
        backgroundColor: [
          'rgba(59, 130, 246, 0.6)',
          'rgba(245, 158, 11, 0.6)',
          'rgba(139, 92, 246, 0.6)',
          'rgba(16, 185, 129, 0.6)',
          'rgba(107, 114, 128, 0.6)'
        ]
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { color: '#9ca3af' } } }
    }
  });
}

// -------------------------------------------------------------
// 2. THREAT INTELLIGENCE FEED & TABLE
// -------------------------------------------------------------
async function loadThreatsTable(page = 1) {
  currentThreatsPage = page;
  const category = document.getElementById('filter-category').value;
  const severity = document.getElementById('filter-severity').value;
  const indType = document.getElementById('filter-indtype').value;
  const status = document.getElementById('filter-status').value;
  const searchQ = document.getElementById('filter-search').value;
  const sortBy = document.getElementById('filter-sort').value;

  const params = new URLSearchParams({
    page: page,
    limit: 15,
    sort: sortBy
  });
  if (category) params.append('category', category);
  if (severity) params.append('severity', severity);
  if (indType) params.append('indicator_type', indType);
  if (status) params.append('status', status);
  if (searchQ) params.append('q', searchQ);

  try {
    const res = await fetch(`${API_BASE}/threats?${params.toString()}`).then(r => r.json());
    if (res.status === 'success') {
      const tbody = document.getElementById('threats-table-body');
      tbody.innerHTML = '';

      res.data.forEach(t => {
        const tr = document.createElement('tr');
        const sevClass = `badge-${t.severity.toLowerCase()}`;
        const statusClass = `badge-status-${t.status.toLowerCase()}`;

        tr.innerHTML = `
          <td><code>${t.threat_id}</code></td>
          <td><b>${escapeHtml(t.threat_name)}</b></td>
          <td><span class="badge" style="background:rgba(255,255,255,0.06); color:#cbd5e1;">${t.category}</span></td>
          <td><code>${escapeHtml(t.indicator_value)}</code> <small style="color:var(--text-muted)">(${t.indicator_type})</small></td>
          <td><span class="badge ${sevClass}">${t.severity}</span></td>
          <td><b>${t.risk_score}</b>/100</td>
          <td>${t.confidence_score}%</td>
          <td><span class="badge ${statusClass}">${t.status}</span></td>
          <td><button class="btn-page" onclick="viewThreatDetails('${t.threat_id}')">Investigate</button></td>
        `;
        tbody.appendChild(tr);
      });

      // Pagination
      document.getElementById('pagination-info').innerText = 
        `Page ${res.pagination.page} of ${res.pagination.total_pages} (${res.pagination.total_records.toLocaleString()} records)`;
      document.getElementById('btn-prev-page').disabled = res.pagination.page <= 1;
      document.getElementById('btn-next-page').disabled = res.pagination.page >= res.pagination.total_pages;
    }
  } catch (err) {
    console.error('Error loading threats table:', err);
  }
}

function applyThreatFilters() {
  loadThreatsTable(1);
}

function resetThreatFilters() {
  document.getElementById('filter-category').value = '';
  document.getElementById('filter-severity').value = '';
  document.getElementById('filter-indtype').value = '';
  document.getElementById('filter-status').value = '';
  document.getElementById('filter-search').value = '';
  document.getElementById('filter-sort').value = 'newest';
  loadThreatsTable(1);
}

function changeThreatPage(delta) {
  loadThreatsTable(currentThreatsPage + delta);
}

// -------------------------------------------------------------
// 3. THREAT INVESTIGATION & DETAILS MODAL
// -------------------------------------------------------------
async function viewThreatDetails(threatId) {
  try {
    const res = await fetch(`${API_BASE}/threats/${threatId}`).then(r => r.json());
    if (res.status === 'success') {
      const data = res.data;
      const rec = data.db_record || {};

      document.getElementById('modal-threat-id').innerText = data.threat_id;
      document.getElementById('modal-threat-name').innerText = data.threat_name;
      document.getElementById('modal-category').innerText = data.category;
      document.getElementById('modal-indicator').innerText = `${data.query} (${data.indicator_type})`;
      document.getElementById('modal-severity').innerHTML = `<span class="badge badge-${data.severity.toLowerCase()}">${data.severity}</span>`;
      document.getElementById('modal-risk').innerText = `${data.risk_score} / 100`;
      document.getElementById('modal-confidence').innerText = `${data.confidence_score} %`;
      document.getElementById('modal-source').innerText = `${data.source_name} (${data.source_reliability})`;
      document.getElementById('modal-dates').innerText = `First Seen: ${data.first_seen} | Last Seen: ${data.last_seen}`;
      document.getElementById('modal-desc').innerText = data.description;

      // MITRE ATT&CK
      const mitre = data.mitre_attack || {};
      document.getElementById('modal-mitre').innerHTML = mitre.tactic ? `
        <b>Tactic:</b> ${mitre.tactic} | <b>Technique:</b> ${mitre.technique} (${mitre.technique_id || 'N/A'})<br>
        <small style="color:var(--text-muted);">${mitre.tactic_description || ''}</small><br>
        <i>Defensive Control:</i> ${mitre.defensive_focus || 'Defense-in-depth monitoring'}
      ` : 'No specific behavioral mapping justified.';

      // Related Indicators
      const relContainer = document.getElementById('modal-related');
      relContainer.innerHTML = '';
      if (data.related_indicators && data.related_indicators.length > 0) {
        data.related_indicators.forEach(rel => {
          const div = document.createElement('div');
          div.style.padding = '0.4rem 0';
          div.innerHTML = `<code>${escapeHtml(rel.indicator_value)}</code> (${rel.indicator_type}) - <span class="badge badge-${rel.severity.toLowerCase()}">${rel.severity}</span> | Reason: ${rel.relation_reason}`;
          relContainer.appendChild(div);
        });
      } else {
        relContainer.innerHTML = '<span style="color:var(--text-muted);">No clustered indicators observed.</span>';
      }

      // Playbooks
      const pbContainer = document.getElementById('modal-playbook');
      pbContainer.innerHTML = '';
      (data.recommended_actions || []).forEach(step => {
        const li = document.createElement('li');
        li.innerText = step;
        pbContainer.appendChild(li);
      });

      // Analyst Notes
      renderAnalystNotes(data.analyst_notes || []);

      // Setup Note Form submission
      const noteBtn = document.getElementById('btn-add-note');
      noteBtn.onclick = () => submitAnalystNote(data.threat_id);

      document.getElementById('threat-detail-modal').style.display = 'flex';
    }
  } catch (err) {
    console.error('Error opening threat modal:', err);
  }
}

function closeModal() {
  document.getElementById('threat-detail-modal').style.display = 'none';
}

function renderAnalystNotes(notes) {
  const container = document.getElementById('modal-notes-list');
  container.innerHTML = '';
  if (notes.length === 0) {
    container.innerHTML = '<span style="color:var(--text-muted);">No analyst notes recorded yet.</span>';
    return;
  }
  notes.forEach(n => {
    const div = document.createElement('div');
    div.style.background = 'rgba(0,0,0,0.2)';
    div.style.padding = '0.6rem';
    div.style.borderRadius = '0.4rem';
    div.style.marginBottom = '0.5rem';
    div.innerHTML = `
      <div style="display:flex; justify-content:space-between; font-size:0.75rem; color:var(--text-muted);">
        <b>${escapeHtml(n.author)}</b> <span>${n.created_at}</span>
      </div>
      <div style="font-size:0.875rem; margin-top:0.2rem;">${escapeHtml(n.note_text)}</div>
    `;
    container.appendChild(div);
  });
}

async function submitAnalystNote(threatId) {
  const noteInput = document.getElementById('input-new-note');
  const noteText = noteInput.value.trim();
  if (!noteText) return;

  try {
    const res = await fetch(`${API_BASE}/threats/${threatId}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note: noteText, author: 'SOC Analyst' })
    }).then(r => r.json());

    if (res.status === 'success') {
      noteInput.value = '';
      renderAnalystNotes(res.data);
    }
  } catch (err) {
    console.error('Error submitting analyst note:', err);
  }
}

// -------------------------------------------------------------
// 4. IOC SEARCH & VALIDATION TOOL
// -------------------------------------------------------------
function initIOCSearch() {
  const btn = document.getElementById('btn-ioc-search');
  const input = document.getElementById('ioc-search-input');

  btn.addEventListener('click', () => performIOCSearch(input.value.trim()));
  input.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') performIOCSearch(input.value.trim());
  });
}

async function performIOCSearch(query) {
  if (!query) return;
  const resultCard = document.getElementById('ioc-search-result');
  resultCard.style.display = 'block';
  resultCard.innerHTML = '<p style="color:var(--accent-cyan);">Validating format and querying local defensive database...</p>';

  try {
    const res = await fetch(`${API_BASE}/indicators/search?q=${encodeURIComponent(query)}`).then(r => r.json());
    if (res.status === 'success') {
      const d = res.data;
      const validBadge = d.is_valid_format
        ? '<span class="badge badge-low">VALID SYNTAX</span>'
        : '<span class="badge badge-critical">INVALID FORMAT</span>';
      
      const knownBadge = d.known_in_dataset
        ? '<span class="badge badge-high">KNOWN IN DATASET</span>'
        : '<span class="badge badge-info">NEW QUERY</span>';

      resultCard.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:1rem; border-bottom:1px solid var(--border-color); padding-bottom:0.75rem;">
          <div>
            <h3 style="font-size:1.2rem; color:var(--text-main); font-family:var(--font-mono);">${escapeHtml(d.query)}</h3>
            <span style="color:var(--text-muted); font-size:0.85rem;">Indicator Type: <b>${d.indicator_type}</b></span>
          </div>
          <div style="display:flex; gap:0.5rem;">${validBadge} ${knownBadge}</div>
        </div>
        
        <p style="font-size:0.85rem; color:var(--text-muted); margin-bottom:1rem;"><i>${escapeHtml(d.validation_notes)}</i></p>

        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:1rem; margin-bottom:1rem;">
          <div class="kpi-card" style="padding:0.75rem;">
            <div class="kpi-title">Calculated Risk</div>
            <div class="kpi-value" style="font-size:1.4rem; color:var(--accent-amber);">${d.risk_score}/100</div>
          </div>
          <div class="kpi-card" style="padding:0.75rem;">
            <div class="kpi-title">Evidence Confidence</div>
            <div class="kpi-value" style="font-size:1.4rem; color:var(--accent-cyan);">${d.confidence_score}%</div>
          </div>
          <div class="kpi-card" style="padding:0.75rem;">
            <div class="kpi-title">Severity Level</div>
            <div class="kpi-value" style="font-size:1.2rem;"><span class="badge badge-${d.severity.toLowerCase()}">${d.severity}</span></div>
          </div>
          <div class="kpi-card" style="padding:0.75rem;">
            <div class="kpi-title">Threat Category</div>
            <div class="kpi-value" style="font-size:1.1rem; color:#cbd5e1;">${d.category}</div>
          </div>
        </div>

        <div style="background:var(--bg-card); padding:1rem; border-radius:0.5rem; margin-bottom:1rem;">
          <h4 style="color:var(--accent-cyan); font-size:0.95rem; margin-bottom:0.4rem;">MITRE ATT&CK Alignment</h4>
          <p style="font-size:0.85rem;"><b>Tactic:</b> ${d.mitre_attack.tactic} | <b>Technique:</b> ${d.mitre_attack.technique} (${d.mitre_attack.technique_id || 'N/A'})</p>
          <p style="font-size:0.8rem; color:var(--text-muted); margin-top:0.2rem;">${d.mitre_attack.defensive_focus}</p>
        </div>

        <div style="background:var(--bg-card); padding:1rem; border-radius:0.5rem;">
          <h4 style="color:var(--accent-green); font-size:0.95rem; margin-bottom:0.4rem;">Recommended Defensive Playbook</h4>
          <ul style="margin-left:1.25rem; font-size:0.85rem; color:var(--text-main);">
            ${d.recommended_actions.map(a => `<li>${a}</li>`).join('')}
          </ul>
        </div>
        
        <div style="font-size:0.75rem; color:var(--text-muted); margin-top:0.75rem;">
          🛡️ <i>${d.offline_safety_guarantee}</i>
        </div>
      `;
    }
  } catch (err) {
    resultCard.innerHTML = `<p style="color:var(--accent-red);">Error processing search: ${err.message}</p>`;
  }
}

// -------------------------------------------------------------
// 5. ALERT MANAGEMENT & SOC TRIAGE
// -------------------------------------------------------------
async function loadAlerts() {
  try {
    const res = await fetch(`${API_BASE}/alerts`).then(r => r.json());
    if (res.status === 'success') {
      const tbody = document.getElementById('alerts-table-body');
      tbody.innerHTML = '';

      res.data.forEach(alt => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><code>${alt.alert_id}</code></td>
          <td><b>${escapeHtml(alt.threat_name)}</b></td>
          <td><code>${escapeHtml(alt.indicator_value)}</code></td>
          <td><span class="badge badge-${alt.severity.toLowerCase()}">${alt.severity}</span></td>
          <td><b>${alt.risk_score}</b>/100</td>
          <td><span class="badge" style="background:rgba(255,255,255,0.1);">${alt.observation_count} obs</span></td>
          <td>
            <select class="filter-select" style="padding:0.2rem 0.4rem; font-size:0.75rem;" onchange="updateAlertStatus('${alt.alert_id}', '${alt.threat_id}', this.value)">
              <option value="NEW" ${alt.status === 'NEW' ? 'selected' : ''}>NEW</option>
              <option value="INVESTIGATING" ${alt.status === 'INVESTIGATING' ? 'selected' : ''}>INVESTIGATING</option>
              <option value="MONITORING" ${alt.status === 'MONITORING' ? 'selected' : ''}>MONITORING</option>
              <option value="RESOLVED" ${alt.status === 'RESOLVED' ? 'selected' : ''}>RESOLVED</option>
              <option value="FALSE_POSITIVE" ${alt.status === 'FALSE_POSITIVE' ? 'selected' : ''}>FALSE_POSITIVE</option>
            </select>
          </td>
          <td><button class="btn-page" onclick="viewThreatDetails('${alt.threat_id}')">Investigate</button></td>
        `;
        tbody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error('Error loading alerts:', err);
  }
}

async function updateAlertStatus(alertId, threatId, newStatus) {
  try {
    await fetch(`${API_BASE}/alerts/${alertId}/status`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus, threat_id: threatId, author: 'SOC Analyst', note: `Updated to ${newStatus}` })
    });
    loadDashboardData();
  } catch (err) {
    console.error('Error updating alert status:', err);
  }
}

// -------------------------------------------------------------
// 6. VULNERABILITY PRIORITIZATION MODULE
// -------------------------------------------------------------
async function loadVulnerabilities() {
  try {
    const res = await fetch(`${API_BASE}/vulnerabilities`).then(r => r.json());
    if (res.status === 'success') {
      const tbody = document.getElementById('vuln-table-body');
      tbody.innerHTML = '';

      res.data.slice(0, 15).forEach(v => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><code>${v.cve_id}</code></td>
          <td><b>${escapeHtml(v.product_name)}</b></td>
          <td><span class="badge badge-${v.severity.toLowerCase()}">${v.severity}</span></td>
          <td><b>${v.cvss_score}</b></td>
          <td>${(v.epss_score * 100).toFixed(1)}%</td>
          <td>${v.known_exploited === 'YES' ? '<span class="badge badge-critical">CISA KEV</span>' : 'No'}</td>
          <td><b style="color:var(--accent-amber);">${v.priority_score}</b>/100</td>
          <td>${v.remediation_guidance}</td>
        `;
        tbody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error('Error loading vulnerabilities:', err);
  }
}

function initVulnCalculator() {
  const btn = document.getElementById('btn-calc-priority');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    const cvss = parseFloat(document.getElementById('calc-cvss').value) || 7.5;
    const epss = parseFloat(document.getElementById('calc-epss').value) || 0.2;
    const isInternet = document.getElementById('calc-internet').checked;
    const isCrit = document.getElementById('calc-critical-asset').checked;
    const isKev = document.getElementById('calc-kev').checked;

    try {
      const res = await fetch(`${API_BASE}/vulnerabilities/prioritize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cvss_score: cvss,
          epss_score: epss,
          is_internet_facing: isInternet,
          is_critical_asset: isCrit,
          known_exploited: isKev
        })
      }).then(r => r.json());

      if (res.status === 'success') {
        const d = res.data;
        document.getElementById('calc-result-box').style.display = 'block';
        document.getElementById('calc-priority-score').innerText = `${d.priority_score} / 100`;
        document.getElementById('calc-priority-tier').innerText = d.priority_tier;
        document.getElementById('calc-sla').innerText = d.recommended_sla;
        document.getElementById('calc-rationale').innerText = d.rationale;
      }
    } catch (err) {
      console.error('Error calculating priority:', err);
    }
  });
}

// -------------------------------------------------------------
// 7. CYBERSECURITY AWARENESS CENTER
// -------------------------------------------------------------
async function loadAwarenessModules() {
  try {
    const res = await fetch(`${API_BASE}/awareness/modules`).then(r => r.json());
    if (res.status === 'success') {
      const container = document.getElementById('awareness-modules-grid');
      container.innerHTML = '';

      res.data.forEach(mod => {
        const card = document.createElement('div');
        card.className = 'awareness-card';
        card.innerHTML = `
          <div>
            <span class="badge" style="background:rgba(6,182,212,0.15); color:var(--accent-cyan); margin-bottom:0.5rem;">${mod.category}</span>
            <h3>${escapeHtml(mod.title)}</h3>
            <p style="font-size:0.875rem; color:var(--text-muted); margin-bottom:0.75rem;">${escapeHtml(mod.summary)}</p>
            
            <div style="font-size:0.8rem; margin-bottom:0.5rem;">
              <b style="color:var(--accent-amber);">⚠️ Warning Signs:</b>
              <ul class="awareness-list">
                ${mod.warning_signs.slice(0, 3).map(w => `<li>${escapeHtml(w)}</li>`).join('')}
              </ul>
            </div>
            
            <div style="font-size:0.8rem;">
              <b style="color:var(--accent-green);">🛡️ Safe Practices:</b>
              <ul class="awareness-list">
                ${mod.safe_practices.slice(0, 2).map(s => `<li>${escapeHtml(s)}</li>`).join('')}
              </ul>
            </div>
          </div>
          <div style="margin-top:1rem; border-top:1px solid var(--border-color); padding-top:0.75rem; font-size:0.75rem; color:var(--text-muted);">
            <b>What to do if targeted:</b> ${escapeHtml(mod.what_to_do)}
          </div>
        `;
        container.appendChild(card);
      });
    }
  } catch (err) {
    console.error('Error loading awareness modules:', err);
  }
}

// -------------------------------------------------------------
// 8. INTERACTIVE SECURITY AWARENESS QUIZ
// -------------------------------------------------------------
async function loadQuiz() {
  try {
    const res = await fetch(`${API_BASE}/quiz`).then(r => r.json());
    if (res.status === 'success') {
      quizQuestions = res.data;
      userQuizAnswers = {};
      currentQuizIndex = 0;
      document.getElementById('quiz-result-box').style.display = 'none';
      document.getElementById('quiz-active-box').style.display = 'block';
      renderQuizQuestion();
    }
  } catch (err) {
    console.error('Error loading quiz:', err);
  }
}

function renderQuizQuestion() {
  if (quizQuestions.length === 0) return;
  const q = quizQuestions[currentQuizIndex];
  const progressPct = ((currentQuizIndex + 1) / quizQuestions.length) * 100;
  document.getElementById('quiz-progress-fill').style.width = `${progressPct}%`;
  document.getElementById('quiz-counter').innerText = `Question ${currentQuizIndex + 1} of ${quizQuestions.length}`;
  document.getElementById('quiz-category-badge').innerText = q.category;
  document.getElementById('quiz-question-text').innerText = q.question;

  const optContainer = document.getElementById('quiz-options-container');
  optContainer.innerHTML = '';

  q.options.forEach((opt, idx) => {
    const div = document.createElement('div');
    div.className = `quiz-option ${userQuizAnswers[q.id] === idx ? 'selected' : ''}`;
    div.innerHTML = `
      <span style="font-weight:700; color:var(--accent-cyan);">${String.fromCharCode(65 + idx)}.</span>
      <span>${escapeHtml(opt)}</span>
    `;
    div.onclick = () => {
      userQuizAnswers[q.id] = idx;
      renderQuizQuestion();
    };
    optContainer.appendChild(div);
  });

  document.getElementById('btn-quiz-prev').disabled = currentQuizIndex === 0;
  document.getElementById('btn-quiz-next').innerText = currentQuizIndex === quizQuestions.length - 1 ? 'Submit Assessment' : 'Next Question';
}

function nextQuizQuestion() {
  if (currentQuizIndex < quizQuestions.length - 1) {
    currentQuizIndex++;
    renderQuizQuestion();
  } else {
    submitQuizAssessment();
  }
}

function prevQuizQuestion() {
  if (currentQuizIndex > 0) {
    currentQuizIndex--;
    renderQuizQuestion();
  }
}

async function submitQuizAssessment() {
  try {
    const res = await fetch(`${API_BASE}/quiz/submit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ answers: userQuizAnswers, user_name: 'Student Defender' })
    }).then(r => r.json());

    if (res.status === 'success') {
      const d = res.data;
      document.getElementById('quiz-active-box').style.display = 'none';
      const resBox = document.getElementById('quiz-result-box');
      resBox.style.display = 'block';

      document.getElementById('quiz-score-display').innerText = `${d.overall_score}%`;
      document.getElementById('quiz-tier-display').innerText = d.tier;
      document.getElementById('quiz-summary-display').innerText = d.summary;

      // Category Scores
      const catList = document.getElementById('quiz-category-breakdown');
      catList.innerHTML = '';
      Object.entries(d.category_scores).forEach(([cat, data]) => {
        const div = document.createElement('div');
        div.style.background = 'var(--bg-card)';
        div.style.padding = '0.75rem';
        div.style.borderRadius = '0.4rem';
        div.style.marginBottom = '0.5rem';
        div.innerHTML = `
          <div style="display:flex; justify-content:space-between;">
            <b>${cat}</b>
            <span>${data.correct} / ${data.total} (${data.percentage}%)</span>
          </div>
          <div style="background:rgba(0,0,0,0.3); height:6px; border-radius:3px; margin-top:0.4rem; overflow:hidden;">
            <div style="background:${data.percentage >= 70 ? 'var(--accent-green)' : 'var(--accent-amber)'}; height:100%; width:${data.percentage}%;"></div>
          </div>
        `;
        catList.appendChild(div);
      });

      // Recommendations
      const recList = document.getElementById('quiz-recommendations-list');
      recList.innerHTML = '';
      d.recommendations.forEach(rec => {
        const li = document.createElement('li');
        li.style.marginBottom = '0.5rem';
        li.innerHTML = `<b>[${rec.priority}] ${rec.module_title}:</b> ${rec.reason}`;
        recList.appendChild(li);
      });

      loadDashboardData();
    }
  } catch (err) {
    console.error('Error submitting quiz:', err);
  }
}

// -------------------------------------------------------------
// 9. EXECUTIVE SUMMARY
// -------------------------------------------------------------
async function loadExecutiveSummary() {
  try {
    const res = await fetch(`${API_BASE}/executive/summary`).then(r => r.json());
    if (res.status === 'success') {
      const d = res.data;
      document.getElementById('exec-summary-text').innerText = d.threat_posture_summary;
      document.getElementById('exec-high-crit-count').innerText = d.critical_and_high_threats;
      document.getElementById('exec-awareness-rating').innerText = `${d.organization_awareness_health.rating} (${d.organization_awareness_health.average_score}%)`;

      const recList = document.getElementById('exec-recommendations');
      recList.innerHTML = '';
      d.executive_recommendations.forEach(r => {
        const li = document.createElement('li');
        li.style.marginBottom = '0.5rem';
        li.innerText = r;
        recList.appendChild(li);
      });
    }
  } catch (err) {
    console.error('Error loading executive summary:', err);
  }
}

// Utility: Escape HTML
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
