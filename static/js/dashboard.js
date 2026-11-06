/**
 * CyberMemory AI — Dashboard Controller
 * Author: Frontend & Dashboard Engineering
 */

document.addEventListener('DOMContentLoaded', () => {
  loadDashboardData();
});

async function loadDashboardData() {
  try {
    const data = await CyberMemoryAPI.getDashboardStats();
    renderKpis(data);
    renderSeverityChart(data.severity_breakdown);
    renderMemoryGrowthChart(data.memory_growth);
    renderRecentTable(data.recent_investigations);

    if (data.system_status && data.system_status.hindsight_bank) {
      const bankEl = document.getElementById('sidebar-bank-id');
      if (bankEl) bankEl.textContent = data.system_status.hindsight_bank;
    }
  } catch (err) {
    console.error('Failed to load dashboard data:', err);
    CyberSOC.showToast('Failed to load dashboard metrics. Re-attempting in standalone mode...', 'error');
  }
}

function renderKpis(data) {
  const totalEl = document.getElementById('kpi-total-investigated');
  const memEl = document.getElementById('kpi-memory-stored');
  const resEl = document.getElementById('kpi-resolved-incidents');
  const satEl = document.getElementById('kpi-satisfaction-rate');

  if (totalEl) totalEl.textContent = data.total_investigated ?? 0;
  if (memEl) memEl.textContent = data.memory_items_stored ?? 0;
  if (resEl) resEl.textContent = data.resolved_incidents ?? 0;
  if (satEl) satEl.textContent = `${data.feedback_satisfaction_rate ?? 95}%`;
}

function renderSeverityChart(severity) {
  const container = document.getElementById('chart-severity');
  if (!container || !window.Plotly) return;

  const values = [
    severity['Critical'] || 0,
    severity['High'] || 0,
    severity['Medium'] || 0,
    severity['Low'] || 0
  ];

  const labels = ['Critical', 'High', 'Medium', 'Low'];
  const colors = ['#EF4444', '#F97316', '#EAB308', '#10B981'];

  const plotData = [{
    values: values,
    labels: labels,
    type: 'pie',
    hole: 0.65,
    marker: {
      colors: colors,
      line: { color: '#070B14', width: 2 }
    },
    textinfo: 'value+percent',
    hoverinfo: 'label+value+percent',
    textfont: { family: 'Inter', color: '#FFFFFF', size: 12 }
  }];

  const layout = {
    paper_bgcolor: 'transparent',
    plot_bgcolor: 'transparent',
    showlegend: true,
    legend: {
      orientation: 'h',
      x: 0,
      y: -0.15,
      font: { color: '#94A3B8', size: 11, family: 'Inter' }
    },
    margin: { t: 15, b: 35, l: 15, r: 15 },
    annotations: [{
      font: { size: 14, color: '#FFFFFF', family: 'Inter', weight: 'bold' },
      showarrow: false,
      text: `${values.reduce((a, b) => a + b, 0)} Total`,
      x: 0.5,
      y: 0.5
    }]
  };

  const config = { responsive: true, displayModeBar: false };
  Plotly.newPlot('chart-severity', plotData, layout, config);
}

function renderMemoryGrowthChart(growthData) {
  const container = document.getElementById('chart-memory-growth');
  if (!container || !window.Plotly || !growthData) return;

  const dates = growthData.map(d => d.date);
  const nodes = growthData.map(d => d.nodes);
  const retrievals = growthData.map(d => d.retrievals);

  const traceNodes = {
    x: dates,
    y: nodes,
    name: 'Retained Nodes',
    type: 'scatter',
    mode: 'lines+markers',
    fill: 'tozeroy',
    fillcolor: 'rgba(0, 242, 254, 0.08)',
    line: { color: '#00F2FE', width: 2.5, shape: 'spline' },
    marker: { size: 6, color: '#00F2FE' }
  };

  const traceRetrievals = {
    x: dates,
    y: retrievals,
    name: 'Investigation Retrievals',
    type: 'scatter',
    mode: 'lines+markers',
    line: { color: '#38BDF8', width: 2, dash: 'dot', shape: 'spline' },
    marker: { size: 5, color: '#38BDF8' }
  };

  const layout = {
    paper_bgcolor: 'transparent',
    plot_bgcolor: 'transparent',
    margin: { t: 20, b: 35, l: 35, r: 20 },
    legend: {
      orientation: 'h',
      x: 0,
      y: 1.15,
      font: { color: '#94A3B8', size: 11, family: 'Inter' }
    },
    xaxis: {
      gridcolor: 'rgba(56, 189, 248, 0.06)',
      tickfont: { color: '#64748B', size: 10, family: 'JetBrains Mono' },
      zeroline: false
    },
    yaxis: {
      gridcolor: 'rgba(56, 189, 248, 0.06)',
      tickfont: { color: '#64748B', size: 10, family: 'JetBrains Mono' },
      zeroline: false
    }
  };

  const config = { responsive: true, displayModeBar: false };
  Plotly.newPlot('chart-memory-growth', [traceNodes, traceRetrievals], layout, config);
}

function renderRecentTable(incidents) {
  const tbody = document.getElementById('recent-investigations-body');
  if (!tbody) return;

  if (!incidents || incidents.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted py-4">No recent investigations found.</td></tr>`;
    return;
  }

  tbody.innerHTML = incidents.map(inc => {
    const sevClass = `sev-${(inc.severity || 'low').toLowerCase()}`;
    const outcomeClass = inc.final_outcome === 'Confirmed Malicious' ? 'outcome-malicious'
      : (inc.final_outcome === 'False Positive' ? 'outcome-fp' : 'outcome-investigating');

    return `
      <tr>
        <td class="font-mono text-cyan fw-semibold">${inc.id}</td>
        <td><span class="sev-badge ${sevClass}">${inc.severity}</span></td>
        <td class="fw-medium text-white">${escapeHtml(inc.title)}</td>
        <td class="font-mono" style="color: #BAE6FD;">${escapeHtml(inc.affected_host || 'N/A')}</td>
        <td><span style="font-size: 0.78rem; color: #94A3B8;">${escapeHtml(inc.alert_type || 'General')}</span></td>
        <td><span class="outcome-badge ${outcomeClass}">${escapeHtml(inc.final_outcome || 'In Progress')}</span></td>
        <td class="font-mono" style="font-size: 0.75rem; color: #64748B;">${CyberSOC.formatDate(inc.timestamp)}</td>
        <td>
          <a href="/investigation/${inc.id}" class="btn-soc-secondary" style="padding: 0.25rem 0.6rem; font-size: 0.75rem;">
            Inspect <i class="bi bi-box-arrow-up-right"></i>
          </a>
        </td>
      </tr>
    `;
  }).join('');
}

function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
