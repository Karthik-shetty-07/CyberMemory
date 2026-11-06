/**
 * Dashboard view. Reads the shared /api/dashboard/stats contract and
 * fills the recent table from /api/incidents when the stats payload
 * does not include a recent list yet.
 */

document.addEventListener('DOMContentLoaded', () => {
  loadDashboardData();
  bindRangeControls();
  initCalendar();
});

let dashState = {
  growth: [],
  range: 'month'
};

async function loadDashboardData() {
  try {
    const data = await CyberMemoryAPI.getDashboardStats();
    if (window.paintBackendStatus) window.paintBackendStatus(data);
    renderKpis(data);
    dashState.growth = data.memory_growth || [];
    renderGrowthChart();
    renderRecallRing(data);

    let recent = data.recent_investigations || [];
    if (!recent.length) {
      const list = await CyberMemoryAPI.getIncidents();
      recent = (list.incidents || []).slice(0, 6);
    }
    renderRecentTable(recent);
  } catch (err) {
    console.error('Failed to load dashboard data:', err);
    CyberSOC.showToast('Could not load dashboard data from the API.', 'error');
    const body = document.getElementById('recent-investigations-body');
    if (body) {
      body.innerHTML = '<tr><td colspan="5" class="empty-note">The dashboard API did not respond.</td></tr>';
    }
  }
}

function renderKpis(data) {
  setText('kpi-total-investigated', formatNumber(data.total_investigated));
  setText('kpi-memory-stored', formatNumber(data.memory_items_stored));
  setText('kpi-resolved-incidents', formatNumber(data.resolved_incidents));
  setText('kpi-satisfaction-rate', `${trimNumber(data.feedback_satisfaction_rate)}%`);

  const severity = data.severity_breakdown || {};
  const critical = severity.Critical || 0;
  const bank = (data.system_status && data.system_status.hindsight_bank) || 'memory bank';
  const deltas = data.deltas || {};

  setFoot('kpi-total-foot', deltas.total_investigated, critical
    ? `${critical} critical still in the queue`
    : 'Cases in the investigation store');
  setFoot('kpi-memory-foot', deltas.memory_items_stored, `Stored in ${bank}`);
  setFoot('kpi-resolved-foot', deltas.resolved_incidents, 'Confirmed or cleared');
  setFoot('kpi-satisfaction-foot', deltas.feedback_satisfaction_rate, 'From analyst feedback');
}

function setFoot(id, delta, fallback) {
  const el = document.getElementById(id);
  if (!el) return;
  if (delta === undefined || delta === null || delta === '') {
    el.textContent = fallback;
    return;
  }
  const value = Number(delta);
  const up = value >= 0;
  el.innerHTML = `<span class="delta-up">${up ? '▲' : '▼'} ${Math.abs(trimNumber(value))}% from last period</span>`;
}

function bindRangeControls() {
  document.querySelectorAll('.range-pills button').forEach((button) => {
    button.addEventListener('click', () => {
      document.querySelectorAll('.range-pills button').forEach((item) => item.classList.remove('active'));
      button.classList.add('active');
      dashState.range = button.dataset.range;
      renderGrowthChart();
    });
  });
}

function renderGrowthChart() {
  const container = document.getElementById('chart-memory-growth');
  const label = document.getElementById('dash-date-label');
  if (!container) return;

  const points = sliceGrowth(dashState.growth, dashState.range);
  if (!points.length) {
    container.innerHTML = '<div class="empty-note">No memory growth series in this response.</div>';
    if (label) label.textContent = 'No dated series';
    return;
  }

  const max = Math.max(...points.map((point) => point.nodes), 1);
  const ticks = [max, Math.round(max / 2), 0];
  if (label) {
    label.textContent = `${formatShortDate(points[0].date)} – ${formatShortDate(points[points.length - 1].date)}`;
  }

  const shades = ['', 'mid', 'alt', '', 'mid', 'alt'];
  container.innerHTML = `
    <div class="bar-axis">
      ${ticks.map((tick) => `<span>${formatCompact(tick)}</span>`).join('')}
    </div>
    <div class="bar-plot">
      ${points.map((point, index) => `
        <div class="bar-col">
          <div class="bar ${shades[index % shades.length]}" style="height:${Math.max(8, Math.round((point.nodes / max) * 168))}px" title="${point.nodes} memories"></div>
          <span>${formatBarLabel(point.date)}</span>
        </div>
      `).join('')}
    </div>
  `;
}

function sliceGrowth(points, range) {
  if (!points.length) return [];
  if (range === 'year') return points;
  const last = new Date(points[points.length - 1].date);
  if (Number.isNaN(last.getTime())) return points;
  const windowDays = range === 'day' ? 1 : range === 'week' ? 7 : 31;
  const start = new Date(last);
  start.setDate(start.getDate() - (windowDays - 1));
  const sliced = points.filter((point) => {
    const date = new Date(point.date);
    return !Number.isNaN(date.getTime()) && date >= start && date <= last;
  });
  return sliced.length ? sliced : points.slice(-windowDays);
}

function renderRecallRing(data) {
  const total = Number(data.total_investigated) || 0;
  const resolved = Number(data.resolved_incidents) || 0;
  const pct = total ? Math.round((resolved / total) * 100) : Math.round(data.feedback_satisfaction_rate || 0);
  const ring = document.getElementById('recall-ring');
  const ringLabel = document.getElementById('recall-ring-label');
  const caption = document.getElementById('recall-caption');
  if (ring) ring.style.setProperty('--pct', String(pct));
  if (ringLabel) ringLabel.textContent = `${pct}%`;
  if (caption) {
    caption.textContent = total
      ? `${formatNumber(resolved)} of ${formatNumber(total)} incidents have a recorded outcome`
      : 'Outcome coverage appears once incidents are loaded';
  }
}

function renderRecentTable(incidents) {
  const tbody = document.getElementById('recent-investigations-body');
  if (!tbody) return;
  if (!incidents || !incidents.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-note">No investigations yet.</td></tr>';
    return;
  }

  tbody.innerHTML = incidents.slice(0, 6).map((inc) => {
    const outcome = inc.final_outcome || 'In progress';
    const pill = outcome === 'Confirmed Malicious'
      ? 'status-pill'
      : (outcome === 'False Positive' ? 'status-pill soft' : 'status-pill line');
    const label = outcome === 'Confirmed Malicious' ? 'Malicious' : (outcome === 'False Positive' ? 'Cleared' : 'Open');
    return `
      <tr>
        <td>
          <div class="incident-cell">
            <span class="incident-thumb"><i class="bi bi-shield"></i></span>
            <span>${escapeHtml(inc.title || 'Untitled incident')}</span>
          </div>
        </td>
        <td>${escapeHtml(inc.affected_host || '—')}</td>
        <td class="font-mono">${escapeHtml(inc.id || '')}</td>
        <td><span class="sev-badge sev-${(inc.severity || 'low').toLowerCase()}">${escapeHtml(inc.severity || 'Low')}</span></td>
        <td><a class="${pill}" href="/investigation/${encodeURIComponent(inc.id || '')}">${label}</a></td>
      </tr>
    `;
  }).join('');
}

let calCursor = startOfWeek(new Date());

function initCalendar() {
  renderCalendar();
  const prev = document.getElementById('cal-prev');
  const next = document.getElementById('cal-next');
  if (prev) prev.addEventListener('click', () => { calCursor.setDate(calCursor.getDate() - 7); renderCalendar(); });
  if (next) next.addEventListener('click', () => { calCursor.setDate(calCursor.getDate() + 7); renderCalendar(); });
}

function renderCalendar() {
  const grid = document.getElementById('dash-calendar');
  const label = document.getElementById('cal-label');
  if (!grid) return;
  const today = new Date();
  if (label) {
    label.textContent = calCursor.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
  }
  const dows = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  let html = dows.map((dow) => `<div class="cal-dow">${dow}</div>`).join('');
  for (let i = 0; i < 7; i += 1) {
    const day = new Date(calCursor);
    day.setDate(calCursor.getDate() + i);
    const isToday = today.toDateString() === day.toDateString();
    html += `<div class="cal-day${isToday ? ' is-today' : ''}">${day.getDate()}</div>`;
  }
  grid.innerHTML = html;
}

function startOfWeek(date) {
  const copy = new Date(date);
  copy.setHours(0, 0, 0, 0);
  copy.setDate(copy.getDate() - copy.getDay());
  return copy;
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString('en-US');
}

function trimNumber(value) {
  const number = Number(value || 0);
  return Number.isInteger(number) ? number : Math.round(number * 10) / 10;
}

function formatCompact(value) {
  if (value >= 1000) return `${Math.round(value / 100) / 10}k`;
  return String(value);
}

function formatShortDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value || '';
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function formatBarLabel(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value || '';
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
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
