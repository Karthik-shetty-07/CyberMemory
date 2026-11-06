/**
 * CyberMemory AI — Incident History Controller
 * Author: Frontend & Dashboard Engineering
 */

let allLoadedIncidents = [];
let searchDebounceTimer = null;

document.addEventListener('DOMContentLoaded', () => {
  filterIncidents();
});

function debounceSearch() {
  clearTimeout(searchDebounceTimer);
  searchDebounceTimer = setTimeout(() => {
    filterIncidents();
  }, 250);
}

async function filterIncidents() {
  const query = document.getElementById('search-input')?.value.trim() || '';
  const severity = document.getElementById('filter-severity')?.value || 'all';
  const type = document.getElementById('filter-type')?.value || 'all';
  const outcome = document.getElementById('filter-outcome')?.value || 'all';

  const tbody = document.getElementById('history-table-body');
  if (tbody) {
    tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted-custom py-4"><span class="spinner-border spinner-border-sm text-cyan me-2"></span> Filtering incident database...</td></tr>`;
  }

  try {
    const data = await CyberMemoryAPI.getIncidents({ query, severity, type, outcome });
    allLoadedIncidents = data.incidents || [];
    renderHistoryTable(allLoadedIncidents);
  } catch (err) {
    console.error('Failed to filter incidents:', err);
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="9" class="text-center text-danger py-4">Error loading archive: ${err.message}</td></tr>`;
    }
  }
}

function resetFilters() {
  if (document.getElementById('search-input')) document.getElementById('search-input').value = '';
  if (document.getElementById('filter-severity')) document.getElementById('filter-severity').value = 'all';
  if (document.getElementById('filter-type')) document.getElementById('filter-type').value = 'all';
  if (document.getElementById('filter-outcome')) document.getElementById('filter-outcome').value = 'all';
  filterIncidents();
}

function renderHistoryTable(incidents) {
  const tbody = document.getElementById('history-table-body');
  const countBadge = document.getElementById('incident-count-badge');

  if (countBadge) {
    countBadge.textContent = `${incidents.length} Incident${incidents.length === 1 ? '' : 's'}`;
  }

  if (!tbody) return;

  if (incidents.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="9" class="text-center py-5">
          <i class="bi bi-inbox text-muted fs-3 d-block mb-2"></i>
          <span class="text-muted-custom">No incidents match the specified search or filter criteria.</span>
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = incidents.map(inc => {
    const sevClass = `sev-${(inc.severity || 'low').toLowerCase()}`;
    const outcomeClass = inc.final_outcome === 'Confirmed Malicious' ? 'outcome-malicious'
      : (inc.final_outcome === 'False Positive' ? 'outcome-fp' : 'outcome-investigating');

    const feedback = inc.analyst_feedback || {};
    const feedbackHtml = feedback.rating === 'Helpful' ? '<span class="text-success small"><i class="bi bi-hand-thumbs-up-fill me-1"></i>Helpful</span>'
      : (feedback.rating === 'Partially Helpful' ? '<span class="text-warning small"><i class="bi bi-dash-circle me-1"></i>Partial</span>'
      : (feedback.rating === 'Not Helpful' ? '<span class="text-danger small"><i class="bi bi-hand-thumbs-down-fill me-1"></i>Unhelpful</span>' : '<span class="text-dim small">Pending</span>'));

    return `
      <tr>
        <td class="font-mono text-cyan fw-semibold">${inc.id}</td>
        <td><span class="sev-badge ${sevClass}">${inc.severity}</span></td>
        <td>
          <div class="fw-semibold text-white">${escapeHtml(inc.title)}</div>
          <div class="text-dim small text-truncate" style="max-width: 320px;">${escapeHtml(inc.description || '')}</div>
        </td>
        <td class="font-mono" style="color: #3f3f46;">${escapeHtml(inc.affected_host || 'N/A')}</td>
        <td><span style="font-size: 0.76rem; color: #71717a;">${escapeHtml(inc.alert_type || 'General')}</span></td>
        <td><span class="outcome-badge ${outcomeClass}">${escapeHtml(inc.final_outcome || 'In Progress')}</span></td>
        <td>${feedbackHtml}</td>
        <td class="font-mono" style="font-size: 0.72rem; color: #64748B;">${CyberSOC.formatDate(inc.timestamp)}</td>
        <td>
          <a href="/investigation/${inc.id}" class="btn-soc-secondary" style="padding: 0.25rem 0.6rem; font-size: 0.75rem;">
            Inspect <i class="bi bi-arrow-right"></i>
          </a>
        </td>
      </tr>
    `;
  }).join('');
}

function exportIncidentsJson() {
  if (!allLoadedIncidents || allLoadedIncidents.length === 0) {
    CyberSOC.showToast('No incidents to export.', 'error');
    return;
  }

  const jsonStr = JSON.stringify(allLoadedIncidents, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `cybermemory_incidents_${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  CyberSOC.showToast('Exported incidents archive as JSON.');
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

