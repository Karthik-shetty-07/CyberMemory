/**
 * CyberMemory AI — Memory Explorer Controller
 * Author: Frontend & Dashboard Engineering
 */

let allMemories = [];

document.addEventListener('DOMContentLoaded', () => {
  loadMemories();
});

async function loadMemories(query = '') {
  const container = document.getElementById('memories-grid-container');
  if (container) {
    container.innerHTML = `<div class="col-12 text-center text-muted-custom py-5"><span class="spinner-border spinner-border-sm text-cyan me-2"></span> Searching Hindsight memory bank...</div>`;
  }

  try {
    const data = await CyberMemoryAPI.searchMemory(query, 50);
    allMemories = data.results || [];

    const countEl = document.getElementById('retained-count');
    if (countEl) countEl.textContent = allMemories.length;

    renderMemoriesGrid(allMemories);
    renderRemediations(allMemories);
    renderPatterns(allMemories);
  } catch (err) {
    console.error('Failed to load memories:', err);
    if (container) {
      container.innerHTML = `<div class="col-12 text-center text-danger py-4">Error loading memory bank: ${err.message}</div>`;
    }
  }
}

function executeMemorySearch() {
  const q = document.getElementById('memory-search-input')?.value.trim() || '';
  loadMemories(q);
}

function quickMemorySearch(term) {
  const input = document.getElementById('memory-search-input');
  if (input) input.value = term;
  loadMemories(term);
}

function renderMemoriesGrid(memories) {
  const container = document.getElementById('memories-grid-container');
  if (!container) return;

  if (memories.length === 0) {
    container.innerHTML = `
      <div class="col-12 text-center py-5">
        <i class="bi bi-inbox text-muted fs-2 d-block mb-2"></i>
        <span class="text-muted-custom">No memory records found matching this semantic query.</span>
      </div>
    `;
    return;
  }

  container.innerHTML = memories.map(mem => {
    const sevClass = `sev-${(mem.severity || 'low').toLowerCase()}`;
    const indicators = mem.indicators || {};
    const procs = (indicators.processes || []).slice(0, 2).join(', ');

    return `
      <div class="col-12 col-md-6 col-xl-4">
        <div class="soc-card h-100 d-flex flex-column justify-content-between" style="background: rgba(15, 26, 46, 0.75);">
          <div>
            <div class="d-flex justify-content-between align-items-center mb-2">
              <span class="font-mono text-cyan fw-bold" style="font-size: 0.8rem;">
                <i class="bi bi-database-check me-1"></i>${mem.memory_id}
              </span>
              <span class="sev-badge ${sevClass}">${mem.severity}</span>
            </div>

            <h4 class="text-white h6 mb-2" style="font-size: 0.92rem; line-height: 1.4;">
              ${escapeHtml(mem.title)}
            </h4>

            <div class="mb-2" style="font-size: 0.75rem;">
              <span class="text-dim">Host:</span>
              <span class="font-mono text-white ms-1">${escapeHtml(mem.affected_host || 'N/A')}</span>
              <span class="text-dim ms-2">| Type:</span>
              <span class="text-muted-custom ms-1">${escapeHtml(mem.alert_type)}</span>
            </div>

            <p class="text-muted-custom small mb-3" style="font-size: 0.78rem; line-height: 1.5; display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden;">
              ${escapeHtml(mem.summary || '')}
            </p>

            <div class="p-2 rounded mb-3" style="background: rgba(11, 18, 32, 0.6); border-left: 2px solid var(--accent-cyan); font-size: 0.74rem;">
              <span class="text-dim d-block mb-1">Root Cause & Remediation:</span>
              <span class="text-white">${escapeHtml(mem.root_cause || mem.remediation || 'Standard procedure applied.')}</span>
            </div>
          </div>

          <div class="d-flex justify-content-between align-items-center pt-2 border-top" style="border-color: rgba(56, 189, 248, 0.08) !important;">
            <span class="font-mono" style="font-size: 0.7rem; color: #64748B;">
              ${CyberSOC.formatDate(mem.retained_at)}
            </span>
            <button class="btn-soc-secondary" style="padding: 0.25rem 0.65rem; font-size: 0.75rem;" onclick="openMemoryModal('${mem.memory_id}')">
              Inspect Node <i class="bi bi-zoom-in"></i>
            </button>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

function renderRemediations(memories) {
  const container = document.getElementById('remediations-list');
  if (!container) return;

  const valid = memories.filter(m => m.remediation && m.remediation.length > 10);
  if (valid.length === 0) {
    container.innerHTML = `<p class="text-muted-custom small">No remediation procedures indexed yet.</p>`;
    return;
  }

  container.innerHTML = valid.map(m => `
    <div class="p-3 rounded" style="background: rgba(11, 18, 32, 0.6); border: 1px solid rgba(16, 185, 129, 0.2);">
      <div class="d-flex justify-content-between align-items-center mb-1">
        <span class="fw-bold text-white" style="font-size: 0.88rem;">${escapeHtml(m.alert_type)}: ${escapeHtml(m.title)}</span>
        <span class="font-mono text-cyan small">${m.memory_id}</span>
      </div>
      <p class="text-success small mb-2"><i class="bi bi-shield-check me-1"></i> ${escapeHtml(m.remediation)}</p>
      ${m.lessons_learned ? `<div style="font-size: 0.75rem; color: var(--text-muted);"><span class="text-dim">Lesson Learned:</span> "${escapeHtml(m.lessons_learned)}"</div>` : ''}
    </div>
  `).join('');
}

function renderPatterns(memories) {
  const container = document.getElementById('patterns-list');
  if (!container) return;

  // Synthesize recurring categories
  const categoryCounts = {};
  memories.forEach(m => {
    categoryCounts[m.alert_type] = (categoryCounts[m.alert_type] || 0) + 1;
  });

  const patterns = Object.entries(categoryCounts).map(([type, count]) => ({
    type,
    count,
    sample: memories.find(m => m.alert_type === type)
  }));

  container.innerHTML = patterns.map(p => `
    <div class="p-3 rounded" style="background: rgba(11, 18, 32, 0.6); border: 1px solid rgba(234, 179, 8, 0.2);">
      <div class="d-flex justify-content-between align-items-center mb-2">
        <span class="fw-bold text-white">${escapeHtml(p.type)}</span>
        <span class="badge" style="background: rgba(234, 179, 8, 0.15); color: #FDE047; font-size: 0.74rem;">
          ${p.count} Historical Occurrence${p.count === 1 ? '' : 's'} Retained
        </span>
      </div>
      <p class="text-muted-custom small mb-1">
        <strong>Typical Root Cause:</strong> ${escapeHtml(p.sample?.root_cause || 'Pattern correlated across sessions')}
      </p>
      <div style="font-size: 0.75rem; color: var(--accent-cyan);">
        <i class="bi bi-arrow-right-short"></i> Memory enables instant triage whenever similar payloads appear on any workstation.
      </div>
    </div>
  `).join('');
}

function openMemoryModal(memId) {
  const mem = allMemories.find(m => m.memory_id === memId);
  if (!mem) return;

  document.getElementById('modal-memory-id').textContent = mem.memory_id;
  document.getElementById('modal-memory-title').textContent = `| ${mem.title}`;

  const linkBtn = document.getElementById('modal-view-incident-btn');
  if (linkBtn) linkBtn.href = `/investigation/${mem.incident_id}`;

  const bodyEl = document.getElementById('modal-memory-body');
  if (!bodyEl) return;

  const indicators = mem.indicators || {};

  bodyEl.innerHTML = `
    <div class="mb-3">
      <span class="soc-label">Memory Vector Summary</span>
      <p class="text-white small mb-0">${escapeHtml(mem.summary)}</p>
    </div>

    <div class="row g-3 mb-3">
      <div class="col-6">
        <span class="soc-label">Origin Host</span>
        <span class="font-mono text-cyan small">${escapeHtml(mem.affected_host || 'N/A')}</span>
      </div>
      <div class="col-6">
        <span class="soc-label">Retained Timestamp</span>
        <span class="font-mono text-muted-custom small">${CyberSOC.formatDate(mem.retained_at)}</span>
      </div>
    </div>

    <div class="mb-3 p-3 rounded" style="background: rgba(11, 18, 32, 0.8); border: 1px solid var(--border-color);">
      <span class="soc-label text-success mb-1">Verified Root Cause</span>
      <p class="text-white small mb-2">${escapeHtml(mem.root_cause)}</p>

      <span class="soc-label text-cyan mb-1">Proven Remediation Action</span>
      <p class="text-white small mb-0">${escapeHtml(mem.remediation)}</p>
    </div>

    <div class="mb-3">
      <span class="soc-label">Indexed Indicators (IOCs)</span>
      <div class="d-flex flex-wrap gap-2 mt-1">
        ${(indicators.ips || []).map(ip => `<span class="ioc-chip"><i class="bi bi-hdd-network"></i> ${ip}</span>`).join('')}
        ${(indicators.domains || []).map(dom => `<span class="ioc-chip"><i class="bi bi-globe"></i> ${dom}</span>`).join('')}
        ${(indicators.processes || []).map(prc => `<span class="ioc-chip" style="color: #F87171;"><i class="bi bi-terminal"></i> ${prc}</span>`).join('')}
        ${(indicators.mitre_techniques || []).map(t => `<span class="mitre-badge">${t}</span>`).join('')}
      </div>
    </div>

    ${mem.lessons_learned ? `
      <div>
        <span class="soc-label">Long-Term Defense Recommendation</span>
        <p class="text-cyan small mb-0 font-italic">"${escapeHtml(mem.lessons_learned)}"</p>
      </div>
    ` : ''}
  `;

  const modalEl = document.getElementById('memoryDetailModal');
  const modal = new bootstrap.Modal(modalEl);
  modal.show();
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
