
/**
 * CyberMemory AI — Unified Frontend API Client
 * Author: Frontend & Dashboard Engineering
 * Handles communication with Flask/FastAPI backend with built-in resilience.
 */

const CyberMemoryAPI = {
  baseUrl: '',

  /**
   * Helper for fetch with JSON parsing and standardized error handling
   */
  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;

    const defaultHeaders = {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    };

    const config = {
      ...options,
      headers: {
        ...defaultHeaders,
        ...(options.headers || {})
      }
    };

    try {
      const response = await fetch(url, config);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({
          message: response.statusText
        }));

        throw new Error(
          errorData.error ||
          errorData.message ||
          `HTTP ${response.status}`
        );
      }

      return await response.json();

    } catch (err) {
      console.error(`[CyberMemoryAPI] Error fetching ${url}:`, err);
      throw err;
    }
  },

  /**
   * 1. Get Dashboard Summary Statistics
   */
  async getDashboardStats() {
    try {
      const data = await this.request('/api/dashboard/stats');
      return normalizeDashboardStats(data);

    } catch (err) {
      console.error(
        '[CyberMemoryAPI] Failed to load dashboard statistics:',
        err
      );
      throw err;
    }
  },

  /**
   * 2. Get Historical Incidents with optional query filters
   */
  async getIncidents(params = {}) {
    const searchParams = new URLSearchParams();

    if (params.query) searchParams.set('query', params.query);
    if (params.severity && params.severity !== 'all') {
      searchParams.set('severity', params.severity);
    }
    if (params.type && params.type !== 'all') {
      searchParams.set('type', params.type);
    }
    if (params.outcome && params.outcome !== 'all') {
      searchParams.set('outcome', params.outcome);
    }

    const queryString = searchParams.toString();

    return this.request(
      `/api/incidents${queryString ? '?' + queryString : ''}`
    );
  },

  /**
   * 3. Get single incident detail by ID
   */
  async getIncidentDetail(id) {
    return this.request(`/api/incidents/${encodeURIComponent(id)}`);
  },

  /**
   * 4. Submit New Security Alert for AI Analysis & Memory Correlation
   */
  async investigate(payload) {
    return this.request('/api/investigate', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
  },

  /**
   * 5. Record Analyst Feedback & Retain Experience into Hindsight Memory
   */
  async submitFeedback(incidentId, feedback) {
    return this.request(
      `/api/investigation/${encodeURIComponent(incidentId)}/feedback`,
      {
        method: 'POST',
        body: JSON.stringify(feedback)
      }
    );
  },

  /**
   * 6. Search Hindsight Persistent Memory
   */
  async searchMemory(query = '', limit = 10) {
    const params = new URLSearchParams();

    if (query) params.set('q', query);
    if (limit) params.set('limit', limit);

    return this.request(`/api/memory/search?${params.toString()}`);
  },

  /**
   * 7. Get Learning Analytics Progression
   */
  async getLearningAnalytics() {
    return this.request('/api/analytics/learning');
  }
};


// Global utility functions for formatting and copying
window.CyberSOC = {

  formatDate(isoString) {
    if (!isoString) return 'N/A';

    try {
      const d = new Date(isoString);

      return d.toLocaleDateString('en-US', {
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        timeZoneName: 'short'
      });

    } catch {
      return isoString;
    }
  },

  copyToClipboard(text, btnElement) {
    if (!navigator.clipboard) {
      const textarea = document.createElement('textarea');

      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();

      document.execCommand('copy');
      document.body.removeChild(textarea);

      this.showToast('Copied to clipboard');
      return;
    }

    navigator.clipboard.writeText(text).then(() => {
      this.showToast('Copied to clipboard: ' + text);

      if (btnElement) {
        const originalIcon = btnElement.innerHTML;

        btnElement.innerHTML =
          '<i class="bi bi-check2 text-success"></i>';

        setTimeout(() => {
          btnElement.innerHTML = originalIcon;
        }, 1500);
      }
    });
  },

  showToast(message, type = 'info') {
    let container = document.getElementById('soc-toast-container');

    if (!container) {
      container = document.createElement('div');
      container.id = 'soc-toast-container';

      container.style.position = 'fixed';
      container.style.bottom = '20px';
      container.style.right = '20px';
      container.style.zIndex = '9999';
      container.style.display = 'flex';
      container.style.flexDirection = 'column';
      container.style.gap = '8px';

      document.body.appendChild(container);
    }

    const toast = document.createElement('div');

    toast.className =
      `soc-alert soc-alert-${type === 'error' ? 'safety' : 'info'}`;

    toast.style.margin = '0';
    toast.style.boxShadow = '0 8px 24px rgba(0,0,0,0.5)';

    toast.innerHTML =
      `<i class="bi bi-${type === 'error' ? 'exclamation-octagon' : 'info-circle'}"></i> <span>${textEscape(message)}</span>`;

    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 0.4s ease';

      setTimeout(() => toast.remove(), 400);
    }, 3500);
  }
};


/**
 * Normalize dashboard statistics
 * Accepts the documented /api/dashboard/stats contract
 * and aliases returned by backend implementations.
 */
function normalizeDashboardStats(raw) {
  const data = raw && typeof raw === 'object' ? raw : {};

  const severity =
    data.severity_breakdown ||
    data.severity ||
    data.severities ||
    {};

  const growth =
    data.memory_growth ||
    data.growth ||
    data.timeline ||
    [];

  const recent =
    data.recent_investigations ||
    data.recent ||
    data.latest_incidents ||
    [];

  return {
    ...data,

    total_investigated: firstNumber(
      data.total_investigated,
      data.total_incidents,
      data.total,
      0
    ),

    memory_items_stored: firstNumber(
      data.memory_items_stored,
      data.memory_count,
      data.memories,
      0
    ),

    resolved_incidents: firstNumber(
      data.resolved_incidents,
      data.resolved,
      data.closed,
      0
    ),

    feedback_satisfaction_rate: firstNumber(
      data.feedback_satisfaction_rate,
      data.satisfaction_rate,
      data.satisfaction,
      0
    ),

    severity_breakdown: {
      Critical: firstNumber(severity.Critical, severity.critical, 0),
      High: firstNumber(severity.High, severity.high, 0),
      Medium: firstNumber(severity.Medium, severity.medium, 0),
      Low: firstNumber(severity.Low, severity.low, 0)
    },

    memory_growth: Array.isArray(growth)
      ? growth.map(point => ({
          date: point.date || point.day || point.label || '',
          nodes: firstNumber(
            point.nodes,
            point.memories,
            point.value,
            0
          ),
          retrievals: firstNumber(
            point.retrievals,
            point.recalls,
            point.count,
            0
          )
        }))
      : [],

    recent_investigations: Array.isArray(recent) ? recent : [],

    deltas: data.deltas || data.period_change || null,

    source: data.source ||
      (
        data.system_status &&
        data.system_status.hindsight_connected
          ? 'backend'
          : 'local'
      ),

    system_status: data.system_status || {}
  };
}


/**
 * Return the first valid numeric value
 */
function firstNumber(...values) {
  for (const value of values) {
    if (value === undefined || value === null || value === '') {
      continue;
    }

    const number = Number(value);

    if (!Number.isNaN(number)) {
      return number;
    }
  }

  return 0;
}


/**
 * Initialize backend connection status
 */
function bootBackendStatus() {
  if (typeof window.paintBackendStatus !== 'function') {
    return;
  }

  CyberMemoryAPI.getDashboardStats()
    .then(window.paintBackendStatus)
    .catch(() => {
      const label = document.getElementById('backend-source-label');

      if (label) {
        label.textContent = 'API offline';
      }
    });
}


if (document.readyState === 'loading') {
  document.addEventListener(
    'DOMContentLoaded',
    bootBackendStatus
  );
} else {
  bootBackendStatus();
}


/**
 * Escape HTML to prevent injection
 */
function textEscape(str) {
  const p = document.createElement('p');

  p.appendChild(
    document.createTextNode(String(str ?? ''))
  );

  return p.innerHTML;
}
