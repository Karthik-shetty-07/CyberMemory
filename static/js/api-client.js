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
        const errorData = await response.json().catch(() => ({ message: response.statusText }));
        throw new Error(errorData.error || errorData.message || `HTTP ${response.status}`);
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
    return this.request('/api/dashboard/stats');
  },

  /**
   * 2. Get Historical Incidents with optional query filters
   */
  async getIncidents(params = {}) {
    const searchParams = new URLSearchParams();
    if (params.query) searchParams.set('query', params.query);
    if (params.severity && params.severity !== 'all') searchParams.set('severity', params.severity);
    if (params.type && params.type !== 'all') searchParams.set('type', params.type);
    if (params.outcome && params.outcome !== 'all') searchParams.set('outcome', params.outcome);

    const queryString = searchParams.toString();
    return this.request(`/api/incidents${queryString ? '?' + queryString : ''}`);
  },

  /**
   * 3. Get single incident detail by ID
   */
  async getIncidentDetail(id) {
    return this.request(`/api/incidents/${id}`);
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
    return this.request(`/api/investigation/${incidentId}/feedback`, {
      method: 'POST',
      body: JSON.stringify(feedback)
    });
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
        btnElement.innerHTML = '<i class="bi bi-check2 text-success"></i>';
        setTimeout(() => { btnElement.innerHTML = originalIcon; }, 1500);
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
    toast.className = `soc-alert soc-alert-${type === 'error' ? 'safety' : 'info'}`;
    toast.style.margin = '0';
    toast.style.boxShadow = '0 8px 24px rgba(0,0,0,0.5)';
    toast.innerHTML = `<i class="bi bi-${type === 'error' ? 'exclamation-octagon' : 'info-circle'}"></i> <span>${textEscape(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity 0.4s ease';
      setTimeout(() => toast.remove(), 400);
    }, 3500);
  }
};

function textEscape(str) {
  const p = document.createElement('p');
  p.appendChild(document.createTextNode(str));
  return p.innerHTML;
}
