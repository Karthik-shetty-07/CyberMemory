/**
 * CyberMemory AI — Learning Analytics Controller
 * Author: Frontend & Dashboard Engineering
 */

document.addEventListener('DOMContentLoaded', () => {
  loadAnalyticsData();
});

async function loadAnalyticsData() {
  try {
    const data = await CyberMemoryAPI.getLearningAnalytics();
    renderKpis(data);
    renderSatisfactionTrend(data.satisfaction_trend);
    renderTriageComparison(data.avg_triage_time_without_memory_min, data.avg_triage_time_with_memory_min);
    renderMitreCoverage(data.mitre_coverage);
    renderFeedbackDistribution(data.feedback_distribution);
  } catch (err) {
    console.error('Failed to load learning analytics:', err);
    CyberSOC.showToast('Failed to load analytics: ' + err.message, 'error');
  }
}

function renderKpis(data) {
  const memEl = document.getElementById('stat-stored-incidents');
  const retEl = document.getElementById('stat-retrieval-count');
  const reuseEl = document.getElementById('stat-reuse-rate');
  const timeEl = document.getElementById('stat-time-saved');

  if (memEl) memEl.textContent = data.total_memories ?? 19;
  if (retEl) retEl.textContent = data.retrieval_count ?? 87;
  if (reuseEl) reuseEl.textContent = `${data.reuse_rate_percentage ?? 78.4}%`;
  if (timeEl) timeEl.textContent = `-${data.triage_time_reduction_percentage ?? 81.3}%`;
}

function renderSatisfactionTrend(trends) {
  const container = document.getElementById('chart-satisfaction-trend');
  if (!container || !window.Plotly || !trends) return;

  const xWeeks = trends.map(t => t.week);
  const yScores = trends.map(t => t.satisfaction_rate);
  const yRetrievals = trends.map(t => t.retrievals);

  const traceSatisfaction = {
    x: xWeeks,
    y: yScores,
    name: 'Analyst Satisfaction (%)',
    type: 'scatter',
    mode: 'lines+markers',
    fill: 'tozeroy',
    fillcolor: 'rgba(0, 242, 254, 0.08)',
    line: { color: '#00F2FE', width: 3, shape: 'spline' },
    marker: { size: 7, color: '#00F2FE' }
  };

  const traceRetrievals = {
    x: xWeeks,
    y: yRetrievals,
    name: 'Memory Invocations',
    yaxis: 'y2',
    type: 'scatter',
    mode: 'lines+markers',
    line: { color: '#38BDF8', width: 2, dash: 'dot', shape: 'spline' },
    marker: { size: 6, color: '#38BDF8' }
  };

  const layout = {
    paper_bgcolor: 'transparent',
    plot_bgcolor: 'transparent',
    margin: { t: 20, b: 35, l: 40, r: 40 },
    legend: {
      orientation: 'h',
      x: 0,
      y: 1.15,
      font: { color: '#94A3B8', size: 11, family: 'Inter' }
    },
    xaxis: {
      gridcolor: 'rgba(56, 189, 248, 0.06)',
      tickfont: { color: '#64748B', size: 11, family: 'Inter' }
    },
    yaxis: {
      title: 'Satisfaction %',
      titlefont: { color: '#00F2FE', size: 10 },
      range: [70, 100],
      gridcolor: 'rgba(56, 189, 248, 0.06)',
      tickfont: { color: '#64748B', size: 10, family: 'JetBrains Mono' }
    },
    yaxis2: {
      title: 'Retrieval Count',
      titlefont: { color: '#38BDF8', size: 10 },
      overlaying: 'y',
      side: 'right',
      gridcolor: 'transparent',
      tickfont: { color: '#64748B', size: 10, family: 'JetBrains Mono' }
    }
  };

  const config = { responsive: true, displayModeBar: false };
  Plotly.newPlot('chart-satisfaction-trend', [traceSatisfaction, traceRetrievals], layout, config);
}

function renderTriageComparison(withoutMem, withMem) {
  const container = document.getElementById('chart-triage-comparison');
  if (!container || !window.Plotly) return;

  const data = [{
    x: ['Without Memory (Cold)', 'With Hindsight Memory'],
    y: [withoutMem || 38.5, withMem || 7.2],
    type: 'bar',
    text: [`${withoutMem || 38.5} mins`, `${withMem || 7.2} mins`],
    textposition: 'auto',
    textfont: { family: 'JetBrains Mono', color: '#070B14', size: 12, weight: 'bold' },
    marker: {
      color: ['#F97316', '#00F2FE'],
      line: { color: '#070B14', width: 2 }
    }
  }];

  const layout = {
    paper_bgcolor: 'transparent',
    plot_bgcolor: 'transparent',
    margin: { t: 20, b: 40, l: 40, r: 20 },
    xaxis: {
      tickfont: { color: '#94A3B8', size: 11, family: 'Inter' }
    },
    yaxis: {
      title: 'Minutes per Incident',
      titlefont: { color: '#94A3B8', size: 10 },
      gridcolor: 'rgba(56, 189, 248, 0.06)',
      tickfont: { color: '#64748B', size: 10, family: 'JetBrains Mono' }
    }
  };

  const config = { responsive: true, displayModeBar: false };
  Plotly.newPlot('chart-triage-comparison', data, layout, config);
}

function renderMitreCoverage(coverageList) {
  const container = document.getElementById('chart-mitre-coverage');
  if (!container || !window.Plotly || !coverageList) return;

  const sorted = [...coverageList].reverse();
  const yLabels = sorted.map(c => c.technique);
  const xValues = sorted.map(c => c.count);

  const data = [{
    y: yLabels,
    x: xValues,
    type: 'bar',
    orientation: 'h',
    text: xValues.map(v => `${v} incidents`),
    textposition: 'inside',
    textfont: { family: 'JetBrains Mono', color: '#070B14', size: 11, weight: 'bold' },
    marker: {
      color: '#38BDF8',
      line: { color: '#070B14', width: 1 }
    }
  }];

  const layout = {
    paper_bgcolor: 'transparent',
    plot_bgcolor: 'transparent',
    margin: { t: 15, b: 30, l: 150, r: 20 },
    xaxis: {
      gridcolor: 'rgba(56, 189, 248, 0.06)',
      tickfont: { color: '#64748B', size: 10, family: 'JetBrains Mono' }
    },
    yaxis: {
      tickfont: { color: '#CBD5E1', size: 10, family: 'Inter' }
    }
  };

  const config = { responsive: true, displayModeBar: false };
  Plotly.newPlot('chart-mitre-coverage', data, layout, config);
}

function renderFeedbackDistribution(dist) {
  const container = document.getElementById('chart-feedback-distribution');
  if (!container || !window.Plotly || !dist) return;

  const labels = Object.keys(dist);
  const values = Object.values(dist);
  const colors = ['#10B981', '#EAB308', '#EF4444'];

  const data = [{
    values: values,
    labels: labels,
    type: 'pie',
    hole: 0.6,
    marker: {
      colors: colors,
      line: { color: '#070B14', width: 2 }
    },
    textinfo: 'percent',
    textfont: { family: 'Inter', color: '#FFFFFF', size: 11 }
  }];

  const layout = {
    paper_bgcolor: 'transparent',
    plot_bgcolor: 'transparent',
    margin: { t: 15, b: 35, l: 15, r: 15 },
    showlegend: true,
    legend: {
      orientation: 'h',
      x: 0,
      y: -0.15,
      font: { color: '#94A3B8', size: 10, family: 'Inter' }
    }
  };

  const config = { responsive: true, displayModeBar: false };
  Plotly.newPlot('chart-feedback-distribution', data, layout, config);
}

