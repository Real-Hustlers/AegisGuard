const formatter = new Intl.NumberFormat('en-US');

window.incidentsById = {};
window.activeIncidentId = null;

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

function severityBadgeClass(severity) {
    const normalized = String(severity || '').toLowerCase();
    if (normalized === 'critical') return 'badge-critical';
    if (normalized === 'high') return 'badge-high';
    if (normalized === 'medium') return 'badge-medium';
    if (normalized === 'low') return 'badge-low';
    return 'badge-info';
}

function severityCardClass(severity) {
    const normalized = String(severity || '').toLowerCase();
    if (normalized === 'critical') return 'critical';
    if (normalized === 'high') return 'high';
    return '';
}

function renderDashboardStats(data) {
    setText('totalEvents', formatter.format(data.events));
    setText('totalThreats', formatter.format(data.threats));
    setText('totalDevices', formatter.format(data.devices));
    setText('activeAlerts', formatter.format(data.alerts));

    const mlSummary = data.ml_summary || {};
    const prediction = String(mlSummary.prediction || 'UNKNOWN').toUpperCase();
    const confidence = mlSummary.confidence != null ? `${Number(mlSummary.confidence).toFixed(1)}%` : 'N/A';
    const count = mlSummary.count != null ? `${mlSummary.count} events` : 'No data';

    setText('mlPredictionSummary', prediction);
    setText('mlConfidenceSummary', `${confidence} • ${count}`);
}

function renderAlerts(alerts) {
    const container = document.getElementById('alertContainer');
    if (!container) return;

    if (!alerts.length) {
        container.innerHTML = '<div class="text-main">No active alerts.</div>';
        return;
    }

    container.innerHTML = alerts.map((alert) => {
        const cardClass = severityCardClass(alert.severity);
        const badgeClass = severityBadgeClass(alert.severity);
        return `
            <div class="alert-card ${cardClass}">
                <i class="ph ph-check-circle" style="position:absolute; right:15px; top:15px; cursor:pointer;"></i>
                <div style="margin-bottom:10px;"><span class="badge ${badgeClass}">${alert.severity.toUpperCase()}</span><span class="mono" style="margin-left:8px; font-size:11px;">${alert.id}</span></div>
                <div class="text-white" style="font-weight:500; margin-bottom:4px;">${alert.title}</div>
                <div class="mono" style="font-size:11px; margin-bottom:8px;">${alert.device}</div>
                <div style="font-size:11px;">${alert.time}</div>
            </div>
        `;
    }).join('');
}

function renderEvents(events) {
    const tableBody = document.getElementById('eventTable');
    if (!tableBody) return;

    tableBody.innerHTML = events.map((event) => {
        const threatLevel = event.threat_level || event.severity || 'LOW';
        const mlPrediction = event.ml_prediction || 'UNKNOWN';
        return `
            <tr>
                <td class="mono">${event.id}</td>
                <td class="mono text-cyan">${event.timestamp}</td>
                <td class="mono text-white">${event.hostname}</td>
                <td class="mono text-white">${event.ip}</td>
                <td><span class="badge ${severityBadgeClass(event.severity)}">${String(event.severity || 'LOW').toUpperCase()}</span></td>
                <td><span class="badge badge-info">${String(mlPrediction).toUpperCase()}</span></td>
                <td><span class="badge ${severityBadgeClass(threatLevel)}">${String(threatLevel).toUpperCase()}</span></td>
                <td class="text-white">${event.event}</td>
            </tr>
        `;
    }).join('');
}

function renderIncidentDetails(incident) {
    const panel = document.getElementById('incidentDetailPanel');
    if (!panel) return;

    if (!incident) {
        panel.innerHTML = `
            <div class="panel-title">Incident details</div>
            <div class="text-main" style="padding: 20px;">Select an incident from the table to inspect ML prediction, confidence, and MITRE mapping.</div>
        `;
        return;
    }

    const mitre = incident.mitre || {};
    const techniqueId = mitre.technique_id || 'Unknown';
    const techniqueName = mitre.technique_name || 'Unknown';
    const tactic = mitre.tactic || 'Unknown';

    panel.innerHTML = `
        <div class="panel-title">Incident details</div>
        <div style="display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-top: 16px;">
            <div style="background: rgba(15, 23, 42, 0.8); padding: 14px; border-radius: 6px; border:1px solid var(--border-color);">
                <div style="font-size:11px; color:#94a3b8; margin-bottom:8px;">Incident ID</div>
                <div style="font-weight:600; color:#f8fafc;">${escapeHtml(incident.incident_id)}</div>
            </div>
            <div style="background: rgba(15, 23, 42, 0.8); padding: 14px; border-radius: 6px; border:1px solid var(--border-color);">
                <div style="font-size:11px; color:#94a3b8; margin-bottom:8px;">Status</div>
                <div style="font-weight:600; color:#f8fafc;">${escapeHtml(incident.status)}</div>
            </div>
            <div style="background: rgba(15, 23, 42, 0.8); padding: 14px; border-radius: 6px; border:1px solid var(--border-color);">
                <div style="font-size:11px; color:#94a3b8; margin-bottom:8px;">Threat Type</div>
                <div style="font-weight:600; color:#f8fafc;">${escapeHtml(incident.threat_type)}</div>
            </div>
            <div style="background: rgba(15, 23, 42, 0.8); padding: 14px; border-radius: 6px; border:1px solid var(--border-color);">
                <div style="font-size:11px; color:#94a3b8; margin-bottom:8px;">Severity</div>
                <div style="font-weight:600; color:#f8fafc;">${escapeHtml(incident.severity)}</div>
            </div>
        </div>
        <div style="display:grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-top: 16px;">
            <div style="background: rgba(15, 23, 42, 0.8); padding: 14px; border-radius: 6px; border:1px solid var(--border-color);">
                <div style="font-size:11px; color:#94a3b8; margin-bottom:8px;">ML Prediction</div>
                <div style="font-weight:600; color:#22d3ee;">${escapeHtml(String(incident.ml_prediction || 'UNKNOWN'))}</div>
                <div style="font-size:11px; color:#94a3b8; margin-top:8px;">Confidence</div>
                <div>${escapeHtml(String(incident.ml_confidence != null ? `${Number(incident.ml_confidence).toFixed(1)}%` : 'N/A'))}</div>
            </div>
            <div style="background: rgba(15, 23, 42, 0.8); padding: 14px; border-radius: 6px; border:1px solid var(--border-color);">
                <div style="font-size:11px; color:#94a3b8; margin-bottom:8px;">Target</div>
                <div style="font-weight:600; color:#f8fafc;">${escapeHtml(incident.hostname || 'Unknown')}</div>
                <div style="font-size:11px; color:#94a3b8; margin-top:8px;">Source IP</div>
                <div>${escapeHtml(incident.source_ip || 'Unknown')}</div>
            </div>
        </div>
        <div style="margin-top: 16px; display:grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px;">
            <div style="background: rgba(15, 23, 42, 0.8); padding: 14px; border-radius: 6px; border:1px solid var(--border-color);">
                <div style="font-size:11px; color:#94a3b8; margin-bottom:8px;">Technique ID</div>
                <div style="font-weight:600; color:#f8fafc;">${escapeHtml(techniqueId)}</div>
            </div>
            <div style="background: rgba(15, 23, 42, 0.8); padding: 14px; border-radius: 6px; border:1px solid var(--border-color);">
                <div style="font-size:11px; color:#94a3b8; margin-bottom:8px;">Technique Name</div>
                <div style="font-weight:600; color:#f8fafc;">${escapeHtml(techniqueName)}</div>
            </div>
            <div style="background: rgba(15, 23, 42, 0.8); padding: 14px; border-radius: 6px; border:1px solid var(--border-color);">
                <div style="font-size:11px; color:#94a3b8; margin-bottom:8px;">Tactic</div>
                <div style="font-weight:600; color:#f8fafc;">${escapeHtml(tactic)}</div>
            </div>
        </div>
        <div style="margin-top: 16px;">
            <div style="font-size:11px; color:#94a3b8; margin-bottom:8px;">Details</div>
            <div class="text-main" style="background: rgba(15, 23, 42, 0.8); padding: 14px; border-radius: 6px; border:1px solid var(--border-color); min-height: 80px; white-space: pre-wrap;">${escapeHtml(incident.incident_report || 'No incident report available.')}</div>
        </div>
    `;
}

window.showIncidentDetails = function(incidentId) {
    if (!window.incidentsById) return;
    const incident = window.incidentsById[incidentId];
    window.activeIncidentId = incidentId;
    renderIncidentDetails(incident);
};

function renderCharts(data) {
    const lineCanvas = document.getElementById('threatChart');
    const barCanvas = document.getElementById('distChart');

    if (lineCanvas && !window.lineChart) {
        window.lineChart = new Chart(lineCanvas, {
            type: 'line',
            data: { labels: data.timeline.labels, datasets: [{ data: data.timeline.values }] },
            options: { responsive: true, maintainAspectRatio: false }
        });
    } else if (lineCanvas && window.lineChart) {
        window.lineChart.data.labels = data.timeline.labels;
        window.lineChart.data.datasets[0].data = data.timeline.values;
        window.lineChart.update();
    }

    if (barCanvas && !window.barChart) {
        window.barChart = new Chart(barCanvas, {
            type: 'bar',
            data: { labels: data.distribution.labels, datasets: [{ data: data.distribution.values }] },
            options: { responsive: true, maintainAspectRatio: false }
        });
    } else if (barCanvas && window.barChart) {
        window.barChart.data.labels = data.distribution.labels;
        window.barChart.data.datasets[0].data = data.distribution.values;
        window.barChart.update();
    }
}

// ------------------------------------------
// Automated Incident Response Front-end
// ------------------------------------------

function escapeHtml(str) {
    return String(str || '')
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function getIncidentStatusBadge(status) {
    const s = String(status || '').toUpperCase();
    if (s === 'PENDING') return '<span class="badge badge-high">PENDING</span>';
    if (s === 'EXECUTING') return '<span class="badge badge-live">EXECUTING</span>';
    if (s === 'SIMULATED') return '<span class="badge badge-low" style="color:var(--orange); border-color:var(--orange); background:rgba(255,165,2,0.1)">SIMULATED</span>';
    if (s === 'EXECUTED') return '<span class="badge badge-live" style="color:var(--green); border-color:var(--green); background:rgba(46,213,115,0.1)">EXECUTED</span>';
    if (s === 'FAILED') return '<span class="badge badge-critical">FAILED</span>';
    return `<span class="badge badge-info">${s}</span>`;
}

function renderPlaybookSteps(steps, status) {
    const s = String(status || '').toUpperCase();
    const isCompleted = ['SIMULATED', 'EXECUTED'].includes(s);
    
    return steps.map((step, idx) => {
        let prefix = '○';
        let style = 'color:#64748b;';
        
        if (isCompleted) {
            prefix = '✓';
            style = 'color:var(--green); font-weight:600;';
        } else if (s === 'EXECUTING' && idx === 0) {
            prefix = '●';
            style = 'color:var(--cyan); font-weight:600;';
        } else if (s === 'PENDING') {
            style = 'color:var(--text-main);';
        }
        
        return `<div style="${style}">${prefix} ${step}</div>`;
    }).join('');
}

function renderIncidentsTable(incidents) {
    const tableBody = document.getElementById('irIncidentsTable');
    if (!tableBody) return;
    
    // Update badge count
    const pendingCount = incidents.filter(i => i.status === 'PENDING').length;
    const badge = document.getElementById('irBadge');
    if (badge) {
        badge.textContent = pendingCount;
        badge.style.display = pendingCount > 0 ? 'inline-block' : 'none';
    }

    if (!incidents.length) {
        tableBody.innerHTML = '<tr><td colspan="4" class="text-main" style="text-align:center; padding: 20px;">No incidents detected. System secure.</td></tr>';
        return;
    }

    tableBody.innerHTML = incidents.map((inc) => {
        const statusBadge = getIncidentStatusBadge(inc.status);
        const stepsHtml = renderPlaybookSteps(inc.playbook_steps, inc.status);
        const actionBtn = inc.status === 'PENDING' 
            ? `<button class="btn-outline" onclick="triggerManualExecution('${inc.incident_id}')" style="padding: 4px 8px; font-size:10px;">EXECUTE</button>` 
            : `<button class="btn-outline" disabled style="padding: 4px 8px; font-size:10px; opacity: 0.5; cursor: not-allowed;">COMPLETED</button>`;

        return `
            <tr onclick="showIncidentDetails('${inc.incident_id}')" style="cursor:pointer;">
                <td class="mono">
                    <div style="font-weight:600; color:var(--text-light);">${inc.incident_id}</div>
                    <div style="font-size:10px; color:#64748b;">${inc.timestamp}</div>
                </td>
                <td>
                    <div class="text-white">${inc.threat_type}</div>
                    <div class="mono" style="font-size:10px; color:#94a3b8;">Target: ${inc.hostname} (${inc.os})</div>
                    <div class="mono text-cyan" style="font-size:10px; margin-top:2px;">
                        ${inc.source_ip ? `IP: ${inc.source_ip}` : ''} 
                        ${inc.user ? ` | User: ${inc.user}` : ''}
                        ${inc.process ? ` | Process: ${inc.process}` : ''}
                    </div>
                </td>
                <td>
                    <div style="margin-bottom:6px;">${statusBadge}</div>
                    <div style="display:flex; flex-direction:column; gap:4px; font-size:11px;">
                        ${stepsHtml}
                    </div>
                </td>
                <td style="text-align:right; padding-right:10px;">
                    ${actionBtn}
                </td>
            </tr>
        `;
    }).join('');
}

let lastLogCount = 0;
function renderTerminalLogs(logs) {
    const term = document.getElementById('irTerminal');
    if (!term) return;

    if (!logs.length) {
        term.innerHTML = '<div style="color:#64748b;">[SYSTEM] Terminal online. Waiting for incident execution...</div>';
        return;
    }

    term.innerHTML = logs.map((log) => {
        let color = '#10b981'; // default green
        if (log.message.includes('[INIT]')) color = 'var(--cyan)';
        else if (log.message.includes('[SIMULATION]')) color = 'var(--orange)';
        else if (log.message.includes('[ACTIVE]')) color = 'var(--cyan)';
        else if (log.message.includes('[ERROR]')) color = 'var(--red)';
        else if (log.message.includes('[SUCCESS]')) color = 'var(--green)';
        else if (log.message.includes('[STDERR]')) color = 'var(--red)';
        else if (log.message.includes('[STDOUT]')) color = '#e2e8f0';

        return `<div style="line-height: 1.4; color:${color}"><span style="color:#64748b;">[${log.timestamp}]</span> ${escapeHtml(log.message)}</div>`;
    }).join('');

    // Auto scroll to bottom only if new logs arrived
    if (logs.length > lastLogCount) {
        term.scrollTop = term.scrollHeight;
        lastLogCount = logs.length;
    }
}

function renderSettingsState(settings) {
    const toggleAuto = document.getElementById('toggleAutoResponse');
    const toggleSim = document.getElementById('toggleSimulationMode');
    const statusText = document.getElementById('irStatusText');
    const sliderAuto = document.getElementById('sliderAuto');
    const knobAuto = document.getElementById('knobAuto');
    const sliderSim = document.getElementById('sliderSim');
    const knobSim = document.getElementById('knobSim');

    if (toggleAuto) toggleAuto.checked = settings.auto_response_enabled;
    if (toggleSim) toggleSim.checked = settings.simulation_mode;

    if (statusText) {
        if (settings.auto_response_enabled) {
            statusText.textContent = settings.simulation_mode ? 'SHIELD ACTIVE (SIMULATION)' : 'SHIELD ACTIVE (ENFORCING)';
            statusText.className = 'badge badge-live';
            statusText.style.borderColor = 'var(--cyan)';
            statusText.style.color = 'var(--cyan)';
            statusText.style.background = 'var(--cyan-dim)';
        } else {
            statusText.textContent = 'SHIELD INACTIVE';
            statusText.className = 'badge badge-info';
            statusText.style.borderColor = 'var(--border-color)';
            statusText.style.color = 'var(--text-main)';
            statusText.style.background = 'transparent';
        }
    }

    // Toggle slider styles
    if (sliderAuto && knobAuto) {
        if (settings.auto_response_enabled) {
            sliderAuto.style.backgroundColor = 'var(--cyan-dim)';
            sliderAuto.style.borderColor = 'var(--cyan)';
            knobAuto.style.left = '25px';
        } else {
            sliderAuto.style.backgroundColor = '#1e293b';
            sliderAuto.style.borderColor = 'var(--border-color)';
            knobAuto.style.left = '3px';
        }
    }

    if (sliderSim && knobSim) {
        if (settings.simulation_mode) {
            sliderSim.style.backgroundColor = 'rgba(255,165,2,0.1)';
            sliderSim.style.borderColor = 'var(--orange)';
            knobSim.style.left = '25px';
        } else {
            sliderSim.style.backgroundColor = '#1e293b';
            sliderSim.style.borderColor = 'var(--border-color)';
            knobSim.style.left = '3px';
        }
    }
}

function renderSuspiciousEntities(data) {
    const topIPEl = document.getElementById('topSuspiciousIP');
    const topIPCountEl = document.getElementById('topSuspiciousIPCount');
    const topHostEl = document.getElementById('topInfectedHost');
    const topHostCountEl = document.getElementById('topInfectedHostCount');

    const topIP = data.ips && data.ips.length ? data.ips[0] : null;
    const topHost = data.hosts && data.hosts.length ? data.hosts[0] : null;

    if (topIPEl && topIP) {
        topIPEl.textContent = topIP.ip;
        topIPCountEl.textContent = `${topIP.count} critical/high events`;
    } else if (topIPEl) {
        topIPEl.textContent = 'NONE';
        topIPCountEl.textContent = '0 threat events';
    }

    if (topHostEl && topHost) {
        topHostEl.textContent = topHost.hostname;
        topHostCountEl.textContent = `${topHost.count} critical/high events`;
    } else if (topHostEl) {
        topHostEl.textContent = 'NONE';
        topHostCountEl.textContent = '0 threat events';
    }
}

function updateSettings(autoEnabled, simMode) {
    fetch('/api/incidents/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            auto_response_enabled: autoEnabled,
            simulation_mode: simMode
        })
    })
    .then(r => r.json())
    .then(settings => {
        renderSettingsState(settings);
    });
}

window.triggerManualExecution = function(incidentId) {
    const simMode = document.getElementById('toggleSimulationMode').checked;
    fetch('/api/incidents/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            incident_id: incidentId,
            enforce: !simMode
        })
    })
    .then(r => r.json())
    .then(res => {
        if (res.success) {
            loadIncidentResponseData();
        }
    });
}

function loadIncidentResponseData() {
    Promise.all([
        fetch('/api/incidents/settings').then(r => r.json()),
        fetch('/api/incidents/suspicious').then(r => r.json()),
        fetch('/api/incidents').then(r => r.json()),
        fetch('/api/incidents/logs').then(r => r.json())
    ])
    .then(([settings, suspicious, incidents, logs]) => {
        renderSettingsState(settings);
        renderSuspiciousEntities(suspicious);
        renderIncidentsTable(incidents);

        window.incidentsById = incidents.reduce((map, incident) => {
            map[incident.incident_id] = incident;
            return map;
        }, {});

        const activeId = window.activeIncidentId && window.incidentsById[window.activeIncidentId]
            ? window.activeIncidentId
            : (incidents.length ? incidents[0].incident_id : null);

        if (activeId) {
            window.activeIncidentId = activeId;
            renderIncidentDetails(window.incidentsById[activeId]);
        } else {
            renderIncidentDetails(null);
        }

        renderTerminalLogs(logs);
    })
    .catch(err => {
        console.error('Incident Response fetch failed:', err);
    });
}

function loadDashboardData() {
    Promise.all([
        fetch('/api/dashboard').then((response) => response.json()),
        fetch('/api/alerts').then((response) => response.json()),
        fetch('/api/events').then((response) => response.json())
    ])
        .then(([dashboardData, alerts, events]) => {
            renderDashboardStats(dashboardData);
            renderAlerts(alerts);
            renderEvents(events);
            renderCharts(dashboardData);
        })
        .catch((error) => {
            console.error('Dashboard load failed:', error);
        });
}

window.addEventListener('DOMContentLoaded', () => {
    // Initial loads
    loadDashboardData();
    loadIncidentResponseData();

    // Setup periodic polling
    setInterval(loadDashboardData, 5000);
    setInterval(loadIncidentResponseData, 3000);

    // Register event listeners
    const toggleAuto = document.getElementById('toggleAutoResponse');
    const toggleSim = document.getElementById('toggleSimulationMode');
    const resetBtn = document.getElementById('irResetBtn');

    if (toggleAuto) {
        toggleAuto.addEventListener('change', () => {
            updateSettings(toggleAuto.checked, toggleSim.checked);
        });
    }
    if (toggleSim) {
        toggleSim.addEventListener('change', () => {
            updateSettings(toggleAuto.checked, toggleSim.checked);
        });
    }
    if (resetBtn) {
        resetBtn.addEventListener('click', () => {
            if (confirm('Are you sure you want to reset all incidents and execution logs?')) {
                fetch('/api/incidents/reset', { method: 'POST' })
                    .then(r => r.json())
                    .then(() => {
                        loadIncidentResponseData();
                    });
            }
        });
    }
});
