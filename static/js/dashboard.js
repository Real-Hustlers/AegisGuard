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

    // Populate severity counts from distribution
    const dist = data.distribution || { labels: [], values: [] };
    let critical = 0, high = 0;
    for (let i = 0; i < (dist.labels || []).length; i++) {
        const label = String(dist.labels[i] || '').toUpperCase();
        const val = dist.values[i] || 0;
        if (label === 'CRITICAL') critical = val;
        if (label === 'HIGH') high = val;
    }
    const critEl = document.getElementById('criticalCount'); if (critEl) critEl.textContent = formatter.format(critical);
    const highEl = document.getElementById('highCount'); if (highEl) highEl.textContent = formatter.format(high);

    const attackEl = document.getElementById('attackPatternsCount');
    if (attackEl) attackEl.textContent = (data.ml_summary && data.ml_summary.count) ? formatter.format(data.ml_summary.count) : '0';

    const mlSummary = data.ml_summary || {};
    const prediction = String(mlSummary.prediction || 'UNKNOWN').toUpperCase();
    const confidence = mlSummary.confidence != null ? `${Number(mlSummary.confidence).toFixed(1)}%` : 'N/A';
    const count = mlSummary.count != null ? `${mlSummary.count} events` : 'No data';

    setText('mlPredictionSummary', prediction);
    setText('mlConfidenceSummary', `${confidence} • ${count}`);
}

function formatRelativeTime(timestamp) {
    const date = new Date(timestamp);
    if (Number.isNaN(date.getTime())) return timestamp;
    const now = new Date();
    const diffMinutes = Math.round((now - date) / 60000);
    if (diffMinutes <= 0) return 'Just now';
    if (diffMinutes === 1) return '1 min';
    if (diffMinutes < 60) return `${diffMinutes} mins`;
    const diffHours = Math.round(diffMinutes / 60);
    return `${diffHours} hr${diffHours === 1 ? '' : 's'}`;
}

function deviceStatusClass(status) {
    if (status === 'critical') return 'critical';
    if (status === 'warning') return 'warning';
    return '';
}

function renderDevices(devices) {
    const container = document.getElementById('deviceGrid');
    const header = document.getElementById('deviceCountText');
    if (!container) return;
    if (header) {
        header.textContent = `Air-gapped network — ${devices.length} total devices`;
    }

    if (!devices.length) {
        container.innerHTML = '<div class="device-card"><div style="font-size:14px; color:#94a3b8;">No devices detected yet.</div></div>';
        return;
    }

    container.innerHTML = devices.map((device) => {
        const statusClass = deviceStatusClass(device.status);
        const statusDot = device.status === 'critical'
            ? 'var(--red)'
            : device.status === 'warning'
                ? 'var(--orange)'
                : 'var(--green)';

        return `
            <div class="device-card ${statusClass}">
                <div style="display:flex; justify-content:space-between; margin-bottom:15px;">
                    <div class="text-white" style="font-weight:600; display:flex; align-items:center; gap:8px;">
                        <span class="status-dot" style="background:${statusDot}"></span> ${escapeHtml(device.hostname)}
                    </div>
                    <i class="ph ph-eye text-main"></i>
                </div>
                <div style="font-size:11px; margin-bottom:2px;">${escapeHtml(device.os)}</div>
                <div class="mono text-cyan" style="font-size:12px; margin-bottom:20px;">${escapeHtml(device.ip)}</div>
                <div style="display:flex; justify-content:space-between; font-size:11px;">
                    <span>${formatter.format(device.event_count)} events</span>
                    <span class="text-white">${formatRelativeTime(device.last_seen)}</span>
                </div>
            </div>
        `;
    }).join('');
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

function renderThreatList(alerts) {
    const container = document.getElementById('threatList');
    if (!container) return;
    // Only show high / critical severity alerts in the Threats panel
    const threats = (alerts || []).filter(a => ['critical','high'].includes(String(a.severity || '').toLowerCase()));

    if (!threats.length) {
        container.innerHTML = '<div class="text-main">No critical or high events.</div>';
        const titleElEmpty = document.getElementById('threatPanelTitle');
        if (titleElEmpty) titleElEmpty.textContent = 'Critical & High Severity Events (0)';
        return;
    }

    // sort critical first, then high, newest first
    const order = { 'critical': 0, 'high': 1 };
    threats.sort((x,y) => {
        const sx = order[String(x.severity || '').toLowerCase()] ?? 9;
        const sy = order[String(y.severity || '').toLowerCase()] ?? 9;
        if (sx !== sy) return sx - sy;
        // fallback to timestamp desc if available
        const tx = new Date(x.timestamp || x.time || 0).getTime();
        const ty = new Date(y.timestamp || y.time || 0).getTime();
        return ty - tx;
    });

    container.innerHTML = threats.map((alert) => {
        const severity = String(alert.severity || 'LOW').toUpperCase();
        const badgeClass = severityBadgeClass(alert.severity);
        return `
            <div class="threat-row">
                <div style="display:flex; gap:15px; align-items:flex-start;">
                    <i class="ph ph-warning-circle ${severity === 'CRITICAL' ? 'text-red' : 'text-orange'}" style="font-size:18px; margin-top:2px;"></i>
                    <div>
                        <div style="margin-bottom:5px;"><span class="badge ${badgeClass}">${severity}</span> <span class="mono" style="font-size:11px; margin-left:8px;">${escapeHtml(alert.id)} · ${escapeHtml(alert.time || alert.timestamp || '')}</span></div>
                        <div class="text-white" style="font-size:14px; margin-bottom:5px;">${escapeHtml(alert.title)}</div>
                        <div class="mono" style="font-size:11px; cursor:pointer; text-decoration:underline;" onclick="loadEventsForHost('${escapeHtml(alert.device || alert.hostname || '')}')">${escapeHtml(alert.device || alert.hostname || '')}</div>
                    </div>
                </div>
                <button class="btn-outline" onclick="showAlertDetails('${escapeHtml(alert.id)}')">INVESTIGATE</button>
            </div>
        `;
    }).join('');
    // update panel title with live count
    const titleEl = document.getElementById('threatPanelTitle');
    if (titleEl) titleEl.textContent = `Critical & High Severity Events (${threats.length})`;
}

function loadEventsForHost(hostname) {
    if (!hostname) return;
    // switch to Event Logs view
    const logsView = document.getElementById('view-logs');
    const dashboardView = document.getElementById('view-dashboard');
    const breadcrumb = document.getElementById('breadcrumb-current');
    // Activate views
    document.querySelectorAll('.view-section').forEach(v => v.classList.remove('active'));
    if (logsView) logsView.classList.add('active');
    if (dashboardView) dashboardView.classList.remove('active');
    if (breadcrumb) breadcrumb.textContent = `EVENT LOGS — ${hostname}`;

    fetch(`/api/events?hostname=${encodeURIComponent(hostname)}`)
        .then(r => r.json())
        .then(events => {
            renderEvents(events);
        })
        .catch(err => console.error('Failed to load events for host', err));
}

function renderEvents(events) {
    const tableBody = document.getElementById('eventTable');
    if (!tableBody) return;

    if (!events || !events.length) {
        tableBody.innerHTML = '<tr><td colspan="8" class="text-main" style="text-align:center; padding:20px;">No event logs available.</td></tr>';
        return;
    }

    tableBody.innerHTML = events.map((ev) => {
        const timeText = formatRelativeTime(ev.timestamp);
        const severity = ev.severity || 'INFO';
        const ml = ev.ml_prediction || 'N/A';
        const threat = ev.threat_level || (ev.threat_score ? `${ev.threat_score}` : 'NONE');
        const eventText = String(ev.event || '').length > 80 ? String(ev.event || '').slice(0, 77) + '...' : (ev.event || '');

        return `
            <tr>
                <td class="mono">${escapeHtml(ev.id)}</td>
                <td>${escapeHtml(timeText)}</td>
                <td>${escapeHtml(ev.hostname || '')}</td>
                <td class="mono">${escapeHtml(ev.ip || '')}</td>
                <td><span class="badge ${severityBadgeClass(severity)}">${escapeHtml(String(severity))}</span></td>
                <td class="mono">${escapeHtml(ml)}</td>
                <td>${escapeHtml(String(threat))}</td>
                <td>${escapeHtml(eventText)}</td>
            </tr>
        `;
    }).join('');
}

window.showAlertDetails = function(alertId) {
    // Fetch correlation-style summary for the alert and render in the incident panel
    fetch(`/api/alerts/summary?log_id=${encodeURIComponent(alertId)}`)
        .then((r) => r.json())
        .then((data) => {
            if (data && !data.error) {
                renderAlertSummaryModal(data);
            } else {
                const modalBody = document.getElementById('alertModalBody');
                if (modalBody) modalBody.innerHTML = `<div class="text-main" style="padding:20px;">No summary available for ${escapeHtml(alertId)}</div>`;
                openModal();
            }
        })
        .catch((err) => {
            console.error('Failed to load alert summary', err);
        });
};

function renderAlertSummary(payload) {
    const panel = document.getElementById('incidentDetailPanel');
    if (!panel) return;

    const ev = payload.event || {};
    const related = payload.related || [];
    const findings = payload.findings || [];

    panel.innerHTML = `
        <div class="panel-title">Alert summary: ${escapeHtml(ev.id)}</div>
        <div style="padding:12px;">
            <div style="font-size:13px; font-weight:600; color:var(--text-light);">${escapeHtml(ev.raw_log || '')}</div>
            <div style="margin-top:8px; font-size:12px; color:#94a3b8;">${escapeHtml(ev.hostname || '')} • ${escapeHtml(ev.timestamp || '')} • ${escapeHtml(ev.severity || '')}</div>
            <div style="margin-top:12px;"><strong>Correlation findings</strong>
                <ul style="margin-top:6px; color:#cbd5e1;">${findings.map(f => `<li>${escapeHtml(f)}</li>`).join('')}</ul>
            </div>
            <div style="margin-top:12px;"><strong>Related logs (±5m)</strong>
                <div style="margin-top:8px; max-height:160px; overflow:auto; background:rgba(255,255,255,0.02); padding:8px; border-radius:4px; border:1px solid var(--border-color);">
                    ${related.length ? related.map(r => `<div style="margin-bottom:8px;"><div class="mono" style="font-size:11px; color:#94a3b8;">${escapeHtml(r.timestamp)} • ${escapeHtml(r.id)}</div><div style="font-size:13px;">${escapeHtml(r.raw_log)}</div></div>`).join('') : '<div class="text-main">No related logs found.</div>'}
                </div>
            </div>
        </div>
    `;
}

// Modal helpers
function openModal() {
    const modal = document.getElementById('alertModal');
    if (!modal) return;
    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');
}

function closeModal() {
    const modal = document.getElementById('alertModal');
    if (!modal) return;
    modal.classList.remove('active');
    modal.setAttribute('aria-hidden', 'true');
}

function renderAlertSummaryModal(payload) {
    const body = document.getElementById('alertModalBody');
    if (!body) return;
    const ev = payload.event || {};
    const related = payload.related || [];
    const findings = payload.findings || [];

    // Format the incident-style summary text
    const incidentId = (() => {
        const m = String(ev.id || '').match(/(\d+)/);
        return m ? `INC-${m[1].padStart(4, '0')}` : (ev.id ? `INC-${ev.id}` : 'INC-0000');
    })();

    const attackType = findings.length ? findings[0] : 'Unknown';
    const severity = ev.severity || 'UNKNOWN';
    const riskScore = ev.threat_score != null ? String(ev.threat_score) : '-';
    const mlPred = ev.ml_prediction || 'UNKNOWN';
    const mlConf = ev.ml_confidence != null ? `${Number(ev.ml_confidence).toFixed(0)}%` : '-';
    const threatCategory = ev.threat_category || '-';
    const detectionMethod = 'Rule Correlation + ML';

    const hostname = ev.hostname || '-';
    const os = ev.os || '-';
    const user = ev.user || '-';
    const srcIp = ev.ip || '-';
    const dstIp = ev.destination_ip || '-';
    const process = ev.process || '-';
    const filePath = ev.file_path || '-';

    const mitre = payload.mitre || {};
    const techniqueId = mitre.technique_id || mitre.technique || '-';
    const techniqueName = mitre.technique || mitre.technique_name || '-';
    const tactic = mitre.tactic || '-';

    const startTime = ev.timestamp || '-';
    const endTime = (related.length ? related[related.length-1].timestamp : ev.timestamp) || '-';

    const relatedList = related.length ? related.map((r,i) => `${i+1}. ${r.raw_log}`) : [];

    const lines = [];
    lines.push('=========================================================');
    lines.push('INCIDENT DETAILS');
    lines.push('=========================================================');
    lines.push('');
    lines.push(`Incident ID:\n${incidentId}`);
    lines.push('');
    lines.push(`Attack Type:\n${attackType}`);
    lines.push('');
    lines.push(`Severity:\n${severity}`);
    lines.push('');
    lines.push(`Risk Score:\n${riskScore}`);
    lines.push('');
    lines.push(`ML Prediction:\n${mlPred}`);
    lines.push('');
    lines.push(`ML Confidence:\n${mlConf}`);
    lines.push('');
    lines.push(`Threat Category:\n${threatCategory}`);
    lines.push('');
    lines.push(`Detection Method:\n${detectionMethod}`);
    lines.push('');
    lines.push('---------------------------------------------------------');
    lines.push('');
    lines.push(`Hostname:\n${hostname}`);
    lines.push('');
    lines.push(`Operating System:\n${os}`);
    lines.push('');
    lines.push(`User:\n${user}`);
    lines.push('');
    lines.push(`Source IP:\n${srcIp}`);
    lines.push('');
    lines.push(`Destination IP:\n${dstIp}`);
    lines.push('');
    lines.push(`Process:\n${process}`);
    lines.push('');
    lines.push(`File Path:\n${filePath}`);
    lines.push('');
    lines.push('---------------------------------------------------------');
    lines.push('');
    lines.push('MITRE ATT&CK');
    lines.push('');
    lines.push(`Technique ID:\n${techniqueId}`);
    lines.push('');
    lines.push(`Technique Name:\n${techniqueName}`);
    lines.push('');
    lines.push(`Tactic:\n${tactic}`);
    lines.push('');
    lines.push('---------------------------------------------------------');
    lines.push('');
    lines.push(`Start Time:\n${startTime}`);
    lines.push('');
    lines.push(`End Time:\n${endTime}`);
    lines.push('');
    lines.push('---------------------------------------------------------');
    lines.push('');
    lines.push('Related Logs');
    lines.push('');
    relatedList.forEach((rl) => lines.push(rl));

    body.innerHTML = `<pre style="white-space:pre-wrap; font-family:var(--font-mono); color:var(--text-main);">${escapeHtml(lines.join('\n'))}</pre>`;
    openModal();
}

function renderIncidentDetails(incident) {
    const panel = document.getElementById('incidentDetailPanel');
    if (!panel) return;

    if (!incident) {
        panel.innerHTML = `
            <div class="panel-title">Incident details <span id="irSelectedIncident" style="font-size:11px; color:var(--text-main);">(none selected)</span></div>
            <div class="text-main" style="padding: 20px;">Select an incident from the table to inspect ML prediction, confidence, and MITRE mapping.</div>
        `;
        return;
    }

    const mitre = incident.mitre || {};
    const techniqueId = mitre.technique_id || 'Unknown';
    const techniqueName = mitre.technique_name || 'Unknown';
    const tactic = mitre.tactic || 'Unknown';

    panel.innerHTML = `
        <div class="panel-title">Incident details <span id="irSelectedIncident" style="font-size:11px; color:var(--text-main);">(${escapeHtml(incident.incident_id)})</span></div>
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
            <div class="text-main" style="background: rgba(15, 23, 42, 0.8); padding: 14px; border-radius: 6px; border:1px solid var(--border-color); min-height: 80px; white-space: pre-wrap;">Threat:
            ${incident.incident_report.threat_type}

            Action:
            ${incident.incident_report.action_taken}

            MITRE:
            ${incident.mitre.technique_id}

            Playbook:
            ${incident.playbook_steps.join("\n")}</div>
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
        } else if (s === 'PENDING' || s === 'OPEN') {
            style = 'color:var(--text-main);';
        }
        
        return `<div style="${style}">${prefix} ${escapeHtml(step)}</div>`;
    }).join('');
}

function getRecommendedPlaybook(incident) {
    const steps = incident.playbook_steps || [];
    if (steps.length) return steps;

    const report = incident.incident_report || {};
    if (report.playbook_steps && report.playbook_steps.length) return report.playbook_steps;

    const type = String(incident.threat_type || report.attack_type || '').toLowerCase();
    if (type.includes('brute force')) {
        return [
            'Block attacker source IP',
            'Lock affected user account',
            'Review failed authentication attempts',
            'Notify security operations'
        ];
    }

    if (type.includes('privilege escalation')) {
        return [
            'Terminate suspicious process',
            'Isolate affected host',
            'Review privilege escalation events',
            'Notify security operations'
        ];
    }

    if (type.includes('malware') || type.includes('ransomware')) {
        return [
            'Quarantine infected host',
            'Kill malicious process',
            'Scan system for malware',
            'Restore from backups if needed'
        ];
    }

    return [
        report.action_taken || 'Investigate and confirm the incident',
        'Collect host and network evidence',
        'Notify the SOC team',
        'Apply containment controls'
    ];
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

    const incidentCountLabel = document.getElementById('irIncidentCount');
    if (incidentCountLabel) {
        incidentCountLabel.textContent = `(${incidents.length})`;
    }

    if (!incidents.length) {
        tableBody.innerHTML = '<tr><td colspan="4" class="text-main" style="text-align:center; padding: 20px;">No incidents detected. System secure.</td></tr>';
        return;
    }

    tableBody.innerHTML = incidents.map((inc) => {
        const statusBadge = getIncidentStatusBadge(inc.status);
        const recommendedSteps = getRecommendedPlaybook(inc);
        const stepsHtml = renderPlaybookSteps(recommendedSteps, inc.status);
        const report = inc.incident_report || {};
        const actionBtn = ['PENDING','OPEN','REVIEW'].includes(String(inc.status || '').toUpperCase())
            ? `<button class="btn-outline" onclick="triggerManualExecution('${inc.incident_id}')" style="padding: 4px 8px; font-size:10px;">EXECUTE</button>`
            : `<button class="btn-outline" disabled style="padding: 4px 8px; font-size:10px; opacity: 0.5; cursor: not-allowed;">COMPLETED</button>`;

        return `
            <tr onclick="showIncidentDetails('${inc.incident_id}')" style="cursor:pointer;">
                <td class="mono">
                    <div style="font-weight:600; color:var(--text-light);">${escapeHtml(inc.incident_id)}</div>
                    <div style="font-size:10px; color:#64748b;">${escapeHtml(inc.timestamp || '')}</div>
                </td>
                <td>
                    <div class="text-white">${escapeHtml(inc.threat_type || report.attack_type || 'Unknown threat')}</div>
                    <div class="mono" style="font-size:10px; color:#94a3b8; margin-top:4px;">Target: ${escapeHtml(inc.hostname || report.hostname || 'Unknown')}</div>
                    <div class="mono text-cyan" style="font-size:10px; margin-top:2px; line-height:1.4;">
                        ${escapeHtml(inc.os || report.os || 'Unknown OS')} • ${escapeHtml(inc.source_ip || report.source_ip || 'No source IP')}
                        ${report.user ? ` • User: ${escapeHtml(report.user)}` : ''}
                    </div>
                </td>
                <td>
                    <div style="margin-bottom:6px; font-size:11px; color:#94a3b8;">Severity: ${escapeHtml(inc.severity || report.severity || 'Unknown')}</div>
                    <div style="margin-bottom:6px;">${statusBadge}</div>
                    <div style="display:flex; flex-direction:column; gap:4px; font-size:11px;">
                        ${stepsHtml}
                    </div>
                    <div style="margin-top:8px; font-size:11px; color:#94a3b8;">MITRE: ${escapeHtml((inc.mitre && (inc.mitre.technique_name || inc.mitre.technique)) || 'Unknown')}</div>
                </td>
                <td style="text-align:right; padding-right:10px; vertical-align:middle;">
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

function loadDeviceData() {
    fetch('/api/devices')
        .then((response) => response.json())
        .then((devices) => renderDevices(devices))
        .catch((error) => {
            console.error('Device load failed:', error);
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
            renderThreatList(alerts);
            renderEvents(events);
            renderCharts(dashboardData);
            // Update sidebar nav badges with live counts
            try {
                const evBadge = document.getElementById('navEventsBadge');
                if (evBadge) evBadge.textContent = String((events && events.length) || 0);

                const threatsBadge = document.getElementById('navThreatsBadge');
                if (threatsBadge) {
                    const highCrit = (alerts || []).filter(a => ['critical','high'].includes(String(a.severity || '').toLowerCase())).length;
                    threatsBadge.textContent = String(highCrit);
                }
            } catch (e) {
                console.error('Failed to update nav badges', e);
            }
        })
        .catch((error) => {
            console.error('Dashboard load failed:', error);
        });
}

window.addEventListener('DOMContentLoaded', () => {
    // Initial loads
    loadDashboardData();
    loadDeviceData();
    loadIncidentResponseData();

    // Setup periodic polling
    setInterval(loadDashboardData, 5000);
    setInterval(loadDeviceData, 10000);
    setInterval(loadIncidentResponseData, 3000);

    // Register event listeners
    const deviceSyncBtn = document.getElementById('deviceSyncBtn');
    if (deviceSyncBtn) {
        deviceSyncBtn.addEventListener('click', () => {
            loadDeviceData();
        });
    }


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

    // Modal close button and keyboard handlers
    const alertModal = document.getElementById('alertModal');
    const alertModalClose = document.getElementById('alertModalClose');
    if (alertModalClose) alertModalClose.addEventListener('click', closeModal);
    if (alertModal) {
        alertModal.addEventListener('click', (ev) => {
            if (ev.target === alertModal) closeModal();
        });
    }
   window.addEventListener('DOMContentLoaded', () => {
    // =========================================================
    // INITIAL DATA LOAD
    // =========================================================
    loadDashboardData();
    loadDeviceData();
    loadIncidentResponseData();


    // =========================================================
    // PERIODIC DATA REFRESH
    // =========================================================
    // Dashboard contains a large /api/events response (~722 KB),
    // so don't request it every 5 seconds.
    setInterval(() => {
        loadDashboardData();
    }, 15000); // every 15 seconds

    setInterval(() => {
        loadDeviceData();
    }, 30000); // every 30 seconds

    setInterval(() => {
        loadIncidentResponseData();
    }, 10000); // every 10 seconds


    // =========================================================
    // DEVICE SYNC BUTTON
    // =========================================================
    const deviceSyncBtn = document.getElementById('deviceSyncBtn');

    if (deviceSyncBtn) {
        deviceSyncBtn.addEventListener('click', () => {
            loadDeviceData();
        });
    }


    // =========================================================
    // AUTO RESPONSE / SIMULATION MODE
    // =========================================================
    const toggleAuto = document.getElementById('toggleAutoResponse');
    const toggleSim = document.getElementById('toggleSimulationMode');
    const resetBtn = document.getElementById('irResetBtn');


    if (toggleAuto) {
        toggleAuto.addEventListener('change', () => {
            updateSettings(
                toggleAuto.checked,
                toggleSim ? toggleSim.checked : false
            );
        });
    }


    if (toggleSim) {
        toggleSim.addEventListener('change', () => {
            updateSettings(
                toggleAuto ? toggleAuto.checked : false,
                toggleSim.checked
            );
        });
    }


    // =========================================================
    // RESET INCIDENTS
    // =========================================================
    if (resetBtn) {
        resetBtn.addEventListener('click', () => {

            const confirmed = confirm(
                'Are you sure you want to reset all incidents and execution logs?'
            );

            if (!confirmed) {
                return;
            }

            fetch('/api/incidents/reset', {
                method: 'POST'
            })
                .then(response => {
                    if (!response.ok) {
                        throw new Error(
                            `Reset request failed: ${response.status}`
                        );
                    }

                    return response.json();
                })
                .then(result => {
                    console.log('Incident reset:', result);

                    // Reload incident data after reset
                    loadIncidentResponseData();
                })
                .catch(error => {
                    console.error(
                        'Failed to reset incidents:',
                        error
                    );

                    alert(
                        'Failed to reset incidents. Check the server console.'
                    );
                });
        });
    }


    // =========================================================
    // ALERT MODAL
    // =========================================================
    const alertModal = document.getElementById('alertModal');
    const alertModalClose = document.getElementById('alertModalClose');


    if (alertModalClose) {
        alertModalClose.addEventListener('click', closeModal);
    }


    if (alertModal) {
        alertModal.addEventListener('click', (event) => {
            if (event.target === alertModal) {
                closeModal();
            }
        });
    }


    // =========================================================
    // ESC KEY → CLOSE MODAL
    // =========================================================
    window.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            closeModal();
        }
    });


    console.log(
        '%cAegisGuard dashboard initialized successfully',
        'color:#22d3ee;font-weight:bold;'
    );
});
});
