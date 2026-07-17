const formatter = new Intl.NumberFormat('en-US');

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) {
        element.textContent = value;
    }
}

function severityBadgeClass(severity) {
    if (severity === 'Critical') return 'badge-critical';
    if (severity === 'High') return 'badge-high';
    if (severity === 'Medium') return 'badge-medium';
    return 'badge-info';
}

function severityCardClass(severity) {
    if (severity === 'Critical') return 'critical';
    if (severity === 'High') return 'high';
    return '';
}

function renderDashboardStats(data) {
    setText('totalEvents', formatter.format(data.events));
    setText('totalThreats', formatter.format(data.threats));
    setText('totalDevices', formatter.format(data.devices));
    setText('activeAlerts', formatter.format(data.alerts));
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

    tableBody.innerHTML = events.map((event) => `
        <tr>
            <td class="mono">${event.id}</td>
            <td class="mono text-cyan">${event.timestamp}</td>
            <td class="mono text-white">${event.hostname}</td>
            <td class="mono text-white">${event.ip}</td>
            <td><span class="badge ${severityBadgeClass(event.severity)}">${event.severity.toUpperCase()}</span></td>
            <td class="text-white">${event.event}</td>
        </tr>
    `).join('');
}

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
    loadDashboardData();
    setInterval(loadDashboardData, 5000);
});
