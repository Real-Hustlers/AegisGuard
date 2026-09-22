/*
 * AegisGuard Intelligence UI - Y7 Slice 2
 * Read-only presentation layer. No network requests are made here.
 */

(function () {
    'use strict';

    const state = {
        dashboard: {},
        alerts: [],
        events: [],
        incidents: []
    };

    function asArray(value) {
        return Array.isArray(value) ? value : [];
    }

    function asObject(value) {
        if (!value) return {};
        if (typeof value === 'object' && !Array.isArray(value)) return value;
        if (typeof value === 'string') {
            try {
                const parsed = JSON.parse(value);
                return parsed && typeof parsed === 'object' ? parsed : {};
            } catch (error) {
                return {};
            }
        }
        return {};
    }

    function escapeHtml(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    function setText(id, value) {
        const element = document.getElementById(id);
        if (element) element.textContent = String(value);
    }

    function normalizeSource(record) {
        const candidates = [
            record && record.detection_type,
            record && record.source_engine,
            record && record.prediction_source,
            record && record.detection_source
        ];

        for (const candidate of candidates) {
            const value = String(candidate || '').toUpperCase();
            if (!value) continue;
            if (value.includes('CORRELATION')) return 'CORRELATION';
            if (value === 'ML' || value.includes('MODEL') || value.includes('ML-')) return 'ML';
            if (value.includes('RULE')) return 'RULE';
        }
        return null;
    }

    function detectionCounts() {
        const counts = { RULE: 0, ML: 0, CORRELATION: 0, UNCLASSIFIED: 0 };
        const records = [
            ...asArray(state.alerts),
            ...asArray(state.events),
            ...asArray(state.incidents)
        ];

        records.forEach((record) => {
            const source = normalizeSource(record);
            if (source) counts[source] += 1;
            else counts.UNCLASSIFIED += 1;
        });
        return counts;
    }

    function collectMitreFrom(value, output) {
        if (!value) return;

        if (Array.isArray(value)) {
            value.forEach((item) => collectMitreFrom(item, output));
            return;
        }

        const object = asObject(value);
        if (!Object.keys(object).length) return;

        if (object.technique_id || object.technique || object.technique_name) {
            const id = String(object.technique_id || 'UNSPECIFIED');
            const name = String(object.technique_name || object.technique || 'Unnamed technique');
            const tactic = String(object.tactic || 'Unspecified tactic');
            const key = `${id}|${name}|${tactic}`;
            output.set(key, { technique_id: id, technique: name, tactic });
        }

        if (object.mitre) collectMitreFrom(object.mitre, output);
        if (object.mappings) collectMitreFrom(object.mappings, output);
    }

    function mitreCoverage() {
        const output = new Map();
        const dashboard = asObject(state.dashboard);
        const mlSummary = asObject(dashboard.ml_summary);

        collectMitreFrom(mlSummary.mitre, output);
        asArray(state.alerts).forEach((item) => collectMitreFrom(item.mitre, output));
        asArray(state.events).forEach((item) => collectMitreFrom(item.mitre, output));
        asArray(state.incidents).forEach((item) => collectMitreFrom(item.mitre, output));

        return Array.from(output.values());
    }

    function storyStages(incident) {
        const report = asObject(incident && incident.incident_report);
        const metadata = asObject(incident && incident.metadata);
        const candidates = [
            incident && incident.attack_story,
            incident && incident.attack_timeline,
            incident && incident.stages,
            metadata.attack_story,
            metadata.timeline,
            report.attack_story,
            report.timeline,
            report.stages
        ];

        for (const candidate of candidates) {
            if (Array.isArray(candidate) && candidate.length) return candidate;
            const object = asObject(candidate);
            if (Array.isArray(object.stages) && object.stages.length) {
                return object.stages;
            }
        }
        return [];
    }

    function stories() {
        return asArray(state.incidents)
            .map((incident) => ({ incident, stages: storyStages(incident) }))
            .filter((entry) => entry.stages.length >= 2);
    }

    function renderDetectionMix() {
        const container = document.getElementById('intelDetectionMix');
        if (!container) return;

        const counts = detectionCounts();
        const known = counts.RULE + counts.ML + counts.CORRELATION;

        setText('intelRuleCount', counts.RULE);
        setText('intelMlCount', counts.ML);
        setText('intelCorrelationCount', counts.CORRELATION);

        if (!known) {
            container.innerHTML = `
                <div class="ag-intel-empty">
                    The current API does not yet expose structured detection_type/source_engine fields.
                    Y8 can wire the Y2 rule, ML, and correlation findings into this surface without changing this layout.
                </div>
            `;
            return;
        }

        const max = Math.max(counts.RULE, counts.ML, counts.CORRELATION, 1);
        const row = (name, value) => `
            <div class="ag-intel-source-row">
                <div class="ag-intel-source-name">${escapeHtml(name)}</div>
                <div class="ag-intel-meter" aria-hidden="true"><span style="width:${Math.round((value / max) * 100)}%"></span></div>
                <div class="ag-intel-source-value">${value}</div>
            </div>
        `;

        container.innerHTML = [
            row('RULE', counts.RULE),
            row('ML', counts.ML),
            row('CORRELATION', counts.CORRELATION),
            `<div class="ag-intel-note">${counts.UNCLASSIFIED} additional records do not expose a structured detection source and are not guessed.</div>`
        ].join('');
    }

    function renderMitreCoverage() {
        const container = document.getElementById('intelMitreCoverage');
        if (!container) return;

        const coverage = mitreCoverage();
        setText('intelMitreCount', coverage.length);

        if (!coverage.length) {
            container.innerHTML = `
                <div class="ag-intel-empty">
                    No structured MITRE ATT&amp;CK mapping is present in the data currently available to this view.
                </div>
            `;
            return;
        }

        container.innerHTML = `
            <div class="ag-intel-chip-list">
                ${coverage.map((mapping) => `
                    <div class="ag-intel-chip">
                        <div class="ag-intel-chip-id">${escapeHtml(mapping.technique_id)}</div>
                        <div class="ag-intel-chip-name">${escapeHtml(mapping.technique)}</div>
                        <div class="ag-intel-chip-tactic">${escapeHtml(mapping.tactic)}</div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    function renderMlTelemetry() {
        const container = document.getElementById('intelMlTelemetry');
        if (!container) return;

        const dashboard = asObject(state.dashboard);
        const summary = asObject(dashboard.ml_summary);
        const prediction = String(summary.prediction || 'UNKNOWN').toUpperCase();
        const confidence = summary.confidence == null
            ? 'Not exposed'
            : `${Number(summary.confidence).toFixed(1)}%`;
        const count = summary.count == null ? 'Not exposed' : String(summary.count);

        const modelVersions = new Set();
        const featureSchemas = new Set();

        asArray(state.incidents).forEach((incident) => {
            const report = asObject(incident.incident_report);
            const version = incident.model_version || report.model_version;
            const schema = incident.feature_schema_version || report.feature_schema_version;
            if (version) modelVersions.add(String(version));
            if (schema) featureSchemas.add(String(schema));
        });

        container.innerHTML = `
            <div class="ag-ml-grid">
                <div class="ag-ml-field">
                    <div class="ag-ml-field-label">Dominant Prediction</div>
                    <div class="ag-ml-field-value">${escapeHtml(prediction)}</div>
                </div>
                <div class="ag-ml-field">
                    <div class="ag-ml-field-label">Average Confidence</div>
                    <div class="ag-ml-field-value">${escapeHtml(confidence)}</div>
                </div>
                <div class="ag-ml-field">
                    <div class="ag-ml-field-label">Observed Events</div>
                    <div class="ag-ml-field-value">${escapeHtml(count)}</div>
                </div>
                <div class="ag-ml-field">
                    <div class="ag-ml-field-label">Model Version</div>
                    <div class="ag-ml-field-value">${escapeHtml(modelVersions.size ? Array.from(modelVersions).join(', ') : 'Not exposed by current API')}</div>
                </div>
                <div class="ag-ml-field">
                    <div class="ag-ml-field-label">Feature Schema</div>
                    <div class="ag-ml-field-value">${escapeHtml(featureSchemas.size ? Array.from(featureSchemas).join(', ') : 'Not exposed by current API')}</div>
                </div>
            </div>
        `;
    }

    function renderAttackStory() {
        const container = document.getElementById('intelAttackStory');
        if (!container) return;

        const availableStories = stories();
        setText('intelStoryCount', availableStories.length);

        if (!availableStories.length) {
            container.innerHTML = `
                <div class="ag-intel-empty">
                    No structured multi-stage attack story is exposed by the current incident API.
                    When Y8 passes Y6 IncidentCandidate story metadata through the API, the timeline will render here.
                </div>
            `;
            return;
        }

        const entry = availableStories[0];
        const incidentId = entry.incident.incident_id || entry.incident.candidate_id || 'Attack story';

        container.innerHTML = `
            <div class="ag-intel-note" style="margin-top:0; padding-top:0; border-top:0; margin-bottom:12px;">
                Showing ${escapeHtml(incidentId)} (${entry.stages.length} stages)
            </div>
            <div class="ag-story">
                ${entry.stages.map((stage, index) => {
                    const object = asObject(stage);
                    const name = object.stage || object.tactic || object.name || object.title || `Stage ${index + 1}`;
                    const timestamp = object.timestamp || object.time || '';
                    const technique = object.technique_id || object.technique || '';
                    const reason = object.reason || object.description || object.details || '';
                    const meta = [timestamp, technique].filter(Boolean).join(' / ');

                    return `
                        <div class="ag-story-stage">
                            <div class="ag-story-stage-name">${escapeHtml(name)}</div>
                            ${meta ? `<div class="ag-story-stage-meta">${escapeHtml(meta)}</div>` : ''}
                            ${reason ? `<div class="ag-story-stage-reason">${escapeHtml(reason)}</div>` : ''}
                        </div>
                    `;
                }).join('')}
            </div>
        `;
    }

    function renderStatus() {
        const status = document.getElementById('intelDataStatus');
        if (!status) return;

        const counts = detectionCounts();
        const coverage = mitreCoverage();
        const availableStories = stories();
        const structuredDetections = counts.RULE + counts.ML + counts.CORRELATION;

        if (structuredDetections || coverage.length || availableStories.length) {
            status.textContent = 'CURRENT API DATA';
            status.className = 'badge badge-live';
        } else {
            status.textContent = 'PARTIAL DATA';
            status.className = 'badge badge-info';
        }
    }

    function renderAll() {
        renderDetectionMix();
        renderMitreCoverage();
        renderMlTelemetry();
        renderAttackStory();
        renderStatus();
    }

    function renderDashboard(dashboard, alerts, events) {
        state.dashboard = asObject(dashboard);
        state.alerts = asArray(alerts);
        state.events = asArray(events);
        renderAll();
    }

    function renderIncidents(incidents) {
        state.incidents = asArray(incidents);
        renderAll();
    }

    window.AegisIntelligenceUI = {
        renderDashboard,
        renderIncidents
    };
})();