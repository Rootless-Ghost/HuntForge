/* HuntForge — Main JavaScript */

'use strict';

// ── Utility ───────────────────────────────────────────────────────────────────

function esc(str) {
    return String(str)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function confColor(score) {
    if (score >= 8) return 'var(--conf-very-high)';
    if (score >= 6) return 'var(--conf-high)';
    if (score >= 4) return 'var(--conf-medium)';
    if (score >= 2) return 'var(--conf-low)';
    return 'var(--conf-very-low)';
}

function confClass(label) {
    return 'conf-' + (label || '').toLowerCase().replace(/\s+/g, '-');
}

// ── Tab switching (generic) ───────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-tab]').forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.getAttribute('data-tab');
            const container = btn.closest('.tab-container');
            if (!container) return;
            container.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            container.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            btn.classList.add('active');
            const target = document.getElementById('tab-' + tabId);
            if (target) target.classList.add('active');
        });
    });
});

// ── Copy button ───────────────────────────────────────────────────────────────

document.addEventListener('click', (e) => {
    const btn = e.target.closest('.copy-btn');
    if (!btn) return;
    const targetId = btn.getAttribute('data-target');
    if (!targetId) return;
    const el = document.getElementById(targetId);
    if (!el) return;
    navigator.clipboard.writeText(el.textContent).then(() => {
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => {
            btn.textContent = orig;
            btn.classList.remove('copied');
        }, 1500);
    }).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = el.textContent;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
    });
});

// ── Technique search autocomplete ─────────────────────────────────────────────

const techniqueInput    = document.getElementById('techniqueInput');
const techniqueDropdown = document.getElementById('techniqueDropdown');
const techniqueInfo     = document.getElementById('techniqueInfo');
const techTactic        = document.getElementById('techTactic');
const techName          = document.getElementById('techName');
const techScore         = document.getElementById('techScore');
const generateBtn       = document.getElementById('generateBtn');

if (techniqueInput) {
    let searchTimer = null;
    let selectedTechniqueId = '';

    techniqueInput.addEventListener('input', () => {
        clearTimeout(searchTimer);
        const val = techniqueInput.value.trim();

        if (val.length < 2) {
            hideDropdown();
            if (generateBtn) generateBtn.disabled = true;
            return;
        }

        searchTimer = setTimeout(() => fetchTechniques(val), 200);
    });

    techniqueInput.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            hideDropdown();
        }
        if (e.key === 'Enter' && selectedTechniqueId) {
            e.preventDefault();
            document.getElementById('generateBtn')?.click();
        }
    });

    document.addEventListener('click', (e) => {
        if (!techniqueInput.contains(e.target) && !techniqueDropdown?.contains(e.target)) {
            hideDropdown();
        }
    });

    async function fetchTechniques(query) {
        try {
            const resp = await fetch(`/api/techniques?q=${encodeURIComponent(query)}`);
            const data = await resp.json();
            showDropdown(data.techniques || []);
        } catch (err) {
            console.error('Technique search failed:', err);
        }
    }

    function showDropdown(techniques) {
        if (!techniqueDropdown) return;
        techniqueDropdown.innerHTML = '';
        if (techniques.length === 0) {
            techniqueDropdown.innerHTML = '<div class="dropdown-item" style="color:var(--text-muted)">No techniques found</div>';
            techniqueDropdown.classList.remove('hidden');
            return;
        }

        techniques.slice(0, 12).forEach(t => {
            const item = document.createElement('div');
            item.className = 'dropdown-item';
            item.innerHTML = `
                <span class="dropdown-item-id">${esc(t.id)}</span>
                <span class="dropdown-item-name">${esc(t.name)}</span>
                <span class="dropdown-item-tactic">${esc(t.tactic)}</span>
            `;
            item.addEventListener('click', () => selectTechnique(t));
            techniqueDropdown.appendChild(item);
        });
        techniqueDropdown.classList.remove('hidden');
    }

    function hideDropdown() {
        if (techniqueDropdown) techniqueDropdown.classList.add('hidden');
    }

    function selectTechnique(tech) {
        techniqueInput.value = tech.id;
        selectedTechniqueId = tech.id;
        hideDropdown();

        if (techniqueInfo) techniqueInfo.classList.remove('hidden');
        if (techTactic) techTactic.textContent = tech.tactic;
        if (techName)   techName.textContent   = tech.name;
        if (techScore)  techScore.textContent   = `Confidence: ${tech.confidence_score}/10`;
        if (generateBtn) generateBtn.disabled = false;
    }

    // Allow direct ID entry (e.g. "T1059.001")
    techniqueInput.addEventListener('blur', () => {
        const val = techniqueInput.value.trim().toUpperCase();
        if (val.match(/^T\d{4}(\.\d{3})?$/)) {
            selectedTechniqueId = val;
            if (generateBtn) generateBtn.disabled = false;
            // Try to enrich the info row
            fetch(`/api/technique/${val}`)
                .then(r => r.json())
                .then(data => {
                    if (data.success && data.technique) {
                        const t = data.technique;
                        if (techniqueInfo) techniqueInfo.classList.remove('hidden');
                        if (techTactic) techTactic.textContent = t.tactic;
                        if (techName)   techName.textContent   = t.name;
                        if (techScore)  techScore.textContent   = `Confidence: ${t.confidence_score}/10`;
                    }
                })
                .catch(() => {});
        }
    });
}

// ── Generate playbook ─────────────────────────────────────────────────────────

const generateBtn2 = document.getElementById('generateBtn');
const generateStatus = document.getElementById('generateStatus');
const playbookOutput = document.getElementById('playbookOutput');

if (generateBtn2) {
    generateBtn2.addEventListener('click', async () => {
        const techniqueId = (document.getElementById('techniqueInput')?.value || '').trim().toUpperCase();
        if (!techniqueId) return;

        const env = document.querySelector('input[name="environment"]:checked')?.value || 'windows';
        const srcCheckboxes = document.querySelectorAll('input[name="log_sources"]:checked');
        const logSources = Array.from(srcCheckboxes).map(cb => cb.value);
        const format = document.getElementById('outputFormat')?.value || 'json';

        // Show loading
        generateBtn2.disabled = true;
        if (generateStatus)  generateStatus.classList.remove('hidden');
        if (playbookOutput)  playbookOutput.classList.add('hidden');

        try {
            const resp = await fetch('/api/playbook/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    technique_id: techniqueId,
                    context: { environment: env, log_sources: logSources },
                    output_format: format,
                    save: true,
                }),
            });

            const data = await resp.json();

            if (generateStatus) generateStatus.classList.add('hidden');

            if (!data.success) {
                alert(`Error: ${data.error || 'Unknown error'}`);
                generateBtn2.disabled = false;
                return;
            }

            renderPlaybook(data);
            if (playbookOutput) playbookOutput.classList.remove('hidden');
            playbookOutput?.scrollIntoView({ behavior: 'smooth' });

        } catch (err) {
            console.error('Generate failed:', err);
            alert('Failed to generate playbook. Check the console for details.');
        } finally {
            generateBtn2.disabled = false;
            if (generateStatus) generateStatus.classList.add('hidden');
        }
    });
}

function renderPlaybook(pb) {
    // Header
    setEl('pbTechId',   pb.technique_id);
    setEl('pbTechName', pb.technique_name);
    setEl('pbTactic',   pb.tactic);

    const conf = pb.confidence || {};
    const confEl = document.getElementById('pbConfidence');
    if (confEl) {
        confEl.textContent = `${conf.label} (${conf.adjusted_score}/10)`;
        confEl.className = `confidence-badge ${confClass(conf.label)}`;
    }

    // Export / view buttons
    if (pb.id) {
        const viewBtn = document.getElementById('viewFullBtn');
        if (viewBtn) viewBtn.href = `/playbook/${pb.id}`;

        const exportJson = document.getElementById('exportJsonBtn');
        if (exportJson) exportJson.onclick = () => {
            window.location.href = `/api/playbook/${pb.id}/export?format=json`;
        };

        const exportMd = document.getElementById('exportMdBtn');
        if (exportMd) exportMd.onclick = () => {
            window.location.href = `/api/playbook/${pb.id}/export?format=markdown`;
        };
    }

    // Confidence bar
    const score = conf.adjusted_score || 0;
    const confBar = document.getElementById('confBar');
    if (confBar) {
        confBar.style.width  = `${score * 10}%`;
        confBar.style.background = confColor(score);
    }
    setEl('confValue',    `${score}/10`);
    setEl('confCoverage', `Log coverage: ${conf.source_coverage || 0}%`);
    setEl('confRationale', conf.rationale || '');

    const confLabelEl = document.getElementById('confLabel');
    if (confLabelEl) {
        confLabelEl.textContent = conf.label || '';
        confLabelEl.className = `conf-label-badge ${confClass(conf.label)}`;
    }

    // Overview
    setEl('pbDescription', pb.description || '');
    setHtml('pbHypothesis', (pb.hypothesis || '').replace(/\n/g, '<br>'));

    // Queries
    const queries = pb.queries || {};
    setEl('splunkQuery', queries.splunk || '');
    setEl('wazuhQuery',  JSON.stringify(queries.wazuh || {}, null, 2));
    setEl('sigmaQuery',  queries.sigma || '');
    setEl('kqlQuery',    queries.kql || '');

    // Artifacts
    const arts = pb.artifacts || {};
    renderTagList('artEventIds',   arts.event_ids   || [], 'artifact-code');
    renderTagList('artFieldNames', arts.field_names || [], 'artifact-tag');
    renderTagList('artProcesses',  arts.processes   || [], 'artifact-code process-name');
    renderCmdList('artCmdPatterns', arts.command_patterns || []);
    renderTagList('artRegKeys',    arts.registry_keys || [], 'artifact-code reg-key');
    renderTagList('artNetPorts',   arts.network_ports || [], 'artifact-code port-num');

    // MITRE context
    const mc = pb.mitre_context || {};
    const mitreInfoEl = document.getElementById('mitreInfo');
    if (mitreInfoEl) {
        mitreInfoEl.innerHTML = `
            <a href="${esc(mc.tactic_url || '')}" target="_blank" class="mitre-link">
                ${esc(mc.tactic_id || '')} — ${esc(mc.tactic_name || '')}
            </a>
            ${mc.parent_id ? `<div class="mitre-parent">Parent: <a href="https://attack.mitre.org/techniques/${esc(mc.parent_id)}/" target="_blank" class="mitre-link">${esc(mc.parent_id)}</a></div>` : ''}
            <div class="mitre-attck-link">
                <a href="${esc(mc.technique_url || '')}" target="_blank" class="mitre-link">
                    View on MITRE ATT&CK →
                </a>
            </div>
        `;
    }

    renderMitreList('mitreSubTechs', mc.sub_techniques   || [], true);
    renderMitreList('mitreRelated',  mc.related_techniques || [], false);
    setEl('mitreDetectionNotes', mc.detection_notes || '');

    // Log sources
    renderLogSources('logSourcesList', pb.suggested_log_sources || []);

    // Reset to overview tab
    document.querySelectorAll('#playbookOutput .tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('#playbookOutput .tab-content').forEach(c => c.classList.remove('active'));
    const firstTab = document.querySelector('#playbookOutput .tab-btn');
    if (firstTab) firstTab.classList.add('active');
    const firstContent = document.querySelector('#playbookOutput .tab-content');
    if (firstContent) firstContent.classList.add('active');
}

function setEl(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}

function setHtml(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
}

function renderTagList(id, items, cls) {
    const el = document.getElementById(id);
    if (!el) return;
    if (!items.length) {
        el.innerHTML = '<span class="artifact-empty">None identified</span>';
        return;
    }
    el.innerHTML = items.map(item =>
        `<span class="${esc(cls)}">${esc(String(item))}</span>`
    ).join(' ');
}

function renderCmdList(id, items) {
    const el = document.getElementById(id);
    if (!el) return;
    if (!items.length) {
        el.innerHTML = '<span class="artifact-empty">None identified</span>';
        return;
    }
    el.innerHTML = items.map(item =>
        `<div class="artifact-item cmd-item"><span class="artifact-code">${esc(item)}</span></div>`
    ).join('');
}

function renderMitreList(id, items, showDesc) {
    const el = document.getElementById(id);
    if (!el) return;
    if (!items.length) {
        el.innerHTML = '<div class="artifact-empty">None listed</div>';
        return;
    }
    el.innerHTML = items.map(item => `
        <div class="mitre-item">
            <span class="mitre-id">${esc(item.id || '')}</span>
            <span class="mitre-name">${esc(item.name || '')}</span>
            ${item.tactic ? `<span class="mitre-tactic-tag">${esc(item.tactic)}</span>` : ''}
            ${showDesc && item.description ? `<div class="mitre-desc">${esc(item.description.substring(0, 120))}</div>` : ''}
        </div>
    `).join('');
}

function renderLogSources(id, items) {
    const el = document.getElementById(id);
    if (!el) return;
    if (!items.length) {
        el.innerHTML = '<div class="artifact-empty">No log source recommendations</div>';
        return;
    }
    el.innerHTML = items.map(src => `
        <div class="logsource-item priority-${esc(src.priority || 'optional')}">
            <div class="logsource-priority ${esc(src.priority || 'optional')}">${esc((src.priority || 'optional').toUpperCase())}</div>
            <div class="logsource-content">
                <div class="logsource-name">${esc(src.name || '')}</div>
                <div class="logsource-desc">${esc(src.description || '')}</div>
            </div>
        </div>
    `).join('');
}

// ── Technique grid loader ─────────────────────────────────────────────────────

function loadTechniqueGrid(tactic) {
    const section = document.getElementById('techniqueGrid');
    const grid    = document.getElementById('techniqueGridItems');
    if (!section || !grid) return;

    fetch(`/api/techniques?tactic=${encodeURIComponent(tactic)}`)
        .then(r => r.json())
        .then(data => {
            if (!data.success || !data.techniques.length) return;

            section.classList.remove('hidden');
            grid.innerHTML = '';

            data.techniques.forEach(t => {
                const item = document.createElement('div');
                item.className = 'technique-grid-item';
                item.innerHTML = `
                    <div class="tgi-id">${esc(t.id)}
                        <span class="tgi-score" style="color:${confColor(t.confidence_score)}">${t.confidence_score}/10</span>
                    </div>
                    <div class="tgi-name">${esc(t.name)}</div>
                    <div class="tgi-tactic">${esc(t.tactic)}</div>
                `;
                item.addEventListener('click', () => {
                    const input = document.getElementById('techniqueInput');
                    if (input) {
                        input.value = t.id;
                        input.dispatchEvent(new Event('blur'));
                    }
                    section.scrollIntoView({ behavior: 'smooth', block: 'end' });
                    setTimeout(() => {
                        window.scrollTo({ top: 0, behavior: 'smooth' });
                    }, 300);
                });
                grid.appendChild(item);
            });
        })
        .catch(err => console.error('Failed to load technique grid:', err));
}
