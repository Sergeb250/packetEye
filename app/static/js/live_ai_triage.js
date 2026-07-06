/**
 * AI Triage page — unified incident table with dual-model LLM, verdicts, deep inspect.
 */
(function () {
    if (!document.getElementById('aiTriageTable')) return;

    const store = { rows: [], expanded: new Set(), pollSince: 0 };
    let pollTimer = null;

    function esc(v) {
        const d = document.createElement('div');
        d.textContent = v == null ? '' : String(v);
        return d.innerHTML;
    }

    function fmtTime(ts) {
        return new Date(ts * 1000).toLocaleTimeString(undefined, { hour12: false });
    }

    function fmtEp(row) {
        const s = row.src_ip || '—';
        const d = row.dst_ip || '—';
        const sp = row.src_port ? `:${row.src_port}` : '';
        const dp = row.dst_port ? `:${row.dst_port}` : '';
        return `${s}${sp} → ${d}${dp}`;
    }

    function sid() {
        return window.sessionId || liveConfig?.active_session?.session_id;
    }

    async function resolveSessionId() {
        let sid = window.sessionId || liveConfig?.active_session?.session_id;
        if (sid) return sid;
        try {
            const st = await fetch('/api/live/triage/status').then((r) => r.json());
            sid = st.session_id || st.llm_packet_triage?.session_id;
            if (sid) {
                window.sessionId = sid;
                return sid;
            }
            const cfg = await fetch('/api/live/config').then((r) => r.json());
            sid = cfg.active_session?.session_id;
            if (sid) window.sessionId = sid;
            return sid || null;
        } catch {
            return null;
        }
    }

    function showNoSessionHint() {
        const tbody = document.getElementById('aiTriageBody');
        if (!tbody) return;
        tbody.innerHTML = `<tr><td colspan="12" class="empty-state py-4 text-center text-muted">
            Start <strong>ML Live Monitor</strong> on the ML tab, then enable <strong>Live triage</strong> above.
            AI alerts also appear on the <a href="/live/overview">SOC Console</a> with an <span class="badge bg-info text-dark">AI</span> badge.
        </td></tr>`;
        const cnt = document.getElementById('aiTriageRowCount');
        if (cnt) cnt.textContent = '0 rows';
    }

    function sourceBadges(sources, fromAi) {
        const map = {
            suricata: 'bg-warning text-dark',
            ml: 'bg-primary',
            llm: 'bg-info text-dark',
            correlation: 'bg-danger',
            heuristic: 'bg-secondary',
        };
        let html = (sources || []).map((s) => {
            const cls = map[s] || 'bg-secondary';
            const label = s === 'llm' ? 'AI' : s.toUpperCase();
            return `<span class="badge ${cls} me-1">${esc(label)}</span>`;
        }).join('');
        if (fromAi && !(sources || []).includes('llm')) {
            html += '<span class="badge bg-info text-dark me-1">AI</span>';
        }
        return html || '<span class="text-muted">—</span>';
    }

    function dispBadge(d) {
        const map = {
            open: 'bg-secondary',
            true_positive: 'bg-danger',
            false_positive: 'bg-warning text-dark',
            true_negative: 'bg-success',
            benign: 'bg-success',
            error: 'bg-dark border',
        };
        const cls = map[d] || 'bg-secondary';
        return `<span class="badge ${cls}">${esc((d || 'open').replace(/_/g, ' '))}</span>`;
    }

    function sevBadge(s) {
        const sev = (s || 'info').toLowerCase();
        const cls = { critical: 'bg-danger', high: 'bg-warning text-dark', medium: 'bg-info text-dark', info: 'bg-secondary' }[sev] || 'bg-secondary';
        return `<span class="badge ${cls}">${esc(sev)}</span>`;
    }

    function llmCell(model) {
        if (!model || !Object.keys(model).length) return '<span class="text-muted">—</span>';
        const atk = model.attack_type || (model.suspicious ? 'suspicious' : 'clear');
        const conf = model.confidence != null ? `${Math.round(model.confidence * 100)}%` : '';
        return `<span class="small">${esc(atk)} ${conf ? `<span class="text-muted">(${esc(conf)})</span>` : ''}</span>`;
    }

    function updateKpis(stats, llm) {
        const by = stats?.by_disposition || {};
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
        set('aiKpiOpen', by.open || 0);
        set('aiKpiTp', by.true_positive || 0);
        set('aiKpiFp', by.false_positive || 0);
        set('aiKpiTn', (by.true_negative || 0) + (by.benign || 0));
        set('aiKpiErrors', by.error || 0);
        const st = llm?.stats || {};
        const elapsed = llm?.elapsed_sec || 0;
        const rate = elapsed > 0 ? ((st.llm_calls || 0) / elapsed * 60).toFixed(1) : '—';
        set('aiKpiLlmRate', rate);
        const badge = document.getElementById('aiTriageRunnerBadge');
        if (badge) {
            badge.textContent = llm?.running ? 'running' : 'idle';
            badge.className = `badge ${llm?.running ? 'bg-success' : 'bg-secondary'}`;
        }
        const toggle = document.getElementById('aiTriageToggle');
        if (toggle && llm) toggle.checked = !!llm.running;
        const stackEl = document.getElementById('aiTriageModelStack');
        if (stackEl && llm?.model_stack?.length) {
            stackEl.textContent = llm.model_stack.join(' · ');
            stackEl.className = 'badge bg-info text-dark';
        }
        renderContextFeed(llm?.context_log || []);
    }

    function renderContextFeed(entries) {
        const feed = document.getElementById('aiLiveContextFeed');
        const cnt = document.getElementById('aiContextCount');
        if (!feed) return;
        if (cnt) cnt.textContent = `${entries.length} events`;
        if (!entries.length) {
            feed.innerHTML = '<div class="text-muted small p-3">Enable live triage to stream 3-model packet analysis here.</div>';
            return;
        }
        feed.innerHTML = entries.map((e) => `
            <div class="ai-context-row border-bottom border-secondary px-3 py-2 small">
                <div class="d-flex justify-content-between text-muted font-monospace mb-1">
                    <span>${fmtTime(e.timestamp)}</span>
                    <span>${esc(e.connection || '')}</span>
                </div>
                <div class="row g-1">
                    <div class="col-md-4"><span class="badge bg-info text-dark me-1">Z.ai</span>${esc(e.zai || '—')}</div>
                    <div class="col-md-4"><span class="badge bg-primary me-1">NVIDIA</span>${esc(e.nvidia || '—')}</div>
                    <div class="col-md-4"><span class="badge bg-secondary me-1">3rd</span>${esc(e.tertiary || '—')}</div>
                </div>
                <div class="mt-1 text-muted"><strong>Merged:</strong> ${esc(e.merged || '—')}</div>
                ${(e.errors || []).length ? `<div class="text-warning mt-1">${esc(e.errors.join(' · '))}</div>` : ''}
            </div>`).join('');
    }

    function renderTable() {
        const tbody = document.getElementById('aiTriageBody');
        const cnt = document.getElementById('aiTriageRowCount');
        if (!tbody) return;
        if (!store.rows.length) {
            tbody.innerHTML = '<tr><td colspan="12" class="empty-state py-4 text-center text-muted">No incidents match filters.</td></tr>';
            if (cnt) cnt.textContent = '0 rows';
            return;
        }
        if (cnt) cnt.textContent = `${store.rows.length} rows`;
        tbody.innerHTML = store.rows.map((row) => {
            const exp = store.expanded.has(row.id);
            const actions = `
                <button type="button" class="btn btn-outline-info btn-sm py-0 ai-btn-inspect" data-id="${esc(row.id)}">Deep</button>
                <div class="btn-group btn-group-sm mt-1">
                    <button type="button" class="btn btn-outline-danger btn-sm py-0 ai-btn-verdict" data-id="${esc(row.id)}" data-disp="true_positive">TP</button>
                    <button type="button" class="btn btn-outline-warning btn-sm py-0 ai-btn-verdict" data-id="${esc(row.id)}" data-disp="false_positive">FP</button>
                    <button type="button" class="btn btn-outline-success btn-sm py-0 ai-btn-verdict" data-id="${esc(row.id)}" data-disp="true_negative">TN</button>
                </div>`;
            const detail = exp ? renderExpand(row) : '';
            return `<tr class="ai-triage-row" data-id="${esc(row.id)}">
                <td><button type="button" class="btn btn-link btn-sm p-0 ai-btn-expand" data-id="${esc(row.id)}"><i class="bi bi-chevron-${exp ? 'down' : 'right'}"></i></button></td>
                <td class="small font-monospace">${fmtTime(row.timestamp)}</td>
                <td class="small font-monospace">${esc(fmtEp(row))}</td>
                <td>${sourceBadges(row.sources, row.from_ai)}</td>
                <td class="small">${esc(row.attack_type || '—')}</td>
                <td>${sevBadge(row.severity)}</td>
                <td>${dispBadge(row.disposition)}</td>
                <td class="small">${llmCell(row.llm_primary)}</td>
                <td class="small">${llmCell(row.llm_secondary)}</td>
                <td class="small">${llmCell(row.llm_tertiary)}</td>
                <td class="small text-truncate" style="max-width:180px" title="${esc(row.llm_merged_summary)}">${esc(row.llm_merged_summary || '—')}</td>
                <td class="small">${actions}</td>
            </tr>${detail}`;
        }).join('');

        tbody.querySelectorAll('.ai-btn-expand').forEach((btn) => {
            btn.addEventListener('click', () => {
                const id = btn.dataset.id;
                if (store.expanded.has(id)) store.expanded.delete(id);
                else store.expanded.add(id);
                renderTable();
            });
        });
        tbody.querySelectorAll('.ai-btn-inspect').forEach((btn) => {
            btn.addEventListener('click', () => deepInspect(btn.dataset.id));
        });
        tbody.querySelectorAll('.ai-btn-verdict').forEach((btn) => {
            btn.addEventListener('click', () => setVerdict(btn.dataset.id, btn.dataset.disp));
        });
    }

    function renderExpand(row) {
        return `<tr class="table-secondary"><td colspan="12" class="small p-3">
            <div class="row g-3">
                <div class="col-md-4"><strong>Z.ai (primary)</strong><pre class="small bg-black border border-secondary p-2 mt-1 mb-0">${esc(JSON.stringify(row.llm_primary || {}, null, 2))}</pre></div>
                <div class="col-md-4"><strong>NVIDIA (secondary)</strong><pre class="small bg-black border border-secondary p-2 mt-1 mb-0">${esc(JSON.stringify(row.llm_secondary || {}, null, 2))}</pre></div>
                <div class="col-md-4"><strong>3rd model</strong><pre class="small bg-black border border-secondary p-2 mt-1 mb-0">${esc(JSON.stringify(row.llm_tertiary || {}, null, 2))}</pre></div>
                <div class="col-md-6"><strong>Packet</strong><pre class="small bg-black border border-secondary p-2 mt-1 mb-0">${esc(JSON.stringify(row.packet || {}, null, 2))}</pre></div>
                <div class="col-md-6"><strong>Errors / indicators</strong>
                    <div class="mt-1">${(row.errors || []).map((e) => `<div class="text-warning">${esc(e)}</div>`).join('') || '<span class="text-muted">None</span>'}</div>
                    <div class="mt-1">${(row.indicators || []).map((i) => `<span class="badge bg-dark border me-1">${esc(i)}</span>`).join('')}</div>
                </div>
            </div>
        </td></tr>`;
    }

    async function pollIncidents() {
        const sessionId = await resolveSessionId();
        if (!sessionId) {
            showNoSessionHint();
            return;
        }
        const source = document.getElementById('aiFilterSource')?.value || '';
        const disposition = document.getElementById('aiFilterDisposition')?.value || '';
        const search = document.getElementById('aiFilterSearch')?.value || '';
        const params = new URLSearchParams({ session_id: sessionId, limit: '200' });
        if (source) params.set('source', source);
        if (disposition) params.set('disposition', disposition);
        if (search) params.set('search', search);
        try {
            const [incRes, stRes] = await Promise.all([
                fetch(`/api/live/triage/incidents?${params}`),
                fetch(`/api/live/triage/status?session_id=${sessionId}`),
            ]);
            if (incRes.ok) {
                const data = await incRes.json();
                store.rows = data.incidents || [];
                renderTable();
            }
            if (stRes.ok) {
                const st = await stRes.json();
                if (st.session_id && !window.sessionId) window.sessionId = st.session_id;
                updateKpis(st.registry, st.llm_packet_triage);
            }
        } catch { /* ignore */ }
    }

    async function toggleTriage(enabled) {
        const sessionId = await resolveSessionId();
        try {
            const res = await fetch('/api/live/llm-packets', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled, session_id: sessionId }),
            });
            const data = await res.json();
            if (typeof showInlineFeedback === 'function') {
                showInlineFeedback(data.message || data.error || (enabled ? 'Started' : 'Stopped'), res.ok ? 'info' : 'danger', 'AI Triage');
            }
            pollIncidents();
        } catch {
            if (typeof showInlineFeedback === 'function') showInlineFeedback('Toggle failed', 'danger', 'AI Triage');
        }
    }

    async function testModels() {
        const btn = document.getElementById('aiTriageTestModels');
        if (btn) btn.disabled = true;
        try {
            const res = await fetch('/api/llm/test', { method: 'POST' });
            const data = await res.json();
            let msg = data.error || (data.ok ? 'All models OK' : 'Probe failed');
            if (data.results) {
                msg = Object.entries(data.results).map(([k, v]) => `${k}: ${v.ok ? 'OK' : v.error || 'fail'} (${v.latency_ms || '?'}ms)`).join(' · ');
            }
            if (typeof showInlineFeedback === 'function') showInlineFeedback(msg, data.ok ? 'success' : 'warning', 'NVIDIA');
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    async function deepInspect(incidentId) {
        const sessionId = sid();
        const body = document.getElementById('aiDeepInspectBody');
        const drawer = document.getElementById('aiDeepInspectDrawer');
        if (!sessionId || !body) return;
        body.innerHTML = '<div class="text-muted">Analyzing…</div>';
        bootstrap.Offcanvas.getOrCreateInstance(drawer).show();
        try {
            const res = await fetch('/api/live/triage/inspect', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: sessionId, incident_id: incidentId }),
            });
            const data = await res.json();
            if (data.ok && data.analysis) {
                body.innerHTML = `<div class="ai-deep-markdown small">${esc(data.analysis).replace(/\n/g, '<br>')}</div>`;
            } else {
                body.innerHTML = `<div class="text-danger">${esc(data.error || 'Inspect failed')}</div>`;
            }
        } catch (e) {
            body.innerHTML = `<div class="text-danger">${esc(String(e))}</div>`;
        }
    }

    async function setVerdict(incidentId, disposition) {
        const sessionId = sid();
        if (!sessionId) return;
        const note = window.prompt('Analyst note (optional):') || '';
        try {
            const res = await fetch('/api/live/triage/verdict', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: sessionId, incident_id: incidentId, disposition, note }),
            });
            if (res.ok) pollIncidents();
        } catch { /* ignore */ }
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.getElementById('aiTriageToggle')?.addEventListener('change', (e) => toggleTriage(e.target.checked));
        document.getElementById('aiTriageTestModels')?.addEventListener('click', testModels);
        ['aiFilterSource', 'aiFilterDisposition'].forEach((id) => {
            document.getElementById(id)?.addEventListener('change', pollIncidents);
        });
        document.getElementById('aiFilterSearch')?.addEventListener('input', () => {
            clearTimeout(window._aiSearchTimer);
            window._aiSearchTimer = setTimeout(pollIncidents, 400);
        });
        pollIncidents();
        pollTimer = setInterval(pollIncidents, 3000);
        fetch('/api/live/llm-packets').then((r) => r.json()).then((d) => {
            const toggle = document.getElementById('aiTriageToggle');
            if (toggle) toggle.checked = !!d.running;
            updateKpis({}, d);
        }).catch(() => {});
        setInterval(() => {
            if (!window.sessionId && liveConfig?.active_session?.session_id) {
                window.sessionId = liveConfig.active_session.session_id;
                pollIncidents();
            }
        }, 4000);
    });

    window.addEventListener('beforeunload', () => { if (pollTimer) clearInterval(pollTimer); });
})();
